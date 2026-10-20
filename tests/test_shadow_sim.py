import importlib.util
import tempfile
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shadow_sim", ROOT / "shadow-sim.py")
assert SPEC is not None and SPEC.loader is not None
shadow_sim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shadow_sim)


def experiment(explicit_count: int) -> dict:
    return shadow_sim.experiment_defaults(
        {
            "run_id": "test",
            "validator_count": 12,
            "subnet_count": 2,
            "local_aggregators_per_subnet": 3,
            "global_aggregator_count": 1,
            "gossipsub_explicit_aggregator_count": explicit_count,
            "geo_seed": 7,
        }
    )


class ExplicitAggregatorAssignmentTests(unittest.TestCase):
    def test_assigns_reciprocal_same_subnet_aggregators(self) -> None:
        nodes = shadow_sim.assign_nodes(experiment(2))
        by_id = {node["node_id"]: node for node in nodes}

        for node in nodes:
            if node["role"] == "global_aggregator":
                self.assertEqual(node["selected_aggregator_ids"], [])
                continue

            selected = node["selected_aggregator_ids"]
            self.assertEqual(len(selected), 2)
            self.assertEqual(len(set(selected)), 2)
            for aggregator_id in selected:
                aggregator = by_id[aggregator_id]
                self.assertEqual(aggregator["role"], "local_aggregator")
                self.assertEqual(aggregator["subnet_id"], node["subnet_id"])
                self.assertNotEqual(aggregator_id, node["node_id"])
                self.assertIn(aggregator["listen_addr"], node["explicit_peer_addrs"])
                self.assertIn(node["listen_addr"], aggregator["explicit_peer_addrs"])

            self.assertTrue(set(node["explicit_peer_addrs"]).issubset(node["seed_addrs"]))

    def test_zero_count_preserves_empty_explicit_peers(self) -> None:
        for node in shadow_sim.assign_nodes(experiment(0)):
            self.assertEqual(node["selected_aggregator_ids"], [])
            self.assertEqual(node["explicit_peer_addrs"], [])

    def test_assignment_is_deterministic(self) -> None:
        first = shadow_sim.assign_nodes(experiment(2))
        second = shadow_sim.assign_nodes(experiment(2))
        self.assertEqual(first, second)


class ValidatorMapPlacementTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.map_path = Path(directory.name) / "map.csv"
        rows = ["validator_index,peer_key,routes,n_windows"]
        # 8 validators on peer A, 4 on peer B, 4 alone; validator 100 is seen on A
        # and C but mostly on C, so it belongs to C.
        rows += [f"{index},A,agg,1" for index in range(8)]
        rows += [f"{index},B,att,2" for index in range(8, 12)]
        rows += [f"{index},solo-{index},agg,1" for index in range(12, 16)]
        rows += ["100,A,agg,1", "100,C,agg,5"]
        self.map_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        shadow_sim.load_validator_map.cache_clear()

    def experiment(self, **overrides: object) -> dict:
        values = {
            "run_id": "test",
            "validator_count": 17,
            "subnet_count": 1,
            "local_aggregators_per_subnet": 3,
            "global_aggregator_count": 1,
            "geo_seed": 7,
            "validator_map": str(self.map_path),
        }
        values.update(overrides)
        return shadow_sim.experiment_defaults(values)

    def test_resolves_ambiguous_validator_to_most_observed_peer(self) -> None:
        entries = dict(shadow_sim.load_validator_map(self.map_path))
        self.assertEqual(entries[100], "C")
        self.assertEqual(entries[0], "A")

    def test_colocated_validators_share_one_host(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        signing = [node for node in nodes if node["role"] != "global_aggregator"]
        # All 17 validators sampled: A, B, C, and four solo peers.
        self.assertEqual(len(signing), 7)
        self.assertEqual(Counter(len(node["validator_ids"]) for node in signing), Counter({8: 1, 4: 1, 1: 5}))
        self.assertEqual(sorted(v for node in signing for v in node["validator_ids"]), list(range(17)))
        by_peer = {node["peer_key"]: node for node in signing}
        self.assertEqual(sorted(by_peer["A"]["source_validator_indices"]), list(range(8)))
        self.assertEqual(len({node["ip"] for node in nodes}), len(nodes))
        self.assertEqual(sum(node["role"] == "local_aggregator" for node in nodes), 3)

    def test_sampling_is_seeded(self) -> None:
        first = shadow_sim.assign_nodes(self.experiment(validator_count=6))
        second = shadow_sim.assign_nodes(self.experiment(validator_count=6))
        self.assertEqual(first, second)

    def test_multi_subnet_hosts_select_aggregators_per_subnet(self) -> None:
        nodes = shadow_sim.assign_nodes(
            self.experiment(validator_count=16, subnet_count=2, local_aggregators_per_subnet=2, gossipsub_explicit_aggregator_count=1)
        )
        by_id = {node["node_id"]: node for node in nodes}
        for node in nodes:
            selected = [by_id[node_id] for node_id in node["selected_aggregator_ids"]]
            self.assertEqual(sorted(aggregator["subnet_id"] for aggregator in selected), node["signing_subnets"])

    def test_too_few_hosts_for_aggregators_fails(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.assign_nodes(self.experiment(validator_count=12, local_aggregators_per_subnet=12))


class NodeMapPlacementTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.map_path = Path(directory.name) / "nodes.csv"
        rows = ["node_type,peer_key,validator_count,validator_indices,routes,max_windows,source_file,receipts,first_seen_s,last_seen_s"]
        # 6 validator nodes with 4/2/1/1/1/1 validators, and 3 no_validator relays:
        # 9 hosts, 4 subnets, 2 subscriptions each, so every subnet has enough
        # distinct subscribers to promote one aggregator from.
        rows.append("validator,A,4,0;1;2;3,agg;att,5,roster.json,100,1,2")
        rows.append("validator,B,2,4;5,agg,3,roster.json,100,1,2")
        rows.append("validator,C,1,6,att,2,roster.json,100,1,2")
        rows.append("validator,D,1,7,att,2,roster.json,100,1,2")
        rows.append("validator,E,1,8,att,2,roster.json,100,1,2")
        rows.append("validator,F,1,9,att,2,roster.json,100,1,2")
        rows.append("no_validator,R1,0,,,0,roster.json,500,1,2")
        rows.append("no_validator,R2,0,,,0,roster.json,500,1,2")
        rows.append("no_validator,R3,0,,,0,roster.json,500,1,2")
        self.map_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        shadow_sim.load_node_map.cache_clear()

    def experiment(self, **overrides: object) -> dict:
        values = {
            "run_id": "test",
            "validator_count": 10,
            "subnet_count": 4,
            "local_aggregators_per_subnet": 1,
            "global_aggregator_count": 0,
            "geo_seed": 7,
            "node_map": str(self.map_path),
            "subnet_subscriptions_per_node": 2,
        }
        values.update(overrides)
        return shadow_sim.experiment_defaults(values)

    def test_all_validators_placed_on_map_hosts(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        placed = sorted(v for node in nodes for v in node["validator_ids"])
        self.assertEqual(placed, list(range(10)))
        by_peer = {node["peer_key"]: node for node in nodes}
        self.assertEqual(sum(len(node["validator_ids"]) for node in nodes), 10)
        # Slot sampling can split a node's slots, but never exceeds its capacity.
        for peer, capacity in (("A", 4), ("B", 2), ("C", 1)):
            self.assertLessEqual(len(by_peer[peer]["validator_ids"]), capacity)
        self.assertEqual(len({node["ip"] for node in nodes}), len(nodes))

    def test_relay_hosts_carry_no_validators(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        relays = [node for node in nodes if node["role"] == "relay"]
        self.assertTrue(relays)
        for node in relays:
            self.assertEqual(node["validator_ids"], [])
            self.assertEqual(node["source_node_type"], "no_validator")
            self.assertTrue(node["subscribed_subnets"])

    def test_every_node_subscribes_to_two_subnets(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        for node in nodes:
            if node["role"] in ("validator", "relay"):
                self.assertEqual(len(node["subscribed_subnets"]), 2, node)
            # Aggregators subscribe to their 2 random subnets plus the collected one.
            if node["role"] == "local_aggregator":
                self.assertLessEqual(len(node["subscribed_subnets"]), 3)
                self.assertIn(node["subnet_id"], node["subscribed_subnets"])

    def test_aggregators_are_subscribed_to_their_subnet(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        for subnet in range(4):
            aggregators = [node for node in nodes if node["role"] == "local_aggregator" and node["subnet_id"] == subnet]
            self.assertEqual(len(aggregators), 1)
            self.assertIn(subnet, aggregators[0]["subscribed_subnets"])

    def test_subscription_set_is_seeded(self) -> None:
        first = shadow_sim.assign_nodes(self.experiment())
        second = shadow_sim.assign_nodes(self.experiment())
        self.assertEqual(first, second)

    def test_publishing_subnets_are_independent_of_subscriptions(self) -> None:
        experiment = self.experiment(validator_count=7, subnet_count=4)
        nodes = shadow_sim.assign_nodes(experiment)
        signing = [node for node in nodes if node["validator_ids"]]
        self.assertTrue(signing)
        # With 4 subnets and 2 random subscriptions, some host must publish to a
        # subnet it is not subscribed to.
        publishing_outside = any(
            subnet not in node["subscribed_subnets"]
            for node in signing
            for subnet in node["signing_subnets"]
        )
        self.assertTrue(publishing_outside)

    def test_too_few_subscribers_for_aggregators_fails(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.assign_nodes(self.experiment(local_aggregators_per_subnet=100))


class SupernodeByValidatorCountTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.map_path = Path(directory.name) / "nodes.csv"
        rows = ["node_type,peer_key,validator_count,validator_indices"]
        rows.append("validator,BIG,150,0;1;2")
        rows.append("validator,SMALL,2,3;4")
        rows.append("validator,TINY,1,5")
        rows.append("no_validator,RELAY,0,")
        self.map_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        shadow_sim.load_node_map.cache_clear()

    def experiment(self, **overrides: object) -> dict:
        values = {
            "run_id": "test",
            "validator_count": 153,
            "subnet_count": 1,
            "local_aggregators_per_subnet": 1,
            "global_aggregator_count": 0,
            "geo_seed": 7,
            "node_map": str(self.map_path),
            "subnet_subscriptions_per_node": 1,
            "supernode_by_validator_count": 100,
        }
        values.update(overrides)
        return shadow_sim.experiment_defaults(values)

    def test_nodes_with_many_real_validators_are_supernodes(self) -> None:
        experiment = self.experiment()
        nodes = shadow_sim.assign_nodes(experiment)
        ids = shadow_sim.supernode_ids(nodes, experiment)
        by_peer = {node["peer_key"]: node for node in nodes}
        # All 153 slots are sampled, so every validator node is present.
        self.assertIn(by_peer["BIG"]["node_id"], ids)
        self.assertNotIn(by_peer["SMALL"]["node_id"], ids)
        self.assertNotIn(by_peer["TINY"]["node_id"], ids)
        relay = by_peer.get("RELAY")
        if relay is not None:
            self.assertNotIn(relay["node_id"], ids)

    def test_threshold_uses_real_slots_not_sampled(self) -> None:
        # BIG keeps its full 150-slot capacity even when only some slots are sampled,
        # so it stays a supernode regardless of how many validators the run selects.
        experiment = self.experiment(validator_count=3)
        nodes = shadow_sim.assign_nodes(experiment)
        ids = shadow_sim.supernode_ids(nodes, experiment)
        big = next(node for node in nodes if node["peer_key"] == "BIG")
        self.assertLessEqual(len(big["validator_ids"]), 150)
        self.assertIn(big["node_id"], ids)

    def test_requires_node_map(self) -> None:
        experiment = self.experiment()
        del experiment["node_map"]
        with self.assertRaises(SystemExit):
            shadow_sim.validate_experiment(experiment)


if __name__ == "__main__":
    unittest.main()
