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
            "gossipsub_explicit_aggregator_count": explicit_count,
            "geo_seed": 7,
        }
    )


class ExplicitAggregatorAssignmentTests(unittest.TestCase):
    def test_assigns_reciprocal_same_subnet_aggregators(self) -> None:
        nodes = shadow_sim.assign_nodes(experiment(2))
        by_id = {node["node_id"]: node for node in nodes}

        for node in nodes:
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

    def test_every_host_has_mesh_n_peers_on_its_subnets(self) -> None:
        # One random seed per host leaves most subnets without peers; the top-up
        # must restore gossipsub_mesh_n on subscribed subnets and
        # PUBLISH_SUBNET_PEER_COUNT on publish-only ones (or every available subscriber).
        original = shadow_sim.SEED_PEER_COUNT
        shadow_sim.SEED_PEER_COUNT = 1
        self.addCleanup(setattr, shadow_sim, "SEED_PEER_COUNT", original)
        experiment = self.experiment(gossipsub_mesh_n=3, gossipsub_mesh_n_low=2, gossipsub_mesh_n_high=4, gossipsub_mesh_outbound_min=1)
        nodes = shadow_sim.assign_nodes(experiment)
        node_of = {node["listen_addr"]: node["node_id"] for node in nodes}
        peers = {node["node_id"]: set() for node in nodes}
        for node in nodes:
            for address in node["seed_addrs"]:
                peers[node["node_id"]].add(node_of[address])
                peers[node_of[address]].add(node["node_id"])
        for node in nodes:
            for subnet in set(node["subscribed_subnets"]) | set(node["signing_subnets"]):
                on_subnet = [peer for peer in peers[node["node_id"]] if subnet in nodes[peer]["subscribed_subnets"]]
                available = sum(1 for other in nodes if other is not node and subnet in other["subscribed_subnets"])
                target = 3 if subnet in node["subscribed_subnets"] else shadow_sim.PUBLISH_SUBNET_PEER_COUNT
                self.assertGreaterEqual(len(on_subnet), min(target, available), (node["node_id"], subnet))


    def test_subscriber_aggregators_aggregate_exactly_their_subnet(self) -> None:
        for node in shadow_sim.assign_nodes(self.experiment()):
            expected = [node["subnet_id"]] if node["role"] == "local_aggregator" else []
            self.assertEqual(node["aggregated_subnets"], expected)
            self.assertEqual(node["aggregator_validator_ids"], [])


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


class AllHostsPlacementTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.map_path = Path(directory.name) / "nodes.csv"
        # 10 slots over 3 validator nodes + 2 no_validator nodes; sample 4 slots.
        rows = [
            "node_type,peer_key,validator_count,validator_indices",
            "validator,BIG,6,0;1;2;3;4;5",
            "validator,MID,3,6;7;8",
            "validator,SOLO,1,9",
            "no_validator,R1,0,",
            "no_validator,R2,0,",
        ]
        self.map_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        shadow_sim.load_node_map.cache_clear()

    def experiment(self, **overrides: object) -> dict:
        values = {
            "run_id": "test",
            "validator_count": 4,
            "subnet_count": 1,
            "local_aggregators_per_subnet": 1,
            "geo_seed": 7,
            "node_map": str(self.map_path),
            "subnet_subscriptions_per_node": 1,
            "all_hosts": True,
        }
        values.update(overrides)
        return shadow_sim.experiment_defaults(values)

    def test_every_map_node_runs(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        self.assertEqual(len(nodes), 5)
        peers = {node["peer_key"] for node in nodes}
        self.assertEqual(peers, {"BIG", "MID", "SOLO", "R1", "R2"})
        self.assertEqual(sum(len(n["validator_ids"]) for n in nodes), 4)
        # Hosts without a sampled slot relay; no_validator nodes relay too.
        for node in nodes:
            if node["validator_ids"]:
                self.assertIn(node["role"], ("validator", "local_aggregator"))
            else:
                self.assertEqual(node["role"], "relay")
                self.assertEqual(node["source_node_type"],
                                 "no_validator" if node["peer_key"] in ("R1", "R2") else "validator")

    def test_without_all_hosts_small_hosts_are_dropped(self) -> None:
        # 1 slot sampled: only the host that got it plus proportional relays run.
        nodes = shadow_sim.assign_nodes(self.experiment(all_hosts=False, validator_count=1))
        with_slot = [node for node in nodes if node["validator_ids"]]
        self.assertEqual(len(with_slot), 1)
        self.assertLess(len(nodes), 5)

    def test_all_hosts_requires_node_map(self) -> None:
        experiment = self.experiment()
        del experiment["node_map"]
        with self.assertRaises(SystemExit):
            shadow_sim.validate_experiment(experiment)


class DutySubnetSubscriptionTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.map_path = Path(directory.name) / "nodes.csv"
        # 16 validators on BIG and SOLO (2 subnets of 8), 1 relay.
        rows = [
            "node_type,peer_key,validator_count,validator_indices",
            "validator,BIG,15,0;1;2;3;4;5;6;7;8;9;10;11;12;13;14",
            "validator,SOLO,1,15",
            "no_validator,R1,0,",
        ]
        self.map_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        shadow_sim.load_node_map.cache_clear()

    def experiment(self, **overrides: object) -> dict:
        values = {
            "run_id": "test",
            "validator_count": 16,
            "subnet_count": 2,
            "local_aggregators_per_subnet": 1,
            "geo_seed": 7,
            "node_map": str(self.map_path),
            "subnet_subscriptions_per_node": 2,
            "subscribe_to_duty_subnets": True,
        }
        values.update(overrides)
        return shadow_sim.experiment_defaults(values)

    def test_validator_hosts_subscribe_to_their_duty_subnets(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        by_peer = {node["peer_key"]: node for node in nodes}
        # BIG's validators span both subnets, so it must be subscribed to both.
        self.assertEqual(by_peer["BIG"]["signing_subnets"], [0, 1])
        self.assertEqual(set(by_peer["BIG"]["subscribed_subnets"]), {0, 1})
        # SOLO's single validator lands in one duty subnet; the second subscription
        # is the random one, so it is subscribed to exactly 2 distinct subnets.
        solo_duty = set(by_peer["SOLO"]["signing_subnets"])
        self.assertEqual(len(by_peer["SOLO"]["subscribed_subnets"]), 2)
        self.assertTrue(solo_duty.issubset(by_peer["SOLO"]["subscribed_subnets"]))

    def test_relays_keep_only_random_subscriptions(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        relay = next(node for node in nodes if node["peer_key"] == "R1")
        self.assertEqual(len(relay["subscribed_subnets"]), 2)

    def test_without_duty_flag_subscriptions_stay_random(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment(subscribe_to_duty_subnets=False))
        for node in nodes:
            if node["role"] in ("validator", "relay"):
                self.assertEqual(len(node["subscribed_subnets"]), 2)

    def test_aggregator_stays_subscribed_to_its_collected_subnet(self) -> None:
        nodes = shadow_sim.assign_nodes(self.experiment())
        for subnet in range(2):
            aggregators = [n for n in nodes if n["role"] == "local_aggregator" and n["subnet_id"] == subnet]
            self.assertEqual(len(aggregators), 1)
            self.assertIn(subnet, aggregators[0]["subscribed_subnets"])

    def test_duty_subscriptions_require_node_map(self) -> None:
        experiment = self.experiment()
        del experiment["node_map"]
        with self.assertRaises(SystemExit):
            shadow_sim.validate_experiment(experiment)


if __name__ == "__main__":
    unittest.main()


class RemovedConfigKeysTests(unittest.TestCase):
    def test_removed_keys_are_rejected(self) -> None:
        for key, value in (
            ("global_aggregator_count", 0),
            ("global_proof_target", 0.66),
            ("global_aggregation_rate", 10),
            ("proof_payload_bytes", 131072),
        ):
            config = shadow_sim.experiment_defaults({"run_id": "t", "validator_count": 4, "subnet_count": 1, key: value})
            with self.assertRaises(SystemExit, msg=key):
                shadow_sim.validate_experiment(config)

    def test_validator_map_is_rejected(self) -> None:
        config = shadow_sim.experiment_defaults({"run_id": "t", "validator_count": 4, "subnet_count": 1, "validator_map": "located-map.csv"})
        with self.assertRaises(SystemExit):
            shadow_sim.validate_experiment(config)

    def test_without_a_node_map_every_validator_runs_on_its_own_host(self) -> None:
        nodes = shadow_sim.assign_nodes(experiment(0))
        self.assertEqual([node["validator_ids"] for node in nodes], [[v] for v in range(12)])
        self.assertTrue(all("peer_key" not in node for node in nodes))

    def test_no_global_aggregator_hosts(self) -> None:
        nodes = shadow_sim.assign_nodes(experiment(0))
        self.assertEqual(len(nodes), 12)
        self.assertNotIn("global_aggregator", {node["role"] for node in nodes})


class CommitteeAggregatorTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.map_path = Path(directory.name) / "nodes.csv"
        # 20 validator slots on 8 hosts plus 2 no_validator relays; 16 validators
        # in 2 committees of 8.
        rows = [
            "node_type,peer_key,validator_count,validator_indices",
            "validator,BIG,12," + ";".join(str(i) for i in range(12)),
            "validator,MID,2,12;13",
            "validator,S1,1,14",
            "validator,S2,1,15",
            "validator,S3,1,16",
            "validator,S4,1,17",
            "validator,S5,1,18",
            "validator,S6,1,19",
            "no_validator,R1,0,",
            "no_validator,R2,0,",
        ]
        self.map_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        shadow_sim.load_node_map.cache_clear()

    def experiment(self, **overrides: object) -> dict:
        values = {
            "run_id": "test",
            "validator_count": 16,
            "subnet_count": 2,
            "local_aggregators_per_subnet": 4,
            "geo_seed": 7,
            "node_map": str(self.map_path),
            "all_hosts": True,
            "subnet_subscriptions_per_node": 1,
            "committee_aggregators": True,
        }
        values.update(overrides)
        return shadow_sim.experiment_defaults(values)

    def winners(self, experiment: dict) -> list[int]:
        return [v for v in range(experiment["validator_count"]) if shadow_sim.is_aggregator(v, experiment)]

    def test_committees_are_contiguous_id_blocks_mapped_to_subnets(self) -> None:
        experiment = self.experiment()
        self.assertEqual([shadow_sim.committee_of(v, experiment) for v in (0, 7, 8, 15)], [0, 0, 1, 1])
        self.assertEqual(shadow_sim.subnet_for_committee(1, experiment), 1)
        self.assertEqual(list(shadow_sim.committee_members(1, experiment)), list(range(8, 16)))

    def test_lottery_is_seeded(self) -> None:
        self.assertEqual(self.winners(self.experiment()), [0, 1, 3, 8, 9, 12, 14, 15])
        self.assertEqual(self.winners(self.experiment(geo_seed=8)), [1, 2, 3, 5, 6, 10, 14])

    def test_lottery_picks_everyone_when_target_covers_the_committee(self) -> None:
        self.assertEqual(self.winners(self.experiment(local_aggregators_per_subnet=8)), list(range(16)))

    def test_lottery_hits_the_target_on_average(self) -> None:
        experiment = {"validator_count": 65536, "subnet_count": 64, "local_aggregators_per_subnet": 16, "geo_seed": 7}
        winners = sum(shadow_sim.is_aggregator(v, experiment) for v in range(65536))
        # Binomial(65536, 1/64): mean 1024, sd ~32 (seed 7 gives 1009).
        self.assertTrue(900 <= winners <= 1150, winners)

    def test_duties_go_to_the_hosts_of_the_winners(self) -> None:
        experiment = self.experiment()
        hosts = shadow_sim.place_nodes(experiment)
        duties = shadow_sim.select_committee_aggregators(hosts, experiment)
        by_peer = {hosts[index]["peer_key"]: subnets for index, subnets in duties.items()}
        self.assertEqual(by_peer, {
            "S5": {0: [0]},
            "BIG": {0: [1], 1: [8, 9, 14]},
            "S2": {0: [3]},
            "MID": {1: [12]},
            "S6": {1: [15]},
        })

    def test_aggregators_are_signing_hosts_of_their_committees(self) -> None:
        experiment = self.experiment()
        nodes = shadow_sim.assign_nodes(experiment)
        aggregators = [node for node in nodes if node["role"] == "local_aggregator"]
        self.assertEqual(sorted(node["peer_key"] for node in aggregators), ["BIG", "MID", "S2", "S5", "S6"])
        for node in aggregators:
            self.assertTrue(set(node["aggregator_validator_ids"]) <= set(node["validator_ids"]))
            self.assertEqual(
                node["aggregated_subnets"],
                sorted({shadow_sim.committee_of(v, experiment) for v in node["aggregator_validator_ids"]}),
            )
            self.assertTrue(set(node["aggregated_subnets"]) <= set(node["subscribed_subnets"]))
            self.assertEqual(node["subnet_id"], node["aggregated_subnets"][0])

    def test_host_aggregates_each_committee_once(self) -> None:
        by_peer = {node["peer_key"]: node for node in shadow_sim.assign_nodes(self.experiment())}
        self.assertEqual(by_peer["BIG"]["aggregated_subnets"], [0, 1])
        self.assertEqual(by_peer["BIG"]["aggregator_validator_ids"], [1, 8, 9, 14])

    def test_validator_less_hosts_never_aggregate(self) -> None:
        for node in shadow_sim.assign_nodes(self.experiment(local_aggregators_per_subnet=8)):
            if not node["validator_ids"]:
                self.assertEqual(node["role"], "relay")
                self.assertEqual(node["aggregated_subnets"], [])
            else:
                self.assertEqual(node["role"], "local_aggregator")

    def test_committee_aggregators_require_node_map(self) -> None:
        experiment = self.experiment()
        del experiment["node_map"]
        with self.assertRaises(SystemExit):
            shadow_sim.validate_experiment(experiment)

    def test_committee_aggregators_must_be_boolean(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.validate_experiment(self.experiment(committee_aggregators="yes"))

    def test_committee_aggregators_need_a_positive_target(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.validate_experiment(self.experiment(local_aggregators_per_subnet=0))


class MeshWarmupTests(unittest.TestCase):
    @staticmethod
    def nodes(*dials: int) -> list[dict]:
        return [{"seed_addrs": ["a"] * count, "explicit_peer_addrs": []} for count in dials]

    def test_short_warmup_when_no_host_dials_many_peers(self) -> None:
        self.assertEqual(shadow_sim.mesh_warmup_ms(self.nodes(10, 200)), 1500)

    def test_busiest_host_sets_the_warmup_for_everyone(self) -> None:
        self.assertEqual(shadow_sim.mesh_warmup_ms(self.nodes(10, 201)), 3000)

    def test_explicit_peers_count_as_dials(self) -> None:
        nodes = [{"seed_addrs": ["a"] * 150, "explicit_peer_addrs": ["a"] * 51}]
        self.assertEqual(shadow_sim.mesh_warmup_ms(nodes), 3000)

    def test_configured_warmup_must_be_non_negative(self) -> None:
        config = shadow_sim.experiment_defaults({"run_id": "t", "validator_count": 4, "subnet_count": 1, "mesh_warmup_ms": -1})
        with self.assertRaises(SystemExit):
            shadow_sim.validate_experiment(config)


class RecursiveTreeTests(unittest.TestCase):
    def test_layer_sizes_shrink_by_the_arity_until_one_group(self) -> None:
        self.assertEqual(shadow_sim.recursive_layer_sizes(64, 2), [32, 16, 8, 4, 2, 1])
        self.assertEqual(shadow_sim.recursive_layer_sizes(64, 4), [16, 4, 1])
        self.assertEqual(shadow_sim.recursive_layer_sizes(64, 8), [8, 1])
        self.assertEqual(shadow_sim.recursive_layer_sizes(64, 16), [4, 1])

    def test_groups_take_consecutive_children_and_the_last_takes_the_rest(self) -> None:
        groups = shadow_sim.recursive_groups({"subnet_count": 6, "recursive_aggregation_arity": 4})
        self.assertEqual(
            [(group["layer"], group["index"], group["children"]) for group in groups],
            [(1, 0, [0, 1, 2, 3]), (1, 1, [4, 5]), (2, 0, [0, 1])],
        )

    def test_eight_to_one_over_64_subnets_is_eight_groups_and_a_root(self) -> None:
        groups = shadow_sim.recursive_groups({"subnet_count": 64, "recursive_aggregation_arity": 8})
        self.assertEqual(len(groups), 9)
        self.assertEqual(groups[0]["children"], list(range(8)))
        self.assertEqual(groups[-1], {"layer": 2, "index": 0, "children": list(range(8))})


class RecursivePoolTests(unittest.TestCase):
    def test_pools_partition_validators_in_a_seeded_order(self) -> None:
        pools = shadow_sim.recursive_pools({"validator_count": 16, "geo_seed": 7}, 3)
        self.assertEqual(pools, [[7, 8, 1, 13, 0], [14, 11, 9, 10, 2], [4, 12, 6, 3, 5, 15]])
