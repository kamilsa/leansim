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


if __name__ == "__main__":
    unittest.main()
