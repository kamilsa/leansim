import importlib.util
import unittest
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


if __name__ == "__main__":
    unittest.main()
