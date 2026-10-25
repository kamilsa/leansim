import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyze  # noqa: E402
from run_fixture import EXPERIMENT, write_fixture_run  # noqa: E402


class FrequencyTests(unittest.TestCase):
    def test_percentiles_use_nearest_rank(self) -> None:
        self.assertEqual(
            analyze.frequency_percentiles({10: 1, 20: 3}),
            {"count": 4, "p5": 10, "p25": 10, "p50": 20, "p75": 20, "p95": 20},
        )

    def test_percentiles_of_nothing_are_none(self) -> None:
        self.assertIsNone(analyze.frequency_percentiles({}))

    def test_cdf_is_cumulative_percent(self) -> None:
        self.assertEqual(analyze.frequency_cdf(Counter({300: 1, 100: 2, 200: 1})), [[100, 50.0], [200, 75.0], [300, 100.0]])

    def test_cdf_is_thinned_but_keeps_both_ends(self) -> None:
        points = analyze.frequency_cdf({value: 1 for value in range(1000)}, limit=400)
        self.assertEqual(len(points), 400)
        self.assertEqual(points[0], [0, 0.1])
        self.assertEqual(points[-1], [999, 100.0])


class NodeClassTests(unittest.TestCase):
    def test_classes_follow_the_manifest_flag(self) -> None:
        self.assertEqual(analyze.node_class({"supernode": True}), "supernode")
        self.assertEqual(analyze.node_class({"supernode": False}), "regular")
        self.assertEqual(analyze.node_class({"node_id": 4}), "unknown")
        self.assertEqual(analyze.node_class(None), "unknown")


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="leansim-analyze-")
        cls.snapshot = analyze.build_snapshot(write_fixture_run(Path(cls.temporary.name) / "run"))
        cls.metrics = cls.snapshot["metrics"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_metadata_keeps_the_main_config(self) -> None:
        skipped = {"supernode_by_validator_count", "supernode_fraction", "node_map"}
        self.assertEqual(self.snapshot["metadata"]["config"], {key: value for key, value in EXPERIMENT.items() if key not in skipped})

    def test_times_start_at_the_first_signature(self) -> None:
        self.assertEqual(self.metrics["t0_ms"], 1000)

    def test_arrival_rows_per_message_and_class(self) -> None:
        self.assertEqual(self.metrics["arrivals"], [
            {"message": "Signatures", "class": "supernode", "count": 1, "p5": 50, "p25": 50, "p50": 50, "p75": 50, "p95": 50},
            {"message": "Signatures", "class": "regular", "count": 4, "p5": 100, "p25": 100, "p50": 200, "p75": 300, "p95": 400},
            {"message": "Subnet proofs", "class": "supernode", "count": 1, "p5": 1000, "p25": 1000, "p50": 1000, "p75": 1000, "p95": 1000},
            {"message": "Subnet proofs", "class": "regular", "count": 1, "p5": 1300, "p25": 1300, "p50": 1300, "p75": 1300, "p95": 1300},
            {"message": "Final proof", "class": "supernode", "count": 1, "p5": 2200, "p25": 2200, "p50": 2200, "p75": 2200, "p95": 2200},
            {"message": "Final proof", "class": "regular", "count": 1, "p5": 2000, "p25": 2000, "p50": 2000, "p75": 2000, "p95": 2000},
        ])

    def test_signature_cdf_lines(self) -> None:
        self.assertEqual(self.metrics["signature_cdf"], {
            "first_seen": [[50, 25.0], [100, 50.0], [200, 75.0], [300, 100.0]],
            "supernode": [[50, 100.0]],
            "regular": [[100, 25.0], [200, 50.0], [300, 75.0], [400, 100.0]],
        })

    def test_population_from_the_manifest(self) -> None:
        self.assertEqual(self.metrics["population"], {
            "hosts": 3,
            "validators": 4,
            "supernode_by_validator_count": 2,
            "supernode_fraction": 0.05,
            "classes": [
                {"class": "supernode", "uplink_mbps": 1000, "downlink_mbps": 1000, "hosts": 1, "validators": 3},
                {"class": "regular", "uplink_mbps": 50, "downlink_mbps": 100, "hosts": 2, "validators": 1},
            ],
            "validators_per_host": [
                {"low": 0, "high": 0, "supernode": 0, "regular": 1, "unknown": 0, "validators": 0},
                {"low": 1, "high": 1, "supernode": 0, "regular": 1, "unknown": 0, "validators": 1},
                {"low": 2, "high": 3, "supernode": 1, "regular": 0, "unknown": 0, "validators": 3},
            ],
            "countries": [
                {"country": "germany", "supernode": 0, "regular": 2, "unknown": 0, "validators": 1},
                {"country": "finland", "supernode": 1, "regular": 0, "unknown": 0, "validators": 3},
            ],
        })

    def test_traffic_hosts_carry_their_manifest_card(self) -> None:
        self.assertEqual(self.metrics["traffic"]["1"]["host"], {
            "country": "germany", "class": "regular", "uplink_mbps": 50, "downlink_mbps": 100,
            "validators": 1, "role": "validator", "duties": {"subnets": [], "layers": {}, "final": False},
        })

    def test_subnet_proofs_in_the_snapshot(self) -> None:
        self.assertEqual(self.metrics["subnet_proofs"], [
            {"subnet": 0, "count": 1, "min": 1000, "p25": 1000, "p50": 1000, "p75": 1000, "max": 1000,
             "proofs": [[1000, 0, "supernode"]]},
        ])

    def test_subnet_proof_rows_spread_every_aggregator(self) -> None:
        hosts = {1: {"supernode": True}, 2: {"supernode": False}, 3: {"supernode": False}}
        local_proofs = [(1, 5, 1300), (2, 5, 1100), (3, 5, 1200), (4, 5, 1500), (1, 2, 1000), (None, 2, 1700)]
        self.assertEqual(analyze.subnet_proof_rows(local_proofs, 1000, hosts), [
            {"subnet": 2, "count": 2, "min": 0, "p25": 0, "p50": 0, "p75": 700, "max": 700,
             "proofs": [[0, 1, "supernode"], [700, None, "unknown"]]},
            {"subnet": 5, "count": 4, "min": 100, "p25": 100, "p50": 200, "p75": 300, "max": 500,
             "proofs": [[100, 2, "regular"], [200, 3, "regular"], [300, 1, "supernode"], [500, 4, "unknown"]]},
        ])

    def test_duties_split_subnets_tree_layers_and_the_final_proof(self) -> None:
        host = {"aggregated_subnets": [40, 12], "recursive_seats": [[2, 3], [1, 11], [1, 10], [3, 0]]}
        self.assertEqual(analyze.host_duties(host, top_layer=3),
                         {"subnets": [12, 40], "layers": {"1": [10, 11], "2": [3]}, "final": True})
        self.assertEqual(analyze.host_duties({}, top_layer=None), {"subnets": [], "layers": {}, "final": False})

    def test_subnet_pages_show_this_subnet_only(self) -> None:
        self.assertEqual(self.metrics["subnet_hosts"], {
            0: {"classes": {"supernode": 1, "regular": 1, "unknown": 0},
                "countries": [{"country": "finland", "supernode": 1, "regular": 0, "unknown": 0, "validators": 3},
                              {"country": "germany", "supernode": 0, "regular": 1, "unknown": 0, "validators": 1}],
                "aggregators": [{"node": 0, "country": "finland", "class": "supernode",
                                 "uplink_mbps": 1000, "downlink_mbps": 1000, "validators": 3}],
                "aggregator_countries": [{"country": "finland", "supernode": 1, "regular": 0, "unknown": 0,
                                          "validators": 3}]}})
        self.assertEqual(self.metrics["signature_cdf_by_subnet"], {
            0: {"first_seen": [[50, 25.0], [100, 50.0], [200, 75.0], [300, 100.0]],
                "supernode": [[50, 100.0]],
                "regular": [[100, 25.0], [200, 50.0], [300, 75.0], [400, 100.0]]}})

    def test_aggregator_population_counts_hosts_and_their_subnets(self) -> None:
        self.assertEqual(self.metrics["aggregators"], {
            "hosts": 1, "subnets": 1, "validators": 3,
            "classes": [{"class": "supernode", "uplink_mbps": 1000, "downlink_mbps": 1000, "hosts": 1, "validators": 3}],
            "countries": [{"country": "finland", "supernode": 1, "regular": 0, "unknown": 0, "validators": 3}],
            "subnets_per_host": [{"low": 1, "high": 1, "supernode": 1, "regular": 0, "unknown": 0, "validators": 3}],
        })

    def test_runs_without_a_node_list_have_no_population(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leansim-analyze-") as temporary:
            directory = write_fixture_run(Path(temporary) / "run")
            (directory / "run-manifest.json").write_text('{"experiment": {"local_threshold": 1.0}}', encoding="utf-8")
            metrics = analyze.build_snapshot(directory)["metrics"]
        self.assertIsNone(metrics["population"])
        self.assertEqual({row["class"] for row in metrics["arrivals"]}, {"unknown"})


if __name__ == "__main__":
    unittest.main()
