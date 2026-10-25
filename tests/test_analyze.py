import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyze  # noqa: E402
from run_fixture import write_fixture_run  # noqa: E402


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
        cls.metrics = analyze.build_snapshot(write_fixture_run(Path(cls.temporary.name) / "run"))["metrics"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

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


if __name__ == "__main__":
    unittest.main()
