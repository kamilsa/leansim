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


if __name__ == "__main__":
    unittest.main()
