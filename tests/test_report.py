import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyze  # noqa: E402
import report  # noqa: E402
from run_fixture import write_fixture_run  # noqa: E402

HAS_PLOTLY = importlib.util.find_spec("plotly") is not None
HAS_NODE = shutil.which("node") is not None


def fixture_snapshot(directory: Path) -> dict:
    return analyze.build_snapshot(write_fixture_run(directory / "run"))


def embedded(document: str, element_id: str) -> dict:
    marker = f'<script id="{element_id}" type="application/json">'
    return json.loads(document.split(marker, 1)[1].split("</script>", 1)[0])


class FigureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="leansim-report-")
        cls.metrics = fixture_snapshot(Path(cls.temporary.name))["metrics"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_host_facts_line(self) -> None:
        card = {"country": "finland", "class": "supernode", "uplink_mbps": 1000, "downlink_mbps": 1000,
                "validators": 3, "role": "local_aggregator"}
        self.assertEqual(report.host_facts(card), "Finland · supernode · ↑ 1,000 / ↓ 1,000 Mbps · 3 validators · local aggregator")
        self.assertEqual(report.host_facts(None), "No manifest entry for this host")

    def test_cdf_has_first_seen_and_one_line_per_class(self) -> None:
        figure = report.cdf_figure(self.metrics)
        self.assertEqual([trace["name"] for trace in figure["data"]],
                         ["First seen by any host", "Delivered to supernodes", "Delivered to regular nodes"])
        self.assertEqual(figure["data"][2]["x"], [0.1, 0.2, 0.3, 0.4])
        self.assertEqual(figure["data"][2]["y"], [25.0, 50.0, 75.0, 100.0])

    def test_arrival_boxes_use_precomputed_percentiles_in_seconds(self) -> None:
        figure = report.arrival_figure(self.metrics)
        supernodes, regular = figure["data"]
        self.assertEqual((supernodes["name"], regular["name"]), ("Supernodes", "Regular nodes"))
        self.assertEqual(regular["y"], ["Signatures", "Subnet proofs", "Final proof"])
        self.assertEqual(regular["lowerfence"], [0.1, 1.3, 2.0])
        self.assertEqual(regular["median"], [0.2, 1.3, 2.0])
        self.assertEqual(regular["upperfence"], [0.4, 1.3, 2.0])
        self.assertEqual(figure["layout"]["yaxis"]["categoryarray"], ["Signatures", "Subnet proofs", "Final proof"])

    def test_validator_bins_are_labelled_and_totalled(self) -> None:
        figure = report.validators_figure(self.metrics["population"])
        self.assertEqual(figure["data"][0]["x"], ["0", "1", "2–3"])
        self.assertEqual([note["text"] for note in figure["layout"]["annotations"]], ["1", "1", "1"])

    def test_countries_put_hosts_and_validators_side_by_side(self) -> None:
        figure = report.countries_figure(self.metrics["population"])
        self.assertEqual(figure["data"][0]["y"], ["Germany", "Finland"])
        self.assertEqual(figure["data"][-1]["x"], [1, 3])
        self.assertEqual(figure["data"][-1]["xaxis"], "x2")


if __name__ == "__main__":
    unittest.main()
