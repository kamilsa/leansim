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


if __name__ == "__main__":
    unittest.main()
