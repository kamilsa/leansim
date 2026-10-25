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


TRAFFIC_FIXTURE = {
    "node": "7", "run": "test", "warmup_ms": 800,
    "milestones": [{"label": "Signature burst", "time_ms": 1100}, {"label": "First subnet proof", "time_ms": 1200},
                   {"label": "Final proof", "time_ms": 1400}],
    "traffic": {"bucket_ms": 100, "sent": 3000000, "received": 1000000, "peers": [], "buckets": [
        {"start_ms": 1000, "width_ms": 200, "outbound": {"signature": 2000000}, "inbound": {"proof_payload": 1000000}},
        {"start_ms": 1400, "width_ms": 100, "outbound": {"signature": 1000000}, "inbound": {}},
    ]},
}

DOM_AND_PLOTLY_MOCK = r"""
const assert = require('node:assert/strict');
const elements = new Map();
global.document = {getElementById(id) {
  if (!elements.has(id)) elements.set(id, {textContent: PAGE_DATA[id] || '', checked: false,
    addEventListener(event, handler) { this[event] = handler; }});
  return elements.get(id);
}};
const plots = new Map();
global.Plotly = {
  newPlot(id, traces, layout, config) { plots.set(id, {traces, layout, config}); },
  restyle(id, changes) {
    for (const trace of plots.get(id).traces) {
      for (const [key, value] of Object.entries(changes)) {
        const [field, property] = key.split('.');
        trace[field][property] = value;
      }
    }
  },
};
"""


@unittest.skipUnless(HAS_NODE, "needs node to run the page scripts")
class ScriptTests(unittest.TestCase):
    def run_node(self, page_data: dict, script: str, checks: str) -> None:
        source = ("const PAGE_DATA = " + json.dumps({key: json.dumps(value) for key, value in page_data.items()}) + ";\n"
                  + DOM_AND_PLOTLY_MOCK + report.COMMON_JS + script + checks)
        with tempfile.TemporaryDirectory(prefix="leansim-js-") as temporary:
            path = Path(temporary) / "page.js"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(["node", str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_traffic_timeline(self) -> None:
        self.run_node({"traffic-data": TRAFFIC_FIXTURE}, report.TRAFFIC_JS, r"""
const timeline = plots.get('timeline');
assert.deepEqual(timeline.layout.xaxis.range, [0, 1.5], 'include the run start, not just traffic');
assert.equal(timeline.layout.paper_bgcolor, '#ffffff');
assert.equal(timeline.layout.shapes[0].x0, 0);
assert.equal(timeline.layout.shapes[0].x1, 0.8);
assert.match(timeline.layout.annotations[0].text, /warmup.*traffic not.*captured/i);
assert.ok(timeline.layout.shapes.some(shape => shape.type === 'line' && shape.x0 === 1.4));
assert.ok(timeline.layout.annotations.some(note => note.text.includes('Final proof')));
assert.notEqual(timeline.layout.annotations[1].y, timeline.layout.annotations[2].y, 'nearby milestones need separate label lanes');
const sent = timeline.traces.find(trace => trace.legendgroup === 'signature' && trace.stackgroup === 'sent');
const received = timeline.traces.find(trace => trace.legendgroup === 'proof_payload' && trace.stackgroup === 'received');
assert.equal(sent.type, 'scatter');
assert.equal(sent.line.shape, 'spline', 'default timeline should have curved outlines');
assert.deepEqual(sent.x, [1, 1.2, 1.4, 1.5]);
assert.deepEqual(sent.y, [10, 0, 10, 0]);
assert.deepEqual(received.y, [-5, 0, 0, 0]);
assert.match(timeline.layout.yaxis.title.text, /MB\/s/);
assert.equal(elements.get('peak').textContent, '10.00 MB/s');
const rawToggle = document.getElementById('raw-buckets');
rawToggle.checked = true;
rawToggle.change();
assert.ok(timeline.traces.every(trace => trace.line.shape === 'hv'));
assert.deepEqual(sent.y, [10, 0, 10, 0], 'switching views must not alter measured rates');
""")

    def test_traffic_timeline_without_warmup_metadata(self) -> None:
        self.run_node({"traffic-data": dict(TRAFFIC_FIXTURE, warmup_ms=None)}, report.TRAFFIC_JS, r"""
assert.equal(plots.get('timeline').layout.xaxis.range[0], 0);
assert.ok(plots.get('timeline').layout.shapes.every(shape => shape.type !== 'rect'));
""")

    def test_summary_plots_figures_and_previews_on_one_time_axis(self) -> None:
        later = dict(TRAFFIC_FIXTURE["traffic"], buckets=[
            {"start_ms": 2900, "width_ms": 100, "outbound": {"signature": 100}, "inbound": {}}])
        figures = {"cdf": {"data": [], "layout": {"xaxis": {"title": {"text": "t"}}}}}
        self.run_node({"report-data": {"figures": figures, "previews": {"7": TRAFFIC_FIXTURE["traffic"], "8": later}}},
                      report.SUMMARY_JS, r"""
assert.equal(plots.get('cdf').layout.xaxis.gridcolor, '#e1e0d9', 'figures get the shared white theme');
assert.equal(plots.get('cdf').layout.xaxis.title.text, 't');
assert.deepEqual(plots.get('preview-7').layout.xaxis.range, [0, 3]);
assert.deepEqual(plots.get('preview-8').layout.xaxis.range, [0, 3]);
assert.equal(plots.get('preview-7').config.staticPlot, true);
""")


if __name__ == "__main__":
    unittest.main()
