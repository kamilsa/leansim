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
        cls.snapshot = fixture_snapshot(Path(cls.temporary.name))
        cls.metrics = cls.snapshot["metrics"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_config_groups_name_the_main_settings(self) -> None:
        self.assertEqual(report.config_groups(self.snapshot["metadata"]["config"], self.metrics), [
            ("Signatures", [
                ("Signature size", "1,200 B", ""),
                ("Aggregation rate", "1,000 signatures/s",
                 "a 100% proof of a 4-validator committee (4 signatures) takes 4 ms"),
                ("Local threshold", "100%", "of a committee's signatures per subnet proof"),
                ("Signing", "100–110 ms after warmup", "warmup 900 ms"),
            ]),
            ("Aggregation", [
                ("Committees", "1 × 4 validators", "one committee per subnet"),
                ("Subnet aggregators", "~1 per committee", "is_aggregator lottery"),
                ("Recursive aggregation", "2-to-1", "1 layer above the subnet proofs"),
                ("Recursive proof time", "276 ms", "per 2-to-1 proof"),
                ("Group size", "~16 members", "lottery target per group"),
                ("Proof size", "262,144 B", "256 KiB, every subnet and recursive proof"),
            ]),
            ("Gossip", [
                ("Mesh degree", "8", "low 4, high 12"),
                ("Heartbeat", "300 ms", ""),
                ("Subnet subscriptions", "2 per host", ""),
                ("Flood publish", "off", ""),
            ]),
        ])

    def test_config_without_recursion_or_settings(self) -> None:
        config = {"recursive_aggregation": False, "committee_aggregators": False, "local_aggregators_per_subnet": 16,
                  "aggregate_proof_bytes": 262144, "subscribe_to_duty_subnets": True, "subnet_subscriptions_per_node": 2}
        self.assertEqual(report.config_groups(config, {}), [
            ("Aggregation", [
                ("Subnet aggregators", "16 per subnet", "promoted among subnet subscribers"),
                ("Recursive aggregation", "off", "subnet proofs are logged, not sent"),
            ]),
            ("Gossip", [("Subnet subscriptions", "2 per host", "plus the subnets its validators sign in")]),
        ])
        self.assertEqual(report.config_groups({}, {}), [])

    def test_subnet_proof_candles_and_one_dot_per_aggregator(self) -> None:
        metrics = {"subnet_proofs": [
            {"subnet": 2, "count": 2, "min": 0, "p25": 0, "p50": 0, "p75": 700, "max": 700,
             "proofs": [[0, 1, "supernode"], [700, None, "unknown"]]},
            {"subnet": 5, "count": 3, "min": 100, "p25": 100, "p50": 200, "p75": 300, "max": 300,
             "proofs": [[100, 2, "regular"], [200, 3, "regular"], [300, 1, "supernode"]]},
        ]}
        figure = report.subnet_proofs_figure(metrics)
        candles, *dots = figure["data"]
        self.assertEqual((candles["type"], candles["orientation"]), ("box", "h"))
        self.assertEqual(candles["y"], [2, 5])
        self.assertEqual(candles["lowerfence"], [0.0, 0.1])
        self.assertEqual(candles["q1"], [0.0, 0.1])
        self.assertEqual(candles["median"], [0.0, 0.2])
        self.assertEqual(candles["q3"], [0.7, 0.3])
        self.assertEqual(candles["upperfence"], [0.7, 0.3])
        self.assertEqual([trace["name"] for trace in dots], ["Supernodes", "Regular nodes", "Unclassified"])
        regular = dots[1]
        self.assertEqual(regular["x"], [0.1, 0.2])
        self.assertEqual(regular["y"], [5.0, 4.8], "dots of one subnet alternate across its row")
        self.assertEqual(regular["text"], ["node 2", "node 3"])
        self.assertEqual(dots[2]["text"], ["unknown node"])
        self.assertEqual(figure["layout"]["yaxis"]["autorange"], "reversed")
        self.assertEqual(figure["layout"]["yaxis"]["tickvals"], [2, 5])
        self.assertEqual(figure["layout"]["yaxis"]["ticktext"], ["subnet 2", "subnet 5"])
        self.assertEqual(report.subnet_proofs_figure({}), None)

    def test_host_facts_line(self) -> None:
        card = {"country": "finland", "class": "supernode", "uplink_mbps": 1000, "downlink_mbps": 1000,
                "validators": 3, "role": "local_aggregator"}
        self.assertEqual(report.host_facts(card), "Finland · supernode · ↑ 1,000 / ↓ 1,000 Mbps · 3 validators · local aggregator")
        self.assertEqual(report.host_facts(None), "No manifest entry for this host")

    def test_duty_line(self) -> None:
        self.assertEqual(report.duty_text({"subnets": [], "layers": {}, "final": False}), "Not an aggregator")
        self.assertEqual(report.duty_text({"subnets": [32], "layers": {}, "final": False}), "Subnet aggregator (subnet 32)")
        self.assertEqual(
            report.duty_text({"subnets": list(range(23)), "layers": {"1": list(range(10)), "2": [3, 4]}, "final": True}),
            "Subnet aggregator (23 subnets) · Layer 1 aggregator (10 groups) · Layer 2 aggregator (groups 3, 4) · Final proof aggregator",
        )
        self.assertEqual(report.duty_text({"subnets": [], "layers": {"10": [0], "2": [7]}, "final": False}),
                         "Layer 2 aggregator (group 7) · Layer 10 aggregator (group 0)")
        self.assertIsNone(report.duty_text(None), "snapshots from before duties were recorded say nothing")

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

    def test_subnet_label_click_opens_its_page(self) -> None:
        self.run_node({"report-data": {"figures": {}, "previews": {}}}, "global.location = {href: 'summary.html'};\n"
                      + report.SUMMARY_JS, r"""
const plot = document.getElementById('subnet-proofs');
plot.click({target: {closest: selector => selector === '.ytick' ? {textContent: 'subnet 12'} : null}});
assert.equal(location.href, 'subnet-12.html');
location.href = 'summary.html';
plot.click({target: {closest: () => null}});
assert.equal(location.href, 'summary.html', 'clicks off the labels do nothing');
""")

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


@unittest.skipUnless(HAS_PLOTLY, "needs the analyze dependency group (plotly)")
class PageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="leansim-report-")
        root = Path(cls.temporary.name)
        output = root / "report" / "summary.html"
        output.parent.mkdir()
        report.generate_html(fixture_snapshot(root), output)
        cls.summary = output.read_text(encoding="utf-8")
        cls.traffic = (output.parent / "traffic-1.html").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_summary_has_every_section(self) -> None:
        for marker in ('id="cdf"', 'id="arrival"', 'id="subnet-proofs"', 'id="validators"', 'id="countries"', 'class="classes"',
                       'class="arrivals"', 'id="preview-1"', 'href="traffic-1.html"', "Open traffic profile"):
            self.assertIn(marker, self.summary)
        self.assertTrue('<p class="duties">Not an aggregator</p>' in self.summary.split('id="traffic"', 1)[1],
                        "every preview card needs a duty line")
        self.assertNotIn("history-body", self.summary, "the summary shows the primary run only")
        self.assertIn("Supernodes are hosts running at least 2 validators.", self.summary)

    def test_summary_shows_the_config(self) -> None:
        section = self.summary.split('id="config"', 1)[1].split("</section>", 1)[0]
        for text in ("Configuration", "2-to-1", "276 ms", "1,000 signatures/s", "1,200 B", "262,144 B"):
            self.assertIn(text, section)
        self.assertLess(self.summary.index('id="config"'), self.summary.index('id="network"'))

    def test_arrival_caption_says_what_each_row_measures(self) -> None:
        caption = self.summary.split('id="arrivals"', 1)[1].split('id="arrival"', 1)[0]
        self.assertIn("finished building the final proof", caption)
        self.assertIn("not when the root members received their input proofs", caption)
        self.assertIn("finished building it or finished fetching it", caption)

    def test_summary_embeds_figures_and_previews(self) -> None:
        data = embedded(self.summary, "report-data")
        self.assertEqual(set(data["figures"]), {"cdf", "arrival", "subnet-proofs", "validators", "countries"})
        self.assertEqual(set(data["previews"]), {"1"})

    def test_subnet_page_shows_this_subnet(self) -> None:
        page = (Path(self.temporary.name) / "report" / "subnet-0.html").read_text(encoding="utf-8")
        self.assertIn('href="summary.html"', page)
        self.assertIn("<h1>Subnet 0</h1>", page)
        data = embedded(page, "subnet-data")
        self.assertEqual(data["subnet"], 0)
        self.assertEqual(data["info"]["classes"], {"supernode": 1, "regular": 1, "unknown": 0})
        self.assertEqual(data["info"]["countries"][0]["country"], "finland")
        self.assertIn("subnet-subscribers", page)
        for figure_id in data["figures"]:
            self.assertTrue(f'id="{figure_id}"' in page, f"figure {figure_id} needs a chart div with that id")
        self.assertTrue('id="subnet-subscribers" style="height:162px"' in page, "the div must fit the figure height")
        self.assertIn("subnet-aggregators", data["figures"])
        self.assertTrue("1 host aggregates this subnet: 1 supernode, 0 regular nodes, in 1 country." in page,
                        "the aggregator caption counts hosts by class and country")
        self.assertTrue('<tr><td>0</td><td>Finland</td><td><span class="swatch" style="background:#2a78d6"></span>Supernode</td>'
                        '<td>1,000 Mbps</td><td>1,000 Mbps</td><td>3</td><td>1.00 s</td></tr>' in page,
                        "one table row per aggregator with its subnet proof time")

    def test_aggregator_table_orders_by_proof_time_and_links_logged_hosts(self) -> None:
        info = {"aggregators": [
            {"node": 4, "country": "japan", "class": "regular", "uplink_mbps": 50, "downlink_mbps": 100, "validators": 1},
            {"node": 7, "country": "germany", "class": "supernode", "uplink_mbps": 1000, "downlink_mbps": 1000, "validators": 12},
            {"node": 9, "country": None, "class": "unknown", "uplink_mbps": None, "downlink_mbps": None, "validators": 0},
        ]}
        row = {"proofs": [[1500, 7, "supernode"], [2250, 4, "regular"]]}
        table = report.aggregator_table(info, row, logged={"4"})
        self.assertLess(table.index("<td>7</td>"), table.index('<a href="traffic-4.html">4</a>'))
        self.assertLess(table.index('<a href="traffic-4.html">4</a>'), table.index("<td>9</td>"),
                        "aggregators without a subnet proof go last")
        self.assertTrue("<td>2.25 s</td>" in table and "<td>Unknown</td>" in table and "<td>–</td>" in table)
        self.assertEqual(report.aggregator_table({}, row, logged=set()), "")

    def test_subnet_page_survives_a_json_round_trip(self) -> None:
        snapshot = json.loads(json.dumps(fixture_snapshot(Path(self.temporary.name) / "json-round-trip")))
        with tempfile.TemporaryDirectory(prefix="leansim-report-") as temporary:
            output = Path(temporary) / "report" / "summary.html"
            output.parent.mkdir()
            report.generate_html(snapshot, output)
            page = (output.parent / "subnet-0.html").read_text(encoding="utf-8")
        data = embedded(page, "subnet-data")
        self.assertEqual(data["info"]["classes"], {"supernode": 1, "regular": 1, "unknown": 0})
        self.assertEqual(len(data["figures"]["subnet-cdf"]["data"]), 3)

    def test_subnet_labels_open_subnet_pages(self) -> None:
        self.assertIn("#subnet-proofs .ytick text { pointer-events: all; cursor: pointer; }", self.summary,
                      "Plotly turns off pointer events on its SVG, so the labels need them back")
        self.assertIn("subnetPlot.addEventListener('click'", self.summary,
                      "one listener on the chart container survives Plotly redrawing its ticks")

    def test_summary_is_white(self) -> None:
        self.assertIn("background: #ffffff", self.summary)
        self.assertNotIn("color-scheme: dark", self.summary + self.traffic)

    def test_traffic_page_layout(self) -> None:
        self.assertIn("Germany · regular node · ↑ 50 / ↓ 100 Mbps · 1 validator · validator", self.traffic)
        self.assertTrue('<p class="duties">Not an aggregator</p>' in self.traffic, "the traffic page needs a duty line")
        self.assertIn('class="traffic-stage"', self.traffic)
        self.assertIn('<table class="peer-ledger">', self.traffic)
        self.assertIn('aria-label="Logged hosts"', self.traffic)
        self.assertIn("Measurement notes", self.traffic)
        self.assertIn('href="summary.html"', self.traffic)
        self.assertNotIn('id="peers"', self.traffic, "a second chart must not compete with the timeline")

    def test_traffic_page_data(self) -> None:
        data = embedded(self.traffic, "traffic-data")
        self.assertEqual(data["warmup_ms"], 900)
        self.assertEqual(data["milestones"], [
            {"label": "Signature burst", "time_ms": 1002.5},
            {"label": "First subnet proof", "time_ms": 2000},
            {"label": "Final proof", "time_ms": 3000},
        ])


if __name__ == "__main__":
    unittest.main()
