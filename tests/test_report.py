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
from run_fixture import write_churn_run, write_fixture_run  # noqa: E402

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

    def test_config_names_bundled_propagation(self) -> None:
        config = {"signature_propagation": "bundled", "bundle_tick_ms": 20, "bundle_max_signatures": 50}
        self.assertEqual(report.config_groups(config, {}), [
            ("Gossip", [("Propagation", "bundled",
                         "every 20 ms, at most 50 a bundle; EIP-8334 over gossipsub partial messages")]),
        ])
        config["bundle_tick_ms"] = 0
        self.assertIn("every arrival", report.config_groups(config, {})[0][1][0][2])
        config["bundle_stagger_ms"] = 200
        self.assertIn("one end of each link waits 200 ms", report.config_groups(config, {})[0][1][0][2])
        config["bundle_announce"] = True
        self.assertIn("waits 200 ms and announces", report.config_groups(config, {})[0][1][0][2])

    def test_config_names_waggle_and_its_propagation(self) -> None:
        config = {"signature_transport": "waggle", "signature_propagation": "gossipsub", "waggle_bundled": True,
                  "waggle_push_peers": 8, "waggle_gossip_peers": 6, "gossipsub_heartbeat_interval_ms": 300,
                  "bundle_tick_ms": 20, "bundle_max_signatures": 50}
        rows = dict((label, (value, note)) for label, value, note in dict(report.config_groups(config, {}))["Gossip"])
        self.assertEqual(rows["Transport"],
                         ("waggle", "pushes to 8 subscribers of a subnet; advertises to 6 others every 300 ms"))
        self.assertEqual(rows["Propagation"], ("bundled", "every 20 ms, at most 50 a bundle; EIP-8334 over waggle"))

        config.update(waggle_bundled=False, waggle_push_peers=0, waggle_gossip_peers=0)
        rows = dict((label, (value, note)) for label, value, note in dict(report.config_groups(config, {}))["Gossip"])
        self.assertEqual(rows["Transport"], ("waggle", "pushes to every subscriber of a subnet"))
        self.assertEqual(rows["Propagation"], ("single", "one waggle message per signature, forwarded on receipt"))

        config.update(waggle_push_selection="hashed", waggle_push_peers=5)
        rows = dict((label, (value, note)) for label, value, note in dict(report.config_groups(config, {}))["Gossip"])
        self.assertEqual(rows["Transport"], (
            "waggle", "a hash of each signature and the two peer ids names the end of a link that sends it; "
                      "pushed to at most 5 of the subscribers it names this host for"))

        # Over gossipsub the propagation row says it all.
        rows = dict(report.config_groups({"signature_transport": "gossipsub", "signature_propagation": "gossipsub"}, {}))
        self.assertEqual(rows["Gossip"], [("Propagation", "gossipsub", "one message per signature")])

    def test_transport_section_shows_bundle_paths_and_ledger(self) -> None:
        empty = {"unique": 0, "duplicate": 0, "bytes": 0}
        metrics = {"signature_transport": {
            "hosts": 2,
            "deliveries": {"gossip": empty, "pull": empty, "coded": empty,
                           "bundle": {"unique": 5, "duplicate": 2, "bytes": 7000},
                           "backlog": {"unique": 0, "duplicate": 3, "bytes": 3000},
                           "requested": {"unique": 1, "duplicate": 0, "bytes": 1000}},
            "wire_bytes": {"bundled_signatures": 8000, "bundle_framing": 300, "parts_metadata": 200, "total": 8500},
            "counters": {"idontwant_ids_sent": 0, "forwards_suppressed": 0, "have_sent": 0, "want_sent": 0,
                         "coded_sent": 0, "bundles_sent": 3, "bundle_sigs_sent": 8, "pushes_avoided": 4,
                         "backlog_sigs_sent": 3, "lazy_sigs_sent": 2, "announce_ids_sent": 7, "iwant_responses": 5, "iwant_response_duplicates": 4,
                         "metadata_sent": 2, "available_ids_sent": 6, "request_ids_sent": 1,
                         "requested_sigs_served": 1, "requests_avoided": 2},
        }}
        metrics["mesh"] = {
            "links_sampled_at": "signing", "copies_per_link": 1.3,
            "push_duplicates_per_first_copy": 4.25, "one_copy_per_link_duplicates_per_first_copy": 3.1,
            "degree": {"signing": {"mean": 8.2, "min": 4, "max": 12}},
        }
        section = report.transport_section(metrics)
        self.assertIn("mesh degree 8.2 on average (4–12) at signing", section)
        self.assertIn("1.30 copies of a signature per mesh link; one per link would leave 3.10 pushed duplicates "
                      "per first copy instead of 4.25", section)
        self.assertEqual(report.mesh_facts(None), [])
        for text in ("Bundled signatures", "Bundle framing", "Parts metadata", "Bundle push", "Bundle request",
                     "Bundle backlog", "3 pushed as backlog to new mesh peers", "2 pushed after the stagger ran out", "7 announced to mesh peers",
                     "5 IWANT responses, 4 already held on arrival",
                     "8 signatures sent in 3 bundles, 4 pushes avoided", "6 indices advertised, 1 requested, 1 served", "2 arrived during the request delay"):
            self.assertIn(text, section)
        self.assertNotIn("Coded repair", section)

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


class ChurnFigureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="leansim-report-")
        cls.snapshot = analyze.build_snapshot(write_churn_run(Path(cls.temporary.name) / "run"))
        cls.metrics = cls.snapshot["metrics"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_config_names_each_class_churn(self) -> None:
        groups = dict(report.config_groups(self.snapshot["metadata"]["config"], self.metrics))
        self.assertEqual(groups["Churn"], [
            ("Supernodes", "stable", "never offline"),
            ("Regular nodes", "50% churny", "a churny host crashes with probability 0.01 a tick and rejoins with 0.05: "
                                            "10.0 s sessions, 2.0 s gaps, online 83% of the time"),
            ("Tick", "100 ms", ""),
            ("Crash", "silent", "all state lost but the peer table; peers hold the dead connection up to 10 s"),
        ])

    def test_config_without_churny_hosts_has_no_churn_card(self) -> None:
        config = {"churn_tick_ms": 100, "regular_churn_fraction": 0.0, "regular_churn_leave_probability": 0.01,
                  "regular_churn_rejoin_probability": 0.05, "supernode_churn_fraction": 0.0}
        self.assertEqual(report.config_groups(config, {}), [])
        config["supernode_churn_fraction"] = 0.125
        rows = dict(report.config_groups(config, {}))["Churn"]
        self.assertEqual(rows[0][:2], ("Supernodes", "12.5% churny"))
        self.assertEqual(rows[1], ("Regular nodes", "stable", "never offline"))

    def test_churny_hosts_get_delivery_lines_of_their_own(self) -> None:
        figure = report.cdf_figure(self.metrics)
        self.assertEqual([(trace["name"], trace["line"]["dash"]) for trace in figure["data"]], [
            ("First seen by any host", "dot"), ("Delivered to supernodes", "solid"),
            ("Delivered to regular nodes (stable)", "solid"), ("Delivered to regular nodes (churny)", "dash"),
        ])
        self.assertEqual(figure["layout"]["legend"]["yanchor"], "bottom", "a wrapped legend must not cover the plot")

    def test_churny_hosts_get_hollow_arrival_boxes(self) -> None:
        figure = report.arrival_figure(self.metrics)
        self.assertEqual([(trace["name"], trace["fillcolor"]) for trace in figure["data"]], [
            ("Supernodes", "#2a78d640"), ("Regular nodes (stable)", "#e3494840"), ("Regular nodes (churny)", "#ffffff"),
        ])
        table = report.arrival_table(self.metrics)
        self.assertIn('<span class="swatch" style="background:#ffffff;border:2px solid #e34948"></span>Regular nodes (churny)', table)

    def test_churny_aggregators_are_hollow_dots(self) -> None:
        metrics = {"subnet_proofs": [{"subnet": 2, "count": 2, "min": 0, "p25": 0, "p50": 0, "p75": 700, "max": 700,
                                      "proofs": [[0, 1, "supernode"], [700, 4, "supernode_churny"]]}]}
        _, stable, churny = report.subnet_proofs_figure(metrics)["data"]
        self.assertEqual((stable["name"], churny["name"]), ("Supernodes (stable)", "Supernodes (churny)"))
        self.assertEqual(churny["marker"]["symbol"], "circle-open")
        self.assertEqual(churny["text"], ["node 4"])

    def test_availability_lines_and_milestones(self) -> None:
        milestones = [{"label": "Signature burst", "time_ms": 1000}, {"label": "First subnet proof", "time_ms": 1100}]
        figure = report.availability_figure(self.metrics["churn"], milestones, 1000)
        self.assertEqual([trace["name"] for trace in figure["data"]], ["All hosts", "Regular nodes"])
        everyone = figure["data"][0]
        self.assertEqual((everyone["x"][0], everyone["y"][0]), (-1.0, 75.0))
        self.assertEqual(everyone["line"]["shape"], "hv", "hosts go offline in steps")
        self.assertEqual(figure["layout"]["yaxis"]["range"], [64, 100.5])
        self.assertEqual([shape["x0"] for shape in figure["layout"]["shapes"]], [0.0, 0.1])
        self.assertIn("First subnet proof · 0.10 s", figure["layout"]["annotations"][1]["text"])

    def test_catch_up_is_a_cdf_over_every_rejoin(self) -> None:
        figure = report.catch_up_figure(self.metrics["churn"])
        (regular,) = figure["data"]
        self.assertEqual(regular["name"], "Regular nodes")
        self.assertEqual(regular["x"], [0, 0.3, 0.7])
        self.assertEqual(regular["y"], [0, 50.0, 100.0])

    def test_churn_tables(self) -> None:
        churn = self.metrics["churn"]
        classes = report.churn_class_table(churn)
        self.assertIn("<td>3</td><td>2 <span class=\"note\">66.7%</span></td><td>2 <span class=\"note\">66.7%</span></td>"
                      "<td>1</td><td>2</td><td>2 <span class=\"note\">of 2</span></td>"
                      "<td>1 <span class=\"note\">50.0%</span></td>", classes)
        self.assertIn("<td>2</td><td>2 <span class=\"note\">100.0%</span></td><td>0.30 s</td><td>0.70 s</td>",
                      report.catch_up_table(churn))
        completion = report.completion_table(churn)
        self.assertLess(completion.index("Stable hosts"), completion.index("Churny hosts"))
        self.assertIn("<td>0.15 s</td><td>0.90 s</td>", completion)
        self.assertEqual(report.completion_table({"completion": {"stable": None, "churny": None}}), "")

    def test_churn_facts_name_what_the_crashes_cost(self) -> None:
        self.assertEqual(report.churn_facts(self.metrics["churn"]), [
            "2 signatures were received again by hosts that had lost them in a crash",
            "rejoining hosts told 2 peers they had restarted, and 1 of those still held a dead connection and reconnected",
            "1 sync request failed",
        ])
        self.assertEqual(report.churn_facts({"counters": {"repeated_proofs": 2, "sync_failures": 3, "failed_proof_pulls": 1}}), [
            "3 sync requests and 1 proof pull failed",
            "2 subnet proofs built again by an aggregator back from a crash are not counted",
        ])

    def test_a_churny_host_says_so(self) -> None:
        card = self.metrics["traffic"]["1"]["host"]
        self.assertEqual(report.host_facts(card), "Germany · regular node · ↑ 50 / ↓ 100 Mbps · 1 validator · validator · churny, 1 crash")

    def test_aggregator_table_says_which_aggregators_churn(self) -> None:
        info = {"churn": {"churny": 1}, "aggregators": [
            {"node": 4, "country": "japan", "class": "regular", "uplink_mbps": 50, "downlink_mbps": 100, "validators": 1, "crashes": 3},
            {"node": 7, "country": "germany", "class": "supernode", "uplink_mbps": 1000, "downlink_mbps": 1000, "validators": 12},
        ]}
        table = report.aggregator_table(info, {"proofs": [[1500, 7, "supernode"]]}, logged=set())
        self.assertIn("<th>Validators</th><th>Churn</th><th>Subnet proof</th>", table)
        self.assertIn("<td>12</td><td>stable</td><td>1.50 s</td>", table)
        self.assertIn("<td>1</td><td>3 crashes</td><td>–</td>", table)


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

    def test_offline_windows_are_shaded_and_carry_no_traffic(self) -> None:
        traffic = dict(TRAFFIC_FIXTURE["traffic"], offline_ms=[[1250, 1350]])
        self.run_node({"traffic-data": dict(TRAFFIC_FIXTURE, traffic=traffic)}, report.TRAFFIC_JS, r"""
const timeline = plots.get('timeline');
const bands = timeline.layout.shapes.filter(shape => shape.type === 'rect' && shape.fillcolor === '#e34948');
assert.deepEqual(bands.map(band => [band.x0, band.x1]), [[1.25, 1.35]]);
const sent = timeline.traces.find(trace => trace.legendgroup === 'signature' && trace.stackgroup === 'sent');
assert.deepEqual(sent.x, [1, 1.2, 1.35, 1.4, 1.5], 'the window starts inside an idle frame and ends in the open');
assert.deepEqual(sent.y, [10, 0, 0, 10, 0], 'no curve rises before the host is back');
assert.equal(elements.get('peak').textContent, '10.00 MB/s');
""")
        self.run_node({"report-data": {"figures": {}, "previews": {"7": traffic}}}, report.SUMMARY_JS, r"""
assert.deepEqual(plots.get('preview-7').layout.shapes.map(band => [band.x0, band.x1]), [[1.25, 1.35]]);
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
        self.assertEqual(set(data["figures"]), {"cdf", "arrival", "subnet-proofs", "validators", "countries",
                                                "subnet-counts", "aggregator-countries"})
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

    def test_network_section_describes_aggregators(self) -> None:
        self.assertIn('id="aggregator-countries"', self.summary)
        self.assertIn('id="subnet-counts"', self.summary)
        self.assertTrue("1 host aggregates subnets: 1 supernode, 0 regular nodes, over 1 subnet, in 1 country." in self.summary,
                        "the network section describes the aggregator population")

    def test_a_run_without_churn_shows_none(self) -> None:
        for marker in ('id="churn"', "kpis five", "Online at signing", "Got again after a crash", "(churny)", "(stable)"):
            self.assertNotIn(marker, self.summary)
        self.assertNotIn("Red bands: the host was offline", self.traffic)
        page = (Path(self.temporary.name) / "report" / "subnet-0.html").read_text(encoding="utf-8")
        self.assertNotIn("<th>Churn</th>", page)

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


@unittest.skipUnless(HAS_PLOTLY, "needs the analyze dependency group (plotly)")
class ChurnPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="leansim-report-")
        root = Path(cls.temporary.name)
        output = root / "report" / "summary.html"
        output.parent.mkdir()
        report.generate_html(analyze.build_snapshot(write_churn_run(root / "run")), output)
        cls.summary = output.read_text(encoding="utf-8")
        cls.traffic = (output.parent / "traffic-1.html").read_text(encoding="utf-8")
        cls.subnet = (output.parent / "subnet-0.html").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_summary_has_a_churn_section_after_the_network(self) -> None:
        self.assertLess(self.summary.index('id="network"'), self.summary.index('id="churn"'))
        self.assertLess(self.summary.index('id="churn"'), self.summary.index('id="propagation"'))
        section = self.summary.split('id="churn"', 1)[1].split("</section>", 1)[0]
        for text in ("2 of 4 hosts churn", "QUIC's idle timeout (10 s)", 'id="churn-availability"', 'id="churn-catch-up"',
                     "Catching up after a rejoin", "how long until it held 75%", "Subnet completion",
                     "2 signatures were received again"):
            self.assertIn(text, section)
        data = embedded(self.summary, "report-data")
        self.assertTrue({"churn-availability", "churn-catch-up"} <= set(data["figures"]))
        self.assertEqual(data["previews"]["1"]["offline_ms"], [[1500, 2500]])

    def test_kpis_say_how_many_hosts_were_online_at_signing(self) -> None:
        kpis = self.summary.split('<div class="kpis five">', 1)[1].split("</div></div>", 1)[0]
        self.assertIn('<span class="label">Online at signing</span><b>75.0%</b>'
                      '<span class="note">1 of 4 hosts offline · 1 signatures missed</span>', kpis)
        self.assertIn("stable regular nodes", kpis)

    def test_config_and_transport_show_churn(self) -> None:
        config = self.summary.split('id="config"', 1)[1].split("</section>", 1)[0]
        self.assertIn("<h3>Churn</h3>", config)
        self.assertIn("50% churny", config)
        transport = self.summary.split('id="transport"', 1)[1].split("</section>", 1)[0]
        self.assertIn("<th>Got again after a crash</th>", transport)
        self.assertIn("<tr><td>Bundle backlog</td><td>1</td><td>1</td><td>2</td></tr>", transport)

    def test_subnet_proofs_caption_counts_aggregators_without_a_proof(self) -> None:
        caption = self.summary.split('id="subnet-proofs-heading"', 1)[1].split("</p>", 1)[0]
        self.assertIn("Hollow dots are churny hosts.", caption)
        self.assertNotIn("never finished", caption, "the only aggregator proved")

    def test_traffic_page_marks_the_offline_windows(self) -> None:
        self.assertIn("churny, 1 crash", self.traffic)
        self.assertIn("Red bands: the host was offline, 1 time for 1.0 s in all.", self.traffic)
        self.assertEqual(embedded(self.traffic, "traffic-data")["traffic"]["offline_ms"], [[1500, 2500]])

    def test_subnet_page_counts_its_churny_hosts(self) -> None:
        self.assertIn("4 subscribed hosts · 4 validators on them · 1 subnet aggregator · 2 churny · "
                      "3 online at signing · 1 signatures missed", self.subnet)
        self.assertIn("<th>Churn</th>", self.subnet)
        self.assertIn("<td>2</td><td>stable</td><td>0.10 s</td>", self.subnet)
        self.assertEqual(len(embedded(self.subnet, "subnet-data")["figures"]["subnet-cdf"]["data"]), 4)


if __name__ == "__main__":
    unittest.main()
