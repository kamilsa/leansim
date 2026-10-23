#!/usr/bin/env python3
"""Build an offline, interactive summary of one or more leanSim Shadow runs."""

import argparse
import html
import json
import math
import shutil
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


EVENT_NAMES = {
    "NodePeerId",
    "SigSent",
    "SigReceived",
    "LocalProofGenerated",
    "ProofAnnounced",
    "ProofRequested",
    "ProofFetched",
    "ProofFetchFailed",
    "ProofServed",
    "RecursiveProofGenerated",
    "NodeStats",
}


def number(value):
    """Return a finite numeric value, or None for malformed event fields."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) else None


def integer(value):
    value = number(value)
    return int(value) if value is not None else None


def median(values):
    values = sorted(values)
    if not values:
        return None
    middle = len(values) // 2
    if len(values) % 2:
        return values[middle]
    return (values[middle - 1] + values[middle]) / 2


def latency_stats(values):
    values = sorted(values)
    if not values:
        return None
    return {"min": values[0], "median": median(values), "max": values[-1], "count": len(values)}


def json_data(value):
    """Serialize data safely for an application/json script element."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c").replace(
        ">", "\\u003e"
    ).replace("&", "\\u0026")


def read_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def metadata_for(output_dir):
    """Read optional runner metadata and the manifest experiment configuration."""
    manifest = read_json(output_dir / "run-manifest.json")
    meta = read_json(output_dir / "run-meta.json")
    sources = (meta, manifest, meta.get("run", {}), manifest.get("run", {}))

    def first(*keys):
        for source in sources:
            if not isinstance(source, dict):
                continue
            for key in keys:
                value = source.get(key)
                if value is not None:
                    return value
        return None

    experiment = manifest.get("experiment")
    if not isinstance(experiment, dict):
        experiment = meta.get("experiment") if isinstance(meta.get("experiment"), dict) else {}
    threshold = number(experiment.get("local_threshold"))
    if threshold is None:
        threshold = number(first("local_threshold"))
    if threshold is not None and not 0 < threshold <= 1:
        threshold = None

    return {
        "runner": first("runner", "runner_name"),
        "seed": first("seed", "random_seed", "geo_seed"),
        "run_index": first("run_index", "index"),
        "run_id": first("run_id", "name"),
        "local_threshold": threshold,
    }


def event_files(output_dir):
    shadow_dir = output_dir if output_dir.name == "shadow.data" else output_dir / "shadow.data"
    hosts_dir = shadow_dir / "hosts"
    if not hosts_dir.is_dir():
        return []
    return sorted(path for path in hosts_dir.glob("*/*stdout*") if path.is_file())


def validator_key(event, host_field):
    """Identify the signing validator; older logs only carry the host id, which then equals it."""
    validator_id = integer(event.get("validator_id"))
    if validator_id is None:
        validator_id = integer(event.get(host_field))
    if validator_id is not None:
        return "validator:" + str(validator_id)
    peer_id = event.get("from_peer_id")
    if isinstance(peer_id, str) and peer_id:
        return "peer:" + peer_id
    return None


def recursive_summary(output_dir, recursive_done, final_times, traffic, local_latencies):
    """Aggregation-tree timing for runs with recursive aggregation, else None: when
    each subnet got its first proof, each group's first and median proof, each
    layer's first and last group, and the final proof."""
    plan = read_json(output_dir / "aggregation-plan.json")
    planned = [group for group in plan.get("groups", []) if isinstance(group, dict)] if isinstance(plan.get("groups"), list) else []
    if not planned and not recursive_done:
        return None
    groups = [
        {"layer": layer, "index": index, "first": min(times), "median": median(times), "members_done": len(times)}
        for (layer, index), times in sorted(recursive_done.items())
    ]
    layer_ids = sorted({group["layer"] for group in groups} | {group["layer"] for group in planned if isinstance(group.get("layer"), int)})
    layers = {}
    for layer in layer_ids:
        firsts = [group["first"] for group in groups if group["layer"] == layer]
        layers[str(layer)] = {
            "groups_planned": sum(1 for group in planned if group.get("layer") == layer),
            "groups_done": len(firsts),
            "first": min(firsts, default=None),
            "median": median(firsts),
            "last": max(firsts, default=None),
        }
    subnet_first = [min(values) for values in local_latencies.values() if values]
    return {
        "arity": plan.get("arity"),
        "groups_planned": len(planned),
        "groups_done": len(groups),
        "subnet_proofs_ms": {"first": min(subnet_first), "median": median(subnet_first), "last": max(subnet_first)} if subnet_first else None,
        "layers": layers,
        "groups": groups,
        "final_proof_ms": min(final_times) if final_times else None,
        "traffic": traffic,
    }


def build_snapshot(output_dir):
    """Parse a run directory into a JSON-serializable metrics snapshot."""
    output_dir = output_dir.resolve()
    metadata = metadata_for(output_dir)
    peer_ids = {}
    sent_times = []
    sent_by_node = defaultdict(list)
    signing_hosts = set()
    sent_sources_by_subnet = defaultdict(set)
    received_by_node_subnet = defaultdict(dict)
    validator_arrivals = {}
    local_latencies = defaultdict(list)
    node_stats = {}
    total_bytes = 0
    total_sig_received = 0
    duplicate_sigs = 0
    unique_receive_events = 0
    parsed_events = 0
    invalid_lines = 0

    # Keep proof timestamps by node/subnet for stage timing even if logs end early.
    local_proofs = []
    recursive_done = defaultdict(list)
    final_times = []
    proof_traffic = {
        "announcements": 0, "pulls": 0, "proofs_fetched": 0, "extra_proofs_fetched": 0,
        "failed_pulls": 0, "fetched_bytes": 0, "served_bytes": 0,
    }
    for path in event_files(output_dir):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue
            if not isinstance(event, dict) or event.get("event") not in EVENT_NAMES:
                continue
            parsed_events += 1
            name = event["event"]
            byte_size = integer(event.get("byte_size"))
            if byte_size is not None and byte_size >= 0:
                total_bytes += byte_size

            if name == "NodePeerId":
                node_id = integer(event.get("node_id"))
                peer_id = event.get("peer_id")
                if node_id is not None and isinstance(peer_id, str) and peer_id:
                    peer_ids[peer_id] = node_id
            elif name == "SigSent":
                timestamp = number(event.get("ts_ms"))
                node_id = integer(event.get("node_id"))
                subnet_id = integer(event.get("subnet_id"))
                key = validator_key(event, "node_id")
                if timestamp is not None:
                    sent_times.append(timestamp)
                if node_id is not None:
                    signing_hosts.add(node_id)
                if node_id is not None and subnet_id is not None and key is not None:
                    sent_sources_by_subnet[subnet_id].add(key)
                    if timestamp is not None:
                        sent_by_node[node_id].append((subnet_id, key, timestamp))
            elif name == "SigReceived":
                total_sig_received += 1
                duplicate = event.get("duplicate") is True
                if duplicate:
                    duplicate_sigs += 1
                    continue
                unique_receive_events += 1
                timestamp = number(event.get("ts_ms"))
                node_id = integer(event.get("node_id"))
                subnet_id = integer(event.get("subnet_id"))
                key = validator_key(event, "from_id")
                if timestamp is not None and key is not None:
                    previous = validator_arrivals.get(key)
                    if previous is None or timestamp < previous:
                        validator_arrivals[key] = timestamp
                    if node_id is not None and subnet_id is not None:
                        seen = received_by_node_subnet[(node_id, subnet_id)]
                        previous = seen.get(key)
                        if previous is None or timestamp < previous:
                            seen[key] = timestamp
            elif name == "LocalProofGenerated":
                latency = number(event.get("latency_ms"))
                node_id = integer(event.get("node_id"))
                subnet_id = integer(event.get("subnet_id"))
                if latency is not None and subnet_id is not None:
                    local_latencies[subnet_id].append(latency)
                    local_proofs.append((node_id, subnet_id, latency))
            elif name == "ProofAnnounced":
                proof_traffic["announcements"] += 1
            elif name == "ProofRequested":
                proof_traffic["pulls"] += 1
            elif name == "ProofFetched":
                proof_traffic["proofs_fetched"] += 1
                if event.get("duplicate") is True:
                    proof_traffic["extra_proofs_fetched"] += 1
                if byte_size is not None and byte_size >= 0:
                    proof_traffic["fetched_bytes"] += byte_size
            elif name == "ProofFetchFailed":
                proof_traffic["failed_pulls"] += 1
            elif name == "ProofServed":
                if byte_size is not None and byte_size >= 0:
                    proof_traffic["served_bytes"] += byte_size
            elif name == "RecursiveProofGenerated":
                layer_id = integer(event.get("layer"))
                group_index = integer(event.get("index"))
                timestamp = number(event.get("ts_ms"))
                if layer_id is not None and group_index is not None and timestamp is not None:
                    recursive_done[(layer_id, group_index)].append(timestamp)
                    if event.get("is_final") is True:
                        final_times.append(timestamp)
            elif name == "NodeStats":
                node_id = integer(event.get("node_id"))
                if node_id is None:
                    continue
                current = node_stats.setdefault(
                    node_id,
                    {"node_id": node_id, "bytes_sent": 0, "bytes_received": 0, "msgs_sent": 0, "msgs_received": 0},
                )
                # Stats can be emitted more than once; counters are cumulative, so retain the latest maximum.
                for key in ("bytes_sent", "bytes_received", "msgs_sent", "msgs_received"):
                    value = integer(event.get(key))
                    if value is not None and value >= 0:
                        current[key] = max(current[key], value)

    arrival_times = sorted(validator_arrivals.values())
    cdf = [
        {"time_ms": value, "percent": round((index + 1) * 100 / len(arrival_times), 4)}
        for index, value in enumerate(arrival_times)
    ]

    def arrival_at(percent):
        if not arrival_times:
            return None
        return arrival_times[max(0, math.ceil(len(arrival_times) * percent / 100) - 1)]

    threshold_fraction = metadata["local_threshold"]
    threshold_times = []
    compute_times = []
    proof_times = []
    if threshold_fraction is not None:
        for node_id, subnet_id, proof_time in local_proofs:
            if node_id is None:
                continue
            received = dict(received_by_node_subnet.get((node_id, subnet_id), {}))
            # An aggregating host holds its own validators' signatures without gossip.
            for own_subnet, key, own_time in sent_by_node.get(node_id, ()):
                if own_subnet == subnet_id:
                    received.setdefault(key, own_time)
            expected = len(sent_sources_by_subnet.get(subnet_id, set()))
            if not expected:
                expected = len(received)
            # Mirror the simulator's usize cast: thresholds truncate rather
            # than round up (e.g. 128 validators at 90% means 115 signatures).
            needed = int(expected * threshold_fraction)
            if needed and len(received) >= needed:
                threshold_time = sorted(received.values())[needed - 1]
                threshold_times.append(threshold_time)
                if proof_time >= threshold_time:
                    compute_times.append(proof_time - threshold_time)
            proof_times.append(proof_time)
    else:
        proof_times = [proof_time for _, _, proof_time in local_proofs]

    # Per signing host: time from the first signature sent until the host holds at
    # least threshold_fraction of its subnet's signatures, its own validators included.
    node_threshold = None
    if threshold_fraction is not None and sent_times:
        slot_start = min(sent_times)
        reached = []
        population = 0
        for node_id, own_signatures in sent_by_node.items():
            for subnet_id in sorted({subnet for subnet, _, _ in own_signatures}):
                population += 1
                held = dict(received_by_node_subnet.get((node_id, subnet_id), {}))
                for own_subnet, key, own_time in own_signatures:
                    if own_subnet == subnet_id:
                        held.setdefault(key, own_time)
                needed = math.ceil(len(sent_sources_by_subnet[subnet_id]) * threshold_fraction - 1e-9)
                if needed and len(held) >= needed:
                    reached.append(sorted(held.values())[needed - 1] - slot_start)
        reached.sort()

        def node_percentile(percent):
            # Hosts that never reached the threshold count as infinitely late.
            index = math.ceil(population * percent / 100) - 1
            return reached[index] if 0 <= index < len(reached) else None

        node_threshold = {
            "nodes": population,
            "reached": len(reached),
            "p50": node_percentile(50),
            "p95": node_percentile(95),
            "max": node_percentile(100),
        }

    local_by_subnet = {str(subnet): latency_stats(values) for subnet, values in sorted(local_latencies.items())}
    nodes = []
    for node in sorted(node_stats.values(), key=lambda item: item["node_id"]):
        node = dict(node)
        node["bytes_total"] = node["bytes_sent"] + node["bytes_received"]
        node["msgs_total"] = node["msgs_sent"] + node["msgs_received"]
        nodes.append(node)
    unique_validators = len(arrival_times)
    ratio = duplicate_sigs / unique_receive_events if unique_receive_events else 0.0

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output_dir": str(output_dir),
        "metadata": metadata,
        "metrics": {
            "parsed_events": parsed_events,
            "ignored_invalid_json_lines": invalid_lines,
            "event_files": len(event_files(output_dir)),
            "total_bytes": total_bytes,
            "total_sig_received": total_sig_received,
            "unique_signature_events": unique_receive_events,
            "duplicate_signature_events": duplicate_sigs,
            "duplicate_to_unique_ratio": ratio,
            "unique_validators": unique_validators,
            "signing_hosts": len(signing_hosts),
            "signature_arrival_ms": {"p50": arrival_at(50), "p90": arrival_at(90), "p95": arrival_at(95), "p99": arrival_at(99)},
            "local_proof_latency_ms_by_subnet": local_by_subnet,
            "stage_medians_ms": {
                "signatures_sent": median(sent_times),
                "threshold_reached": median(threshold_times),
                "aggregation_compute": median(compute_times),
                "local_proof_published": median(proof_times),
            },
            "threshold_fraction": threshold_fraction,
            "node_threshold_ms": node_threshold,
            "recursive_aggregation": recursive_summary(output_dir, recursive_done, final_times, proof_traffic, local_latencies),
        },
        "cdf": cdf,
        "node_stats": nodes,
    }


def snapshot_identity(snapshot):
    metadata = snapshot.get("metadata", {})
    return (
        snapshot.get("output_dir"),
        json.dumps(metadata.get("seed"), sort_keys=True),
        json.dumps(metadata.get("run_index"), sort_keys=True),
    )


def load_history(path):
    """Accept the current history envelope and a legacy bare snapshot list."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    values = value.get("snapshots") if isinstance(value, dict) else value
    if not isinstance(values, list):
        return []
    return [snapshot for snapshot in values if isinstance(snapshot, dict) and snapshot.get("output_dir")]


def merge_history(existing, snapshots, append):
    """Apply primary/overlay history semantics without losing valid prior entries."""
    primary, *overlays = snapshots
    if not existing:
        merged = [primary]
        seen = {snapshot_identity(primary)}
        for snapshot in overlays:
            key = snapshot_identity(snapshot)
            if key not in seen:
                merged.append(snapshot)
                seen.add(key)
        return merged

    merged = list(existing)
    primary_dir = primary.get("output_dir")
    if append:
        merged.append(primary)
    else:
        # Summary-only and serve-only should refresh the current run's latest
        # snapshot without adding another campaign row.
        matches = [index for index, snapshot in enumerate(merged) if snapshot_identity(snapshot) == snapshot_identity(primary)]
        if matches:
            merged[matches[-1]] = primary
        else:
            merged.append(primary)
    seen = {snapshot_identity(snapshot) for snapshot in merged}
    for snapshot in overlays:
        if snapshot.get("output_dir") == primary_dir:
            continue
        key = snapshot_identity(snapshot)
        if key not in seen:
            merged.append(snapshot)
            seen.add(key)
    return merged


INTERACTIVE_JS = r"""
const data = JSON.parse(document.getElementById('snapshot-data').textContent);
const views = data.views;
let selected = data.selected;
const number = value => value == null ? 'n/a' : (Number.isInteger(value) ? value.toLocaleString() : Number(value).toFixed(2));
const bytes = value => value == null ? 'n/a' : Number(value).toLocaleString() + ' B';
const label = snapshot => {
  const meta = snapshot.metadata || {};
  return meta.run_id || [meta.runner, meta.seed == null ? null : 'seed ' + meta.seed, meta.run_index == null ? null : 'run ' + meta.run_index].filter(Boolean).join(' / ') || snapshot.output_dir;
};
function card(id, value) { document.getElementById(id).textContent = value; }
function drawNodeChart(snapshot) {
  const field = document.getElementById('node-field').value;
  const labels = snapshot.node_stats.map(node => 'node ' + node.node_id);
  const values = snapshot.node_stats.map(node => node[field] || 0);
  Plotly.react('nodes', [{type: 'bar', x: labels, y: values, marker: {color: '#3d77b3'}}], {
    title: field.replaceAll('_', ' '), margin: {t: 42, l: 55, r: 15, b: 80}, yaxis: {rangemode: 'tozero'}, paper_bgcolor: '#fffdf8', plot_bgcolor: '#fffdf8'
  }, {responsive: true, displaylogo: false});
}
function draw(snapshot) {
  const metrics = snapshot.metrics;
  card('run-name', label(snapshot));
  card('bytes', bytes(metrics.total_bytes));
  card('validators', number(metrics.unique_validators) + (metrics.signing_hosts ? ' on ' + number(metrics.signing_hosts) + ' hosts' : ''));
  card('duplicates', number(metrics.duplicate_signature_events) + ' / ' + number(metrics.duplicate_to_unique_ratio));
  card('arrival', number(metrics.signature_arrival_ms.p90) + ' ms');
  card('node-threshold', metrics.node_threshold_ms ? number(metrics.node_threshold_ms.p95) + ' ms' : '-');
  const cdf = snapshot.cdf || [];
  Plotly.react('cdf', [{mode: 'lines+markers', x: cdf.map(point => point.time_ms), y: cdf.map(point => point.percent), line: {color: '#e07a4f'}, marker: {size: 5}}], {
    title: 'Unique validator signature arrival', xaxis: {title: 'time (ms)'}, yaxis: {title: 'validators reached (%)', range: [0, 100]}, margin: {t: 42, l: 65, r: 15, b: 55}, paper_bgcolor: '#fffdf8', plot_bgcolor: '#fffdf8'
  }, {responsive: true, displaylogo: false});
  const local = metrics.local_proof_latency_ms_by_subnet || {};
  const ids = Object.keys(local);
  Plotly.react('local', [{type: 'bar', x: ids.map(id => 'subnet ' + id), y: ids.map(id => local[id].median), error_y: {type: 'data', array: ids.map(id => local[id].max - local[id].median), arrayminus: ids.map(id => local[id].median - local[id].min), visible: true}, marker: {color: '#537d63'}}], {
    title: 'Local proof latency (median, min/max)', yaxis: {title: 'ms', rangemode: 'tozero'}, margin: {t: 42, l: 55, r: 15, b: 55}, paper_bgcolor: '#fffdf8', plot_bgcolor: '#fffdf8'
  }, {responsive: true, displaylogo: false});
  drawNodeChart(snapshot);
}
function renderTable() {
  const body = document.getElementById('history-body');
  body.replaceChildren();
  views.forEach((snapshot, index) => {
    const row = document.createElement('tr');
    if (index === selected) row.className = 'selected';
    [label(snapshot), snapshot.metadata.seed, snapshot.metadata.run_index, snapshot.metrics.unique_validators, snapshot.metrics.signature_arrival_ms.p90, snapshot.metrics.total_bytes].forEach(value => {
      const cell = document.createElement('td'); cell.textContent = value == null ? 'n/a' : (typeof value === 'number' ? number(value) : value); row.appendChild(cell);
    });
    row.addEventListener('click', () => { selected = index; renderTable(); draw(views[index]); });
    body.appendChild(row);
  });
}
document.getElementById('node-field').addEventListener('change', () => drawNodeChart(views[selected]));
renderTable(); draw(views[selected]);
"""


def generate_html(primary_snapshot, history, output):
    """Create a self-contained report, importing Plotly only when needed."""
    try:
        from plotly.offline import get_plotlyjs
    except ImportError as error:
        raise RuntimeError("Plotly is required to generate summary.html; run with the analyze dependency group") from error
    views = list(history)
    primary_key = snapshot_identity(primary_snapshot)
    if not any(snapshot_identity(snapshot) == primary_key for snapshot in views):
        views.append(primary_snapshot)
    selected = max((index for index, snapshot in enumerate(views) if snapshot_identity(snapshot) == primary_key), default=0)
    report_data = json_data({"views": views, "selected": selected})
    plotly_js = get_plotlyjs().replace("</script", "<\\/script")
    title = html.escape("leanSim analysis: " + Path(primary_snapshot["output_dir"]).name)
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>""" + title + """</title><style>
:root { color: #222; background: #f3efe6; font-family: Georgia, 'Times New Roman', serif; }
body { max-width: 1400px; margin: 0 auto; padding: 28px; } h1 { margin: 0 0 5px; } .sub { color: #665f52; margin: 0 0 24px; }
.cards { display: grid; grid-template-columns: repeat(5, minmax(130px, 1fr)); gap: 12px; margin-bottom: 22px; } .card, .panel { background: #fffdf8; border: 1px solid #d8d0c1; border-radius: 8px; box-shadow: 0 2px 6px #332b1b12; }
.card { padding: 13px; } .card b { display: block; font-size: 1.35rem; margin-top: 5px; } .label { color: #665f52; font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; } .panel { padding: 8px; min-width: 0; } .wide { grid-column: 1 / -1; } #cdf, #local, #nodes { width: 100%; height: 350px; }
table { width: 100%; border-collapse: collapse; font-family: ui-sans-serif, system-ui, sans-serif; font-size: .86rem; } th, td { padding: 9px; text-align: left; border-bottom: 1px solid #e6dfd1; } th { color: #665f52; } tbody tr { cursor: pointer; } tbody tr:hover, tbody tr.selected { background: #f1e5c6; }
select { margin: 10px 10px 0; padding: 5px; } @media (max-width: 780px) { body { padding: 14px; } .cards, .grid { grid-template-columns: 1fr; } .wide { grid-column: auto; } .table-wrap { overflow-x: auto; } }
</style></head><body><h1>leanSim run analysis</h1><p class="sub" id="run-name"></p>
<section class="cards"><div class="card"><span class="label">Event bytes</span><b id="bytes"></b></div><div class="card"><span class="label">Unique validators</span><b id="validators"></b></div><div class="card"><span class="label">Duplicates / ratio</span><b id="duplicates"></b></div><div class="card"><span class="label">90% arrival</span><b id="arrival"></b></div><div class="card"><span class="label">p95 node at threshold</span><b id="node-threshold"></b></div><div class="card"><span class="label">History snapshots</span><b>""" + str(len(views)) + """</b></div></section>
<section class="grid"><div class="panel"><div id="cdf"></div></div><div class="panel"><div id="local"></div></div><div class="panel wide"><label for="node-field">Per-node measure</label><select id="node-field"><option value="bytes_total">total bytes</option><option value="bytes_sent">bytes sent</option><option value="bytes_received">bytes received</option><option value="msgs_total">total messages</option><option value="msgs_sent">messages sent</option><option value="msgs_received">messages received</option></select><div id="nodes"></div></div>
<div class="panel wide table-wrap"><table><thead><tr><th>Run</th><th>Seed</th><th>Index</th><th>Validators</th><th>90% arrival</th><th>Event bytes</th></tr></thead><tbody id="history-body"></tbody></table></div></section>
<script id="snapshot-data" type="application/json">""" + report_data + """</script><script>""" + plotly_js + """</script><script>""" + INTERACTIVE_JS + """</script></body></html>"""
    output.write_text(document, encoding="utf-8")


def serve_directory(directory, port):
    handler = partial(SimpleHTTPRequestHandler, directory=str(directory))
    server = ThreadingHTTPServer(("0.0.0.0", port), handler)
    server.daemon_threads = True
    print("Serving http://0.0.0.0:%d/summary.html (Ctrl-C to stop)" % port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")
    finally:
        server.server_close()


def self_test():
    """Exercise parsing and the primary/overlay history rules without Shadow."""
    with tempfile.TemporaryDirectory(prefix="leansim-analyze-") as temporary:
        root = Path(temporary)

        def fixture(name, seed, run_index):
            directory = root / name
            stdout = directory / "shadow.data" / "hosts" / "host-1" / "stdout"
            stdout.parent.mkdir(parents=True)
            stdout.write_text("\n".join((
                "not JSON",
                '{"event":"NodePeerId","node_id":0,"peer_id":"peer-0"}',
                '{"event":"SigSent","node_id":0,"subnet_id":0,"seq":0,"ts_ms":100,"byte_size":10}',
                '{"event":"SigSent","node_id":1,"subnet_id":0,"seq":0,"ts_ms":110,"byte_size":10}',
                '{"event":"SigReceived","node_id":10,"from_id":0,"subnet_id":0,"duplicate":false,"ts_ms":130,"byte_size":20}',
                '{"event":"SigReceived","node_id":10,"from_id":1,"subnet_id":0,"duplicate":false,"ts_ms":150,"byte_size":20}',
                '{"event":"SigReceived","node_id":10,"from_id":0,"subnet_id":0,"duplicate":true,"ts_ms":155,"byte_size":20}',
                '{"event":"LocalProofGenerated","node_id":10,"subnet_id":0,"sig_count":2,"latency_ms":170}',
                '{"event":"NodeStats","node_id":10,"bytes_sent":70,"bytes_received":60,"msgs_sent":2,"msgs_received":3}',
            )), encoding="utf-8")
            (directory / "run-meta.json").write_text(json.dumps({"runner": "test", "seed": seed, "run_index": run_index}), encoding="utf-8")
            (directory / "run-manifest.json").write_text(json.dumps({"experiment": {"local_threshold": 1.0}}), encoding="utf-8")
            return directory

        primary_dir = fixture("primary", 7, 0)
        overlay_dir = fixture("overlay", 8, 1)
        primary = build_snapshot(primary_dir)
        overlay = build_snapshot(overlay_dir)
        metrics = primary["metrics"]
        # 2 sends x 10 + 3 receives x 20; local proofs are not transmitted.
        assert metrics["total_bytes"] == 80
        assert metrics["unique_signature_events"] == 2
        assert metrics["duplicate_signature_events"] == 1
        assert metrics["unique_validators"] == 2
        assert metrics["stage_medians_ms"]["threshold_reached"] == 150
        assert metrics["stage_medians_ms"]["aggregation_compute"] == 20
        assert metrics["recursive_aggregation"] is None
        overlay_dir = root / "overlay-self-signature"
        stdout = overlay_dir / "shadow.data" / "hosts" / "host-1" / "stdout"
        stdout.parent.mkdir(parents=True)
        stdout.write_text("\n".join((
            '{"event":"SigSent","node_id":0,"subnet_id":0,"seq":0,"ts_ms":100,"byte_size":10}',
            '{"event":"SigSent","node_id":1,"subnet_id":0,"seq":0,"ts_ms":110,"byte_size":10}',
            '{"event":"SigReceived","node_id":0,"from_id":1,"subnet_id":0,"duplicate":false,"ts_ms":150,"byte_size":10}',
            '{"event":"LocalProofGenerated","node_id":0,"subnet_id":0,"sig_count":2,"latency_ms":170}',
        )), encoding="utf-8")
        (overlay_dir / "run-manifest.json").write_text(
            json.dumps({"experiment": {"local_threshold": 1.0}}), encoding="utf-8"
        )
        overlay_metrics = build_snapshot(overlay_dir)["metrics"]
        assert overlay_metrics["stage_medians_ms"]["threshold_reached"] == 150
        assert overlay_metrics["stage_medians_ms"]["aggregation_compute"] == 20
        colocated_dir = root / "colocated"
        stdout = colocated_dir / "shadow.data" / "hosts" / "host-1" / "stdout"
        stdout.parent.mkdir(parents=True)
        # Host 0 runs validators 0 and 1 and aggregates; host 1 runs validator 2.
        stdout.write_text("\n".join((
            '{"event":"SigSent","node_id":0,"validator_id":0,"subnet_id":0,"seq":0,"ts_ms":100,"byte_size":10}',
            '{"event":"SigSent","node_id":0,"validator_id":1,"subnet_id":0,"seq":1,"ts_ms":101,"byte_size":10}',
            '{"event":"SigSent","node_id":1,"validator_id":2,"subnet_id":0,"seq":0,"ts_ms":110,"byte_size":10}',
            '{"event":"SigReceived","node_id":1,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":140,"byte_size":10}',
            '{"event":"SigReceived","node_id":1,"from_id":0,"validator_id":1,"subnet_id":0,"duplicate":false,"ts_ms":141,"byte_size":10}',
            '{"event":"SigReceived","node_id":0,"from_id":1,"validator_id":2,"subnet_id":0,"duplicate":false,"ts_ms":150,"byte_size":10}',
            '{"event":"LocalProofGenerated","node_id":0,"subnet_id":0,"sig_count":3,"latency_ms":170}',
        )), encoding="utf-8")
        (colocated_dir / "run-manifest.json").write_text(
            json.dumps({"experiment": {"local_threshold": 1.0}}), encoding="utf-8"
        )
        colocated_metrics = build_snapshot(colocated_dir)["metrics"]
        assert colocated_metrics["unique_validators"] == 3
        assert colocated_metrics["signing_hosts"] == 2
        assert colocated_metrics["stage_medians_ms"]["threshold_reached"] == 150
        # Host 0 holds 0 and 1 at once and gets 2 at 150; host 1 gets 0 and 1 by 141.
        node_threshold = colocated_metrics["node_threshold_ms"]
        assert node_threshold["nodes"] == 2 and node_threshold["reached"] == 2
        assert node_threshold["p50"] == 41 and node_threshold["max"] == 50
        recursive_dir = root / "recursive"
        stdout = recursive_dir / "shadow.data" / "hosts" / "host-1" / "stdout"
        stdout.parent.mkdir(parents=True)
        # Subnets 0 and 1 feed one root group with members 3 and 4.
        stdout.write_text("\n".join((
            '{"event":"LocalProofGenerated","node_id":1,"subnet_id":0,"sig_count":2,"latency_ms":170}',
            '{"event":"LocalProofGenerated","node_id":2,"subnet_id":1,"sig_count":2,"latency_ms":190}',
            '{"event":"ProofAnnounced","node_id":1,"to_id":3,"layer":0,"index":0,"ts_ms":170}',
            '{"event":"ProofAnnounced","node_id":2,"to_id":3,"layer":0,"index":1,"ts_ms":190}',
            '{"event":"ProofRequested","node_id":3,"from_id":1,"layer":0,"index":0,"ts_ms":171}',
            '{"event":"ProofServed","node_id":1,"to_id":3,"layer":0,"index":0,"ts_ms":172,"byte_size":100}',
            '{"event":"ProofFetched","node_id":3,"from_id":1,"layer":0,"index":0,"duplicate":false,"ts_ms":200,"byte_size":100}',
            '{"event":"ProofFetched","node_id":3,"from_id":2,"layer":0,"index":1,"duplicate":false,"ts_ms":220,"byte_size":100}',
            '{"event":"ProofFetched","node_id":3,"from_id":4,"layer":0,"index":1,"duplicate":true,"ts_ms":230,"byte_size":100}',
            '{"event":"ProofFetchFailed","node_id":4,"from_id":2,"layer":0,"index":1,"ts_ms":240}',
            '{"event":"RecursiveProofGenerated","node_id":3,"layer":1,"index":0,"inputs":2,"is_final":true,"ts_ms":500}',
            '{"event":"RecursiveProofGenerated","node_id":4,"layer":1,"index":0,"inputs":2,"is_final":true,"ts_ms":520}',
        )), encoding="utf-8")
        (recursive_dir / "run-manifest.json").write_text(json.dumps({"experiment": {"local_threshold": 1.0}}), encoding="utf-8")
        (recursive_dir / "aggregation-plan.json").write_text(
            json.dumps({"arity": 2, "groups": [{"layer": 1, "index": 0, "children": [0, 1], "members": [3, 4]}]}),
            encoding="utf-8",
        )
        recursive_metrics = build_snapshot(recursive_dir)["metrics"]
        recursive = recursive_metrics["recursive_aggregation"]
        assert recursive_metrics["total_bytes"] == 400
        assert recursive["final_proof_ms"] == 500
        assert recursive["groups_planned"] == 1 and recursive["groups_done"] == 1
        assert recursive["groups"] == [{"layer": 1, "index": 0, "first": 500, "median": 510, "members_done": 2}]
        assert recursive["layers"] == {"1": {"groups_planned": 1, "groups_done": 1, "first": 500, "median": 500, "last": 500}}
        assert recursive["subnet_proofs_ms"] == {"first": 170, "median": 180, "last": 190}
        assert recursive["traffic"] == {
            "announcements": 2, "pulls": 1, "proofs_fetched": 3, "extra_proofs_fetched": 1,
            "failed_pulls": 1, "fetched_bytes": 300, "served_bytes": 100,
        }
        history = merge_history([], [primary, overlay], append=False)
        assert len(history) == 2
        assert len(merge_history(history, [primary, overlay], append=False)) == 2
        assert len(merge_history(history, [primary, overlay], append=True)) == 3
        history_path = primary_dir / "runs-history.json"
        history_path.write_text("malformed", encoding="utf-8")
        assert load_history(history_path) == []
        if shutil.which("node"):
            js_path = root / "report.js"
            js_path.write_text(INTERACTIVE_JS, encoding="utf-8")
            import subprocess
            result = subprocess.run(["node", "--check", str(js_path)], capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dirs", nargs="*", help="output directories (the first is the primary report directory)")
    parser.add_argument("--serve", action="store_true", help="serve the primary output directory after generating the report")
    parser.add_argument("--append", action="store_true", help="append the primary snapshot even if it is already in history")
    parser.add_argument("--port", type=int, default=4321, help="HTTP port for --serve (default: 4321)")
    parser.add_argument("--self-test", action="store_true", help="run fixture-based parser and history tests")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.dirs:
        parser.error("at least one output directory is required unless --self-test is used")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    directories = [Path(directory).expanduser() for directory in args.dirs]
    primary_dir = directories[0]
    primary_dir.mkdir(parents=True, exist_ok=True)
    snapshots = [build_snapshot(directory) for directory in directories]
    history_path = primary_dir / "runs-history.json"
    history = merge_history(load_history(history_path), snapshots, args.append)
    history_path.write_text(json.dumps({"schema_version": 1, "snapshots": history}, indent=2) + "\n", encoding="utf-8")
    summary_path = primary_dir / "summary.html"
    generate_html(snapshots[0], history, summary_path)
    print("Analyzed %d director%s: %s" % (len(snapshots), "y" if len(snapshots) == 1 else "ies", summary_path))
    print("History snapshots: %d; primary events: %d" % (len(history), snapshots[0]["metrics"]["parsed_events"]))
    if args.serve:
        serve_directory(primary_dir, args.port)


if __name__ == "__main__":
    main()
