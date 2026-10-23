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
    "TrafficBucket",
    "TrafficPeer",
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


# Peers kept per host in the snapshot; the dashboard's peer chart shows the top 15.
MAX_TRAFFIC_PEERS = 50


def traffic_summary(traffic_buckets, traffic_peers, peer_ids):
    """Per-host traffic for hosts that logged it: bucket totals by kind, run
    totals, and the busiest peers (`node:<id>` keys resolved through NodePeerId
    events, `peer:<base58>` keys kept as-is when the node is unknown)."""
    summary = {}
    for node_id, buckets_at in traffic_buckets.items():
        starts = sorted(buckets_at)
        buckets = [buckets_at[start] for start in starts]
        peers = []
        for key, totals in traffic_peers.get(node_id, {}).items():
            if key.startswith("peer:"):
                peer_node = peer_ids.get(key[5:])
            elif key.startswith("node:") and key[5:].isdigit():
                peer_node = int(key[5:])
            else:
                peer_node = None
            peers.append(
                {
                    "peer": f"node {peer_node}" if peer_node is not None else key,
                    "node_id": peer_node,
                    **totals,
                }
            )
        peers.sort(key=lambda peer: (-(peer["inbound"] + peer["outbound"]), str(peer["peer"])))
        summary[str(node_id)] = {
            "bucket_ms": buckets[-1].pop("width_ms"),
            "sent": sum(sum(bucket["outbound"].values()) for bucket in buckets),
            "received": sum(sum(bucket["inbound"].values()) for bucket in buckets),
            "buckets": buckets,
            "peers": peers[:MAX_TRAFFIC_PEERS],
        }
    return summary


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
    traffic_buckets = defaultdict(dict)
    traffic_peers = defaultdict(dict)
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
            elif name == "TrafficBucket":
                node_id = integer(event.get("node_id"))
                start_ms = integer(event.get("start_ms"))
                width_ms = integer(event.get("width_ms"))
                if node_id is None or start_ms is None or width_ms is None:
                    continue
                traffic_buckets[node_id][start_ms] = {
                    "start_ms": start_ms,
                    "width_ms": width_ms,
                    "inbound": {str(kind): integer(bytes) or 0 for kind, bytes in event.get("inbound", {}).items()},
                    "outbound": {str(kind): integer(bytes) or 0 for kind, bytes in event.get("outbound", {}).items()},
                }
            elif name == "TrafficPeer":
                node_id = integer(event.get("node_id"))
                peer = event.get("peer")
                if node_id is None or not isinstance(peer, str) or not peer:
                    continue
                traffic_peers[node_id][peer] = {
                    "inbound": integer(event.get("inbound_bytes")) or 0,
                    "outbound": integer(event.get("outbound_bytes")) or 0,
                    "inbound_msgs": integer(event.get("inbound_msgs")) or 0,
                    "outbound_msgs": integer(event.get("outbound_msgs")) or 0,
                }
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
            "traffic": traffic_summary(traffic_buckets, traffic_peers, peer_ids),
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
function drawTree(metrics) {
  const recursive = metrics.recursive_aggregation;
  const groups = (recursive && recursive.groups) || [];
  const local = metrics.local_proof_latency_ms_by_subnet || {};
  const subnets = Object.keys(local);
  Plotly.react('tree', [
    {mode: 'markers', name: 'subnet proofs (first)', x: subnets.map(id => local[id].min), y: subnets.map(() => 0), text: subnets.map(id => 'subnet ' + id), marker: {color: '#537d63', size: 7}},
    {mode: 'markers', name: 'group proofs (first)', x: groups.map(group => group.first), y: groups.map(group => group.layer), text: groups.map(group => 'group ' + group.layer + '/' + group.index + ', ' + group.members_done + ' members proved'), marker: {color: '#e07a4f', size: 8}},
  ], {
    title: 'Aggregation tree: first proof per subnet and group', xaxis: {title: 'time (ms)'}, yaxis: {title: 'layer', dtick: 1, rangemode: 'tozero'}, margin: {t: 42, l: 55, r: 15, b: 55}, paper_bgcolor: '#fffdf8', plot_bgcolor: '#fffdf8'
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
  const recursive = metrics.recursive_aggregation;
  card('final-proof', recursive && recursive.final_proof_ms != null ? number(recursive.final_proof_ms) + ' ms' : '-');
  drawTree(metrics);
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


TRAFFIC_JS = """
const data = JSON.parse(document.getElementById('traffic-data').textContent);
const traffic = data.traffic;
const colors = {signature: '#5aa9e6', duplicate_signature: '#2f6f9e', proof_payload: '#e07a4f', proof_announce: '#d9b26a', proof_request: '#8f7bd8', proof_control: '#6b7280'};
const mb = (bytes) => bytes / 1e6;
const kinds = [...new Set(traffic.buckets.flatMap(bucket => [...Object.keys(bucket.inbound), ...Object.keys(bucket.outbound)]))].sort();
const x = traffic.buckets.map(bucket => bucket.start_ms / 1000);
const traces = [];
for (const kind of kinds) {
  traces.push({name: kind.replaceAll('_', ' ') + ' · sent', type: 'bar', x, y: traffic.buckets.map(bucket => mb(bucket.outbound[kind] || 0)), marker: {color: colors[kind] || '#7f8c9b'}, legendgroup: kind, hovertemplate: '%{y:.2f} MB sent at %{x:.1f} s<extra>' + kind + '</extra>'});
}
for (const kind of kinds) {
  traces.push({name: kind.replaceAll('_', ' ') + ' · received', type: 'bar', x, y: traffic.buckets.map(bucket => -mb(bucket.inbound[kind] || 0)), marker: {color: colors[kind] || '#7f8c9b'}, legendgroup: kind, showlegend: false, hovertemplate: '%{y:.2f} MB received at %{x:.1f} s<extra>' + kind + '</extra>'});
}
const dark = {paper_bgcolor: '#14161a', plot_bgcolor: '#14161a', font: {color: '#d7dae0'}};
Plotly.newPlot('timeline', traces, Object.assign({}, dark, {
  barmode: 'relative', bargap: 0.05,
  xaxis: {title: 'time (s)', gridcolor: '#262b33', zeroline: false},
  yaxis: {title: 'MB · sent above, received below', gridcolor: '#262b33', zerolinecolor: '#5b6472'},
  margin: {t: 30, l: 70, r: 20, b: 110}, legend: {orientation: 'h', y: -0.25, font: {size: 10}}
}), {responsive: true, displaylogo: false});
const peers = traffic.peers.slice(0, 15).reverse();
Plotly.newPlot('peers', [
  {name: 'sent', type: 'bar', orientation: 'h', y: peers.map(peer => peer.peer), x: peers.map(peer => mb(peer.outbound)), marker: {color: '#e07a4f'}, hovertemplate: '%{x:.2f} MB sent<extra>%{y}</extra>'},
  {name: 'received', type: 'bar', orientation: 'h', y: peers.map(peer => peer.peer), x: peers.map(peer => -mb(peer.inbound)), marker: {color: '#5aa9e6'}, hovertemplate: '%{x:.2f} MB received<extra>%{y}</extra>'},
], Object.assign({}, dark, {
  barmode: 'relative', title: 'busiest peers',
  xaxis: {title: 'MB · sent right, received left', gridcolor: '#262b33', zerolinecolor: '#5b6472'},
  yaxis: {automargin: true}, margin: {t: 40, l: 90, r: 20, b: 50}, legend: {orientation: 'h', y: -0.15}
}), {responsive: true, displaylogo: false});
document.getElementById('node').textContent = data.node;
document.getElementById('run').textContent = data.run + ' · ' + traffic.bucket_ms + ' ms buckets · ' + traffic.buckets.length + ' buckets with traffic';
document.getElementById('received').textContent = mb(traffic.received).toFixed(2) + ' MB';
document.getElementById('sent').textContent = mb(traffic.sent).toFixed(2) + ' MB';
document.getElementById('buckets').textContent = number(traffic.buckets.length);
const peak = traffic.buckets.reduce((best, bucket) => Math.max(best, mb(Object.values(bucket.inbound).reduce((a, b) => a + b, 0) + Object.values(bucket.outbound).reduce((a, b) => a + b, 0))), 0);
document.getElementById('peak').textContent = peak.toFixed(2) + ' MB';
document.getElementById('peers-count').textContent = number(traffic.peers.length);
"""

TRAFFIC_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>leanSim traffic: node {node_id}</title><style>
:root {{ color-scheme: dark; }}
body {{ background: #14161a; color: #d7dae0; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 0 auto; padding: 28px; max-width: 1500px; }}
h1 {{ font-size: 1.3rem; margin: 0 0 4px; font-weight: 600; }} h1 span {{ color: #e07a4f; }}
.sub {{ color: #8b93a1; margin: 0 0 22px; font-size: .88rem; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 18px; }}
.card, .panel {{ background: #1b1f26; border: 1px solid #262b33; border-radius: 10px; }}
.card {{ padding: 14px; }} .card b {{ display: block; font-size: 1.3rem; margin-top: 6px; font-variant-numeric: tabular-nums; }}
.label {{ color: #8b93a1; font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; }}
.grid {{ display: grid; gap: 16px; }} .panel {{ padding: 10px; min-width: 0; }}
#timeline {{ width: 100%; height: 430px; }} #peers {{ width: 100%; height: 430px; }}
@media (min-width: 1100px) {{ .two {{ grid-template-columns: 3fr 2fr; }} }}
</style></head><body>
<h1>Traffic: node <span id="node"></span></h1><p class="sub" id="run"></p>
<section class="cards">
<div class="card"><span class="label">Received</span><b id="received"></b></div>
<div class="card"><span class="label">Sent</span><b id="sent"></b></div>
<div class="card"><span class="label">Buckets with traffic</span><b id="buckets"></b></div>
<div class="card"><span class="label">Peak bucket</span><b id="peak"></b></div>
<div class="card"><span class="label">Peers seen</span><b id="peers-count"></b></div>
</section>
<section class="grid two"><div class="panel"><div id="timeline"></div></div><div class="panel"><div id="peers"></div></div></section>
<script id="traffic-data" type="application/json">{data}</script>
<script>{plotly}</script>
<script>{script}</script>
</body></html>
"""


def generate_traffic_html(snapshot, directory, plotly_js):
    """One dark dashboard per host that kept traffic logs."""
    traffic = snapshot.get("metrics", {}).get("traffic") or {}
    run = Path(snapshot.get("output_dir", "")).name
    for node_id, logged in traffic.items():
        data = json_data({"node": node_id, "run": run, "traffic": logged})
        document = TRAFFIC_TEMPLATE.format(
            node_id=html.escape(str(node_id)),
            data=data,
            plotly=plotly_js,
            script=TRAFFIC_JS,
        )
        (directory / f"traffic-{node_id}.html").write_text(document, encoding="utf-8")


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
    logged_hosts = ",".join(sorted((primary_snapshot.get("metrics", {}).get("traffic") or {}), key=int))
    traffic_links = (
        '<p class="traffic-links">Traffic logs per host: '
        + " ".join(
            f'<a href="traffic-{node_id}.html">node {html.escape(node_id)}</a>'
            for node_id in logged_hosts.split(",") if node_id
        )
        + "</p>"
        if logged_hosts
        else ""
    )
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>""" + title + """</title><style>
:root { color: #222; background: #f3efe6; font-family: Georgia, 'Times New Roman', serif; }
body { max-width: 1400px; margin: 0 auto; padding: 28px; } h1 { margin: 0 0 5px; } .sub { color: #665f52; margin: 0 0 24px; }
.cards { display: grid; grid-template-columns: repeat(5, minmax(130px, 1fr)); gap: 12px; margin-bottom: 22px; } .card, .panel { background: #fffdf8; border: 1px solid #d8d0c1; border-radius: 8px; box-shadow: 0 2px 6px #332b1b12; }
.card { padding: 13px; } .card b { display: block; font-size: 1.35rem; margin-top: 5px; } .label { color: #665f52; font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; } .panel { padding: 8px; min-width: 0; } .wide { grid-column: 1 / -1; } #cdf, #local, #nodes, #tree { width: 100%; height: 350px; }
table { width: 100%; border-collapse: collapse; font-family: ui-sans-serif, system-ui, sans-serif; font-size: .86rem; } th, td { padding: 9px; text-align: left; border-bottom: 1px solid #e6dfd1; } th { color: #665f52; } tbody tr { cursor: pointer; } tbody tr:hover, tbody tr.selected { background: #f1e5c6; }
select { margin: 10px 10px 0; padding: 5px; } @media (max-width: 780px) { body { padding: 14px; } .cards, .grid { grid-template-columns: 1fr; } .wide { grid-column: auto; } .table-wrap { overflow-x: auto; } }
</style></head><body><h1>leanSim run analysis</h1><p class="sub" id="run-name"></p>
<section class="cards"><div class="card"><span class="label">Event bytes</span><b id="bytes"></b></div><div class="card"><span class="label">Unique validators</span><b id="validators"></b></div><div class="card"><span class="label">Duplicates / ratio</span><b id="duplicates"></b></div><div class="card"><span class="label">90% arrival</span><b id="arrival"></b></div><div class="card"><span class="label">p95 node at threshold</span><b id="node-threshold"></b></div><div class="card"><span class="label">Final proof</span><b id="final-proof"></b></div><div class="card"><span class="label">History snapshots</span><b>""" + str(len(views)) + """</b></div></section>
<section class="grid"><div class="panel"><div id="cdf"></div></div><div class="panel"><div id="local"></div></div><div class="panel wide"><div id="tree"></div></div><div class="panel wide"><label for="node-field">Per-node measure</label><select id="node-field"><option value="bytes_total">total bytes</option><option value="bytes_sent">bytes sent</option><option value="bytes_received">bytes received</option><option value="msgs_total">total messages</option><option value="msgs_sent">messages sent</option><option value="msgs_received">messages received</option></select><div id="nodes"></div></div>
<div class="panel wide table-wrap"><table><thead><tr><th>Run</th><th>Seed</th><th>Index</th><th>Validators</th><th>90% arrival</th><th>Event bytes</th></tr></thead><tbody id="history-body"></tbody></table></div></section>""" + traffic_links + """
<script id="snapshot-data" type="application/json">""" + report_data + """</script><script>""" + plotly_js + """</script><script>""" + INTERACTIVE_JS + """</script></body></html>"""
    output.write_text(document, encoding="utf-8")
    generate_traffic_html(primary_snapshot, output.parent, plotly_js)


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
        traffic_dir = root / "traffic"
        stdout = traffic_dir / "shadow.data" / "hosts" / "host-1" / "stdout"
        stdout.parent.mkdir(parents=True)
        # Host 7 logs two buckets; peer 9 is known by its PeerId, peer 5 by node id.
        stdout.write_text("\n".join((
            '{"event":"NodePeerId","node_id":9,"peer_id":"peer-9"}',
            '{"event":"TrafficBucket","node_id":7,"start_ms":4300,"width_ms":100,"inbound":{"signature":1200,"proof_payload":262144},"outbound":{"signature":2400}}',
            '{"event":"TrafficBucket","node_id":7,"start_ms":4400,"width_ms":100,"inbound":{},"outbound":{"proof_announce":128}}',
            '{"event":"TrafficPeer","node_id":7,"peer":"peer:peer-9","inbound_bytes":1200,"outbound_bytes":2400,"inbound_msgs":1,"outbound_msgs":2}',
            '{"event":"TrafficPeer","node_id":7,"peer":"node:5","inbound_bytes":262144,"outbound_bytes":0,"inbound_msgs":1,"outbound_msgs":0}',
        )), encoding="utf-8")
        (traffic_dir / "run-manifest.json").write_text(json.dumps({"experiment": {"local_threshold": 1.0}}), encoding="utf-8")
        traffic_snapshot = build_snapshot(traffic_dir)
        traffic = traffic_snapshot["metrics"]["traffic"]
        assert traffic_snapshot["metrics"]["total_bytes"] == 0, "traffic events must not count as signature traffic"
        assert set(traffic) == {"7"}
        logged = traffic["7"]
        assert logged["bucket_ms"] == 100
        assert logged["received"] == 263344 and logged["sent"] == 2528
        assert [bucket["start_ms"] for bucket in logged["buckets"]] == [4300, 4400]
        assert logged["peers"] == [
            {"peer": "node 5", "node_id": 5, "inbound": 262144, "outbound": 0, "inbound_msgs": 1, "outbound_msgs": 0},
            {"peer": "node 9", "node_id": 9, "inbound": 1200, "outbound": 2400, "inbound_msgs": 1, "outbound_msgs": 2},
        ]
        assert primary["metrics"]["traffic"] == {}
        report = root / "traffic-report" / "summary.html"
        report.parent.mkdir()
        generate_html(traffic_snapshot, [], report)
        dashboard = (report.parent / "traffic-7.html").read_text(encoding="utf-8")
        assert "node 7" in dashboard and "traffic-data" in dashboard
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
            traffic_js_path = root / "traffic.js"
            traffic_js_path.write_text(TRAFFIC_JS, encoding="utf-8")
            result = subprocess.run(["node", "--check", str(traffic_js_path)], capture_output=True, text=True)
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
