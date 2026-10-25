#!/usr/bin/env python3
"""Build an offline, interactive summary of one or more leanSim Shadow runs."""

import argparse
import html
import json
import math
import shutil
import tempfile
from collections import Counter, defaultdict
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


# Points kept per CDF line: smooth at any screen width, small in runs-history.json.
MAX_CDF_POINTS = 400
# Whisker, box and median percentiles of the arrival-time chart.
BOX_PERCENTILES = (5, 25, 50, 75, 95)
# Host classes in display order; "unknown" covers manifests without a supernode flag.
NODE_CLASSES = ("supernode", "regular", "unknown")


def frequency_percentiles(counts, percents=BOX_PERCENTILES):
    """Nearest-rank percentiles of a {value: occurrences} histogram, plus its sample count."""
    total = sum(counts.values())
    if not total:
        return None
    values = sorted(counts)
    result = {"count": total}
    for percent in percents:
        rank = max(1, math.ceil(total * percent / 100))
        seen = 0
        for value in values:
            seen += counts[value]
            if seen >= rank:
                result["p" + str(percent)] = value
                break
    return result


def frequency_cdf(counts, limit=MAX_CDF_POINTS):
    """[[value, percent of samples at or below it], ...], thinned to at most
    `limit` evenly spaced points; the first and last points are always kept."""
    total = sum(counts.values())
    if not total:
        return []
    points = []
    seen = 0
    for value in sorted(counts):
        seen += counts[value]
        points.append([value, round(seen * 100 / total, 4)])
    if len(points) > limit:
        step = (len(points) - 1) / (limit - 1)
        points = [points[round(index * step)] for index in range(limit)]
    return points


def manifest_hosts(manifest):
    """Manifest node records by node id; empty when the manifest has no node list."""
    nodes = manifest.get("nodes")
    if not isinstance(nodes, list):
        return {}
    return {node["node_id"]: node for node in nodes if isinstance(node, dict) and isinstance(node.get("node_id"), int)}


def node_class(host):
    """'supernode' or 'regular' from the manifest flag; 'unknown' without one."""
    if not host or not isinstance(host.get("supernode"), bool):
        return "unknown"
    return "supernode" if host["supernode"] else "regular"


def proof_label(layer, final_layer):
    if layer == 0:
        return "Subnet proofs"
    if layer == final_layer:
        return "Final proof"
    return f"Layer {layer} proofs"


def arrival_rows(signature_counts, proof_held, final_layer, t0, hosts):
    """Box-plot rows: per message and host class, the spread of the times
    (ms after t0) at which hosts first held it. Signatures count once per
    (receiving host, validator); proofs once per (host, proof), whether the
    host built the proof or fetched it."""
    rows = []

    def add(message, counts_by_class):
        for kind in NODE_CLASSES:
            stats = frequency_percentiles(counts_by_class.get(kind, {}))
            if stats:
                rows.append({"message": message, "class": kind, **stats})

    add("Signatures", signature_counts)
    for layer in sorted(proof_held):
        counts = defaultdict(Counter)
        for held in proof_held[layer].values():
            for node_id, time_ms in held.items():
                counts[node_class(hosts.get(node_id))][time_ms - t0] += 1
        add(proof_label(layer, final_layer), counts)
    return rows


def host_card(host):
    """What a traffic preview shows about its host."""
    if not host:
        return None
    return {
        "country": host.get("country"),
        "class": node_class(host),
        "uplink_mbps": host.get("uplink_mbps"),
        "downlink_mbps": host.get("downlink_mbps"),
        "validators": len(host.get("validator_ids") or []),
        "role": host.get("role"),
    }


def host_population(hosts, experiment):
    """Host and validator counts by bandwidth class, validators-per-host bins
    (0, 1, 2-3, 4-7, ...) and countries, from the manifest; None without nodes."""
    if not hosts:
        return None
    classes = defaultdict(lambda: {"hosts": 0, "validators": 0})
    countries = defaultdict(lambda: {"supernode": 0, "regular": 0, "unknown": 0, "validators": 0})
    bins = defaultdict(lambda: {"supernode": 0, "regular": 0, "unknown": 0, "validators": 0})
    for host in hosts.values():
        kind = node_class(host)
        count = len(host.get("validator_ids") or [])
        totals = classes[(kind, host.get("uplink_mbps"), host.get("downlink_mbps"))]
        totals["hosts"] += 1
        totals["validators"] += count
        country = countries[host.get("country") or "unknown"]
        country[kind] += 1
        country["validators"] += count
        low = 1 << (count.bit_length() - 1) if count else 0
        bins[low][kind] += 1
        bins[low]["validators"] += count
    top = max(bins)
    lows = [0] + [1 << power for power in range(top.bit_length())]
    return {
        "hosts": len(hosts),
        "validators": sum(len(host.get("validator_ids") or []) for host in hosts.values()),
        "supernode_by_validator_count": experiment.get("supernode_by_validator_count"),
        "supernode_fraction": experiment.get("supernode_fraction"),
        "classes": [
            {"class": kind, "uplink_mbps": up, "downlink_mbps": down, **totals}
            for (kind, up, down), totals in sorted(
                classes.items(), key=lambda item: (NODE_CLASSES.index(item[0][0]), -item[1]["hosts"], str(item[0][1:]))
            )
        ],
        "validators_per_host": [{"low": low, "high": low * 2 - 1 if low else 0, **bins[low]} for low in lows],
        "countries": sorted(
            ({"country": name, **totals} for name, totals in countries.items()),
            key=lambda row: (-(row["supernode"] + row["regular"] + row["unknown"]), row["country"]),
        ),
    }


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
        "mesh_warmup_ms": number(experiment.get("mesh_warmup_ms")),
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
            "bucket_ms": buckets[-1]["width_ms"],
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
    # layer -> proof index -> node id -> first time the host held that proof.
    proof_held = defaultdict(lambda: defaultdict(dict))
    final_layer = None

    def hold(layer, index, node_id, time_ms):
        if layer is None or index is None or node_id is None or time_ms is None:
            return
        held = proof_held[layer][index]
        if node_id not in held or time_ms < held[node_id]:
            held[node_id] = time_ms

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
                    hold(0, subnet_id, node_id, latency)
            elif name == "ProofAnnounced":
                proof_traffic["announcements"] += 1
            elif name == "ProofRequested":
                proof_traffic["pulls"] += 1
            elif name == "ProofFetched":
                hold(integer(event.get("layer")), integer(event.get("index")), integer(event.get("node_id")), number(event.get("ts_ms")))
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
                    hold(layer_id, group_index, integer(event.get("node_id")), timestamp)
                    if event.get("is_final") is True:
                        final_times.append(timestamp)
                        final_layer = layer_id
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

    manifest = read_json(output_dir / "run-manifest.json")
    hosts = manifest_hosts(manifest)
    # Every chart in summary.html measures time from the first signature sent.
    t0 = min(sent_times) if sent_times else 0
    signature_counts = defaultdict(Counter)
    for (node_id, _), seen in received_by_node_subnet.items():
        counter = signature_counts[node_class(hosts.get(node_id))]
        for time_ms in seen.values():
            counter[time_ms - t0] += 1
    signature_cdf = {"first_seen": frequency_cdf(Counter(time_ms - t0 for time_ms in arrival_times))}
    for kind in NODE_CLASSES:
        if signature_counts.get(kind):
            signature_cdf[kind] = frequency_cdf(signature_counts[kind])
    experiment = manifest.get("experiment") if isinstance(manifest.get("experiment"), dict) else {}
    traffic = traffic_summary(traffic_buckets, traffic_peers, peer_ids)
    for node_id, logged in traffic.items():
        logged["host"] = host_card(hosts.get(int(node_id)))

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
            "traffic": traffic,
            "t0_ms": t0,
            "signature_cdf": signature_cdf,
            "arrivals": arrival_rows(signature_counts, proof_held, final_layer, t0, hosts),
            "population": host_population(hosts, experiment),
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
const colors = {signature: '#53d8b1', duplicate_signature: '#328b91', proof_payload: '#ad9bff', proof_announce: '#e2bc7a', proof_request: '#8ca8d1', proof_control: '#778598'};
const names = {signature: 'Signatures', duplicate_signature: 'Duplicate signatures', proof_payload: 'Proof payloads', proof_announce: 'Announcements', proof_request: 'Pull requests', proof_control: 'Proof control'};
const mb = (bytes) => bytes / 1e6;
const kinds = [...new Set(traffic.buckets.flatMap(bucket => [...Object.keys(bucket.inbound), ...Object.keys(bucket.outbound)]))].sort();
const frames = [];
let previousEnd = null;
for (const bucket of traffic.buckets) {
  if (previousEnd !== null && bucket.start_ms > previousEnd) {
    frames.push({start_ms: previousEnd, inbound: {}, outbound: {}, width_ms: traffic.bucket_ms});
  }
  frames.push(bucket);
  previousEnd = bucket.start_ms + bucket.width_ms;
}
if (previousEnd !== null) frames.push({start_ms: previousEnd, inbound: {}, outbound: {}, width_ms: traffic.bucket_ms});
const x = frames.map(bucket => bucket.start_ms / 1000);
const rate = (bytes, bucket) => mb(bytes) * 1000 / bucket.width_ms;
const traces = [];
for (const [direction, field, sign] of [['sent', 'outbound', 1], ['received', 'inbound', -1]]) {
  for (const kind of kinds) {
    const values = frames.map(bucket => rate(bucket[field][kind] || 0, bucket));
    traces.push({name: names[kind] || kind, type: 'scatter', mode: 'lines', x,
      y: values.map(value => value === 0 ? 0 : sign * value), customdata: values,
      stackgroup: direction, line: {color: '#dbe8f155', width: 0.6, shape: 'spline', smoothing: 0.65},
      fillcolor: colors[kind] || '#778598', legendgroup: kind, showlegend: direction === 'sent',
      hovertemplate: '%{customdata:.2f} MB/s ' + direction + ' at %{x:.1f} s<extra>' + (names[kind] || kind) + '</extra>'});
  }
}
const peak = frames.reduce((best, bucket) => Math.max(best,
  rate(Object.values(bucket.inbound).reduce((a, b) => a + b, 0), bucket),
  rate(Object.values(bucket.outbound).reduce((a, b) => a + b, 0), bucket)), 0);
const extent = peak > 0 ? peak * 1.12 : 1;
const warmupSeconds = Number.isFinite(data.warmup_ms) && data.warmup_ms > 0 ? data.warmup_ms / 1000 : 0;
const milestones = (data.milestones || []).filter(point => Number.isFinite(point.time_ms));
const endSeconds = Math.max((previousEnd || 0) / 1000, warmupSeconds, ...milestones.map(point => point.time_ms / 1000), 1);
const shapes = warmupSeconds > 0 ? [{type: 'rect', xref: 'x', yref: 'paper', x0: 0, x1: warmupSeconds, y0: 0, y1: 1,
  fillcolor: '#96a6b9', opacity: 0.055, line: {width: 0}, layer: 'below'}] : [];
const annotations = warmupSeconds > 0 ? [{xref: 'x', yref: 'paper', x: warmupSeconds / 2, y: 0.88,
  text: 'Warmup<br>traffic not<br>captured', showarrow: false, font: {color: '#96a6b9', size: 10}, align: 'center'}] : [];
for (const [index, point] of milestones.entries()) {
  const at = point.time_ms / 1000;
  shapes.push({type: 'line', xref: 'x', yref: 'paper', x0: at, x1: at, y0: 0, y1: 1,
    line: {color: '#748399', width: 0.7, dash: 'dot'}, layer: 'below'});
  annotations.push({xref: 'x', yref: 'paper', x: at, y: index % 2 ? 1.20 : 1.02, yanchor: 'bottom',
    text: point.label + '<br>' + at.toFixed(2) + ' s', xanchor: index === milestones.length - 1 ? 'right' : 'center',
    showarrow: false, font: {color: '#96a6b9', size: 10}, align: 'center'});
}
Plotly.newPlot('timeline', traces, {
  paper_bgcolor: '#161e28', plot_bgcolor: '#161e28', font: {color: '#96a6b9', family: 'Menlo, Consolas, monospace', size: 10},
  xaxis: {title: {text: 'TIME FROM RUN START / s', standoff: 16, font: {size: 10}}, range: [0, endSeconds], autorange: false,
    gridcolor: '#29344366', zeroline: false, tickcolor: '#293443', ticks: 'outside', fixedrange: false},
  shapes, annotations,
  yaxis: {title: {text: 'MB/s', standoff: 10, font: {size: 10}}, range: [-extent, extent], gridcolor: '#293443', zerolinecolor: '#718196', zerolinewidth: 1,
    tickvals: [-extent * 0.9, -extent * 0.45, 0, extent * 0.45, extent * 0.9],
    ticktext: [extent * 0.9, extent * 0.45, 0, extent * 0.45, extent * 0.9].map(value => value.toFixed(1))},
  margin: {t: 94, l: 60, r: 30, b: 100},
  legend: {orientation: 'h', x: 0, y: -0.22, font: {size: 10}, groupclick: 'togglegroup'},
  hoverlabel: {bgcolor: '#10151c', bordercolor: '#293443', font: {color: '#e8eef5', family: 'Menlo, Consolas, monospace', size: 11}},
  uirevision: data.run + data.node,
}, {responsive: true, displaylogo: false, modeBarButtonsToRemove: ['lasso2d', 'select2d', 'autoScale2d']});
document.getElementById('node').textContent = data.node;
document.getElementById('run').textContent = data.run + ' · ' + traffic.bucket_ms + ' ms buckets · ' + traffic.buckets.length + ' buckets with traffic';
document.getElementById('received').textContent = mb(traffic.received).toFixed(2) + ' MB';
document.getElementById('sent').textContent = mb(traffic.sent).toFixed(2) + ' MB';
document.getElementById('peak').textContent = peak.toFixed(2) + ' MB/s';
document.getElementById('raw-buckets').addEventListener('change', () => {
  const raw = document.getElementById('raw-buckets').checked;
  Plotly.restyle('timeline', {'line.shape': raw ? 'hv' : 'spline', 'line.smoothing': raw ? 0 : 0.65});
  document.getElementById('curve-note').textContent = raw
    ? 'Raw buckets · flat rate within each measured interval'
    : 'Curved display · interpolation only; totals, peak and hover values use raw buckets';
});
"""

TRAFFIC_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>leanSim traffic: node {node_id}</title><style>
:root {{ color-scheme: dark; --ink: #10151c; --surface: #161e28; --rule: #293443; --text: #e8eef5; --muted: #96a6b9; --sent: #53d8b1; --received: #ad9bff; --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace; }}
* {{ box-sizing: border-box; }}
body {{ background: var(--ink); color: var(--text); font: 14px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; }}
a {{ color: inherit; text-decoration: none; }} a:hover {{ color: var(--sent); }}
a:focus-visible, input:focus-visible, summary:focus-visible {{ outline: 2px solid var(--sent); outline-offset: 5px; }}
.shell {{ max-width: 1560px; margin: auto; padding: 0 48px 36px; }}
.masthead {{ display: flex; justify-content: space-between; align-items: center; gap: 20px; padding: 22px 0; border-bottom: 1px solid var(--rule); }}
.brand {{ font: 700 18px 'Avenir Next', 'Segoe UI', sans-serif; letter-spacing: -.7px; }} .brand span {{ color: var(--sent); }}
.eyebrow, .capture-tag, .unit, .section-index {{ font: 11px/1.5 var(--mono); letter-spacing: .09em; text-transform: uppercase; color: var(--muted); }}
.capture-tag {{ display: flex; align-items: center; gap: 8px; }} .capture-tag::before {{ content: ''; width: 6px; height: 6px; background: var(--muted); border-radius: 50%; }}
.intro {{ display: flex; justify-content: space-between; align-items: end; gap: 24px; margin: 32px 0 22px; }}
h1 {{ font: 500 clamp(28px, 3.3vw, 44px)/1.2 'Avenir Next', 'Segoe UI', sans-serif; letter-spacing: -1.6px; margin: 7px 0 8px; }}
h1 span {{ color: var(--muted); }} .run-name {{ color: var(--muted); font: 11px/1.6 var(--mono); overflow-wrap: anywhere; margin: 0; }}
.summary-link {{ font: 12px var(--mono); white-space: nowrap; padding-bottom: 6px; }}
.host-strip {{ display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }}
.host-strip .eyebrow {{ margin-right: 12px; }} .host-link {{ font: 12px var(--mono); padding: 7px 13px; border: 1px solid transparent; border-radius: 6px; color: var(--muted); }}
.host-link:hover {{ background: var(--surface); color: var(--text); }} .host-link[aria-current="page"] {{ color: var(--sent); background: #53d8b10c; border-color: #53d8b14d; }}
.traffic-stage {{ border: 1px solid var(--rule); border-radius: 12px; background: var(--surface); overflow: hidden; }}
.stage-head {{ display: flex; justify-content: space-between; align-items: center; gap: 20px; padding: 22px 26px 16px; }}
h2 {{ font: 500 17px 'Avenir Next', 'Segoe UI', sans-serif; letter-spacing: -.3px; margin: 0; }} .stage-head .eyebrow {{ margin-bottom: 5px; }}
.view-control {{ display: flex; align-items: center; gap: 9px; color: var(--muted); font: 11px var(--mono); cursor: pointer; white-space: nowrap; }} .view-control input {{ accent-color: var(--sent); width: 15px; height: 15px; margin: 0; }}
.readouts {{ display: flex; flex-wrap: wrap; align-items: baseline; gap: 30px; padding: 0 26px 4px; }}
.readout {{ display: flex; align-items: baseline; gap: 10px; }} .readout .label {{ font: 11px var(--mono); text-transform: uppercase; letter-spacing: .04em; }}
.readout b {{ font: 500 22px/1.4 var(--mono); letter-spacing: -.9px; }} .out {{ color: var(--sent); }} .in {{ color: var(--received); }}
.readout.quiet {{ margin-left: auto; color: var(--muted); }} .readout.quiet b {{ font-size: 13px; letter-spacing: 0; }}
#timeline {{ width: 100%; height: 470px; }}
.chart-foot {{ padding: 12px 26px; border-top: 1px solid var(--rule); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px 20px; color: var(--muted); font: 10px/1.5 var(--mono); }}
.below {{ display: grid; grid-template-columns: minmax(0, 3fr) minmax(230px, 1fr); gap: 36px; margin-top: 32px; align-items: start; }}
.section-heading {{ display: flex; align-items: baseline; justify-content: space-between; gap: 16px; margin-bottom: 16px; }}
.section-index {{ font-size: 10px; text-transform: none; letter-spacing: 0; }}
.table-scroll {{ overflow-x: auto; }} .peer-ledger {{ width: 100%; border-collapse: collapse; font: 11px/1.5 var(--mono); text-align: left; }}
.peer-ledger th {{ font-weight: 400; color: var(--muted); padding: 0 12px 10px; border-bottom: 1px solid var(--rule); }}
.peer-ledger td {{ padding: 11px 12px; border-bottom: 1px solid #29344377; font-variant-numeric: tabular-nums; }}
.peer-ledger th:first-child, .peer-ledger td:first-child {{ padding-left: 0; }} .peer-ledger td:first-child {{ max-width: 230px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.peer-ledger tr:hover td {{ background: #ffffff03; }} .peer-ledger .numeric {{ text-align: right; white-space: nowrap; }}
.mix {{ display: flex; height: 5px; width: 100%; min-width: 80px; border-radius: 3px; background: #293443; overflow: hidden; }} .mix i {{ height: 100%; }}
.mix .out {{ background: var(--sent); }} .mix .in {{ background: var(--received); }}
.notes {{ border-left: 1px solid var(--rule); padding-left: 24px; color: var(--muted); font-size: 12px; }}
.notes h2 {{ color: var(--text); font-size: 15px; }} .notes p {{ margin: 12px 0; }}
.notes details {{ margin-top: 18px; }} .notes summary {{ cursor: pointer; color: var(--text); font: 11px var(--mono); }}
.notes dl {{ margin: 18px 0 0; }} .notes dt {{ font: 10px var(--mono); color: var(--text); text-transform: uppercase; letter-spacing: .05em; margin-top: 15px; }} .notes dd {{ margin: 4px 0 0; }}
.footer {{ display: flex; justify-content: space-between; gap: 15px; border-top: 1px solid var(--rule); margin-top: 30px; padding-top: 16px; color: var(--muted); font: 10px var(--mono); }}
@media (max-width: 800px) {{ .shell {{ padding: 0 18px 24px; }} .intro {{ margin-top: 24px; }} .below {{ grid-template-columns: 1fr; gap: 28px; }} .notes {{ border-left: 0; border-top: 1px solid var(--rule); padding: 20px 0 0; }} .stage-head {{ padding: 18px; }} .readouts {{ padding: 0 18px; gap: 12px 20px; }} .readout b {{ font-size: 17px; }} .readout.quiet {{ margin-left: 0; }} #timeline {{ height: 410px; }} .chart-foot {{ padding: 12px 18px; }} .capture-tag {{ font-size: 9px; }} }}
@media (max-width: 460px) {{ .intro {{ align-items: start; }} .summary-link {{ font-size: 10px; }} .stage-head {{ align-items: start; }} .readout {{ gap: 6px; }} .host-strip .eyebrow {{ width: 100%; }} }}
@media (prefers-reduced-motion: reduce) {{ *, *::before, *::after {{ animation: none !important; transition: none !important; }} }}
</style></head><body><div class="shell">
<header class="masthead"><a class="brand" href="summary.html">lean<span>Sim</span></a><span class="capture-tag">Recorded simulation / traffic</span></header>
<div class="intro"><div><div class="eyebrow">Peer traffic analysis</div><h1>Node <span id="node">{node_id}</span></h1><p class="run-name" id="run"></p></div><a class="summary-link" href="summary.html">Run overview ↗</a></div>
<nav class="host-strip" aria-label="Logged hosts"><span class="eyebrow">Tracked hosts</span>{host_links}</nav>
<section class="traffic-stage" aria-labelledby="traffic-heading">
<div class="stage-head"><div><div class="eyebrow">Duplex traffic · MB/s</div><h2 id="traffic-heading">Signature gossip to recursive proofs</h2></div><label class="view-control"><input type="checkbox" id="raw-buckets" aria-describedby="curve-note">Raw buckets</label></div>
<div class="readouts"><div class="readout out"><span class="label">↑ Sent</span><b id="sent"></b></div><div class="readout in"><span class="label">↓ Received</span><b id="received"></b></div><div class="readout quiet"><span class="label">Peak bucket rate</span><b id="peak"></b></div></div>
<div id="timeline" role="img" aria-label="Traffic timeline. Sent traffic above zero, received traffic below. Warmup is unmeasured."></div>
<div class="chart-foot"><span id="curve-note">Curved display · raw values on hover</span><span>Time from run start · run-wide milestones</span></div>
</section>
<div class="below"><section aria-labelledby="peers-heading"><div class="section-heading"><h2 id="peers-heading">Peer exchanges</h2><span class="section-index">{peer_caption}</span></div>
<div class="table-scroll"><table class="peer-ledger"><thead><tr><th scope="col">Peer</th><th scope="col" class="numeric">Sent ↑</th><th scope="col" class="numeric">Received ↓</th><th scope="col">Traffic mix</th></tr></thead><tbody>{peer_rows}</tbody></table></div></section>
<aside class="notes"><h2>Reading this trace</h2><p>Above the baseline is sent traffic. Below is received traffic. Colors identify message types; click a legend item to hide or restore a type.</p><dl><dt>Before signatures</dt><dd>Connections and subscriptions form during warmup. That traffic is not captured.</dd><dt>After signatures</dt><dd>Gossip arrives in a burst. Proof transfers follow as aggregation groups complete.</dd></dl><details><summary>Measurement notes</summary><p>Application-level traffic, not wire bandwidth. Outgoing gossip is estimated. IHAVE/IWANT, transport overhead and retransmissions are not measured.</p><p>Proof bytes are assigned when messages are handled, not spread over the transfer. Peaks can exceed physical link rates.</p><p>Curves are interpolation only. Totals, peak rates and hover values use the raw buckets.</p></details></aside></div>
<footer class="footer"><span>leanSim / offline trace</span><span>Decimal MB · 1 MB = 1,000,000 bytes</span></footer>
</div><script id="traffic-data" type="application/json">{data}</script><script>{plotly}</script><script>{script}</script></body></html>
"""


def generate_traffic_html(snapshot, directory, plotly_js):
    """One dark dashboard per host that kept traffic logs."""
    traffic = snapshot.get("metrics", {}).get("traffic") or {}
    run = Path(snapshot.get("output_dir", "")).name
    metrics = snapshot.get("metrics", {})
    recursive = metrics.get("recursive_aggregation") or {}
    local_firsts = [stats["min"] for stats in metrics.get("local_proof_latency_ms_by_subnet", {}).values() if stats]
    milestones = [
        {"label": label, "time_ms": time_ms}
        for label, value in (
            ("Signature burst", metrics.get("stage_medians_ms", {}).get("signatures_sent")),
            ("First subnet proof", min(local_firsts, default=None)),
            ("Final proof", recursive.get("final_proof_ms")),
        )
        if (time_ms := number(value)) is not None and time_ms >= 0
    ]
    for node_id, logged in traffic.items():
        host_links = " ".join(
            f'<a class="host-link" href="traffic-{html.escape(str(host))}.html"'
            + (' aria-current="page"' if host == node_id else '')
            + f'>Node {html.escape(str(host))}</a>'
            for host in sorted(traffic, key=int)
        )
        leaders = logged["peers"][:15]
        rows = []
        largest = max((peer["inbound"] + peer["outbound"] for peer in leaders), default=1) or 1
        for peer in leaders:
            label = html.escape(peer["peer"])
            if str(peer.get("node_id")) in traffic:
                label = f'<a href="traffic-{peer["node_id"]}.html">{label} ↗</a>'
            sent_width = peer["outbound"] / largest * 100
            received_width = peer["inbound"] / largest * 100
            rows.append(
                f'<tr><td title="{html.escape(peer["peer"], quote=True)}">{label}</td>'
                f'<td class="numeric out">{peer["outbound"] / 1e6:,.2f} MB</td>'
                f'<td class="numeric in">{peer["inbound"] / 1e6:,.2f} MB</td>'
                f'<td><span class="mix" aria-hidden="true"><i class="out" style="width:{sent_width:.3f}%"></i>'
                f'<i class="in" style="width:{received_width:.3f}%"></i></span></td></tr>'
            )
        data = json_data({"node": node_id, "run": run, "traffic": logged, "milestones": milestones,
                          "warmup_ms": snapshot.get("metadata", {}).get("mesh_warmup_ms")})
        document = TRAFFIC_TEMPLATE.format(
            node_id=html.escape(str(node_id)),
            host_links=host_links,
            peer_caption=f'Top {len(leaders)} of {len(logged["peers"])} retained peer records',
            peer_rows="".join(rows) or '<tr><td colspan="4">No per-peer records in this trace.</td></tr>',
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
            '{"event":"SigSent","node_id":7,"validator_id":0,"subnet_id":0,"ts_ms":4100}',
            '{"event":"LocalProofGenerated","node_id":7,"subnet_id":0,"sig_count":1,"latency_ms":4200}',
            '{"event":"RecursiveProofGenerated","node_id":7,"layer":1,"index":0,"inputs":2,"is_final":true,"ts_ms":4500}',
            '{"event":"TrafficBucket","node_id":7,"start_ms":4300,"width_ms":100,"inbound":{"signature":1200,"proof_payload":262144},"outbound":{"signature":2400}}',
            '{"event":"TrafficBucket","node_id":7,"start_ms":4400,"width_ms":100,"inbound":{},"outbound":{"proof_announce":128}}',
            '{"event":"TrafficPeer","node_id":7,"peer":"peer:peer-9","inbound_bytes":1200,"outbound_bytes":2400,"inbound_msgs":1,"outbound_msgs":2}',
            '{"event":"TrafficPeer","node_id":7,"peer":"node:5","inbound_bytes":262144,"outbound_bytes":0,"inbound_msgs":1,"outbound_msgs":0}',
        )), encoding="utf-8")
        (traffic_dir / "run-manifest.json").write_text(json.dumps({"experiment": {"local_threshold": 1.0, "mesh_warmup_ms": 3000}}), encoding="utf-8")
        traffic_snapshot = build_snapshot(traffic_dir)
        assert traffic_snapshot["metadata"]["mesh_warmup_ms"] == 3000
        assert primary["metadata"]["mesh_warmup_ms"] is None
        traffic = traffic_snapshot["metrics"]["traffic"]
        assert traffic_snapshot["metrics"]["total_bytes"] == 0, "traffic events must not count as signature traffic"
        assert set(traffic) == {"7"}
        logged = traffic["7"]
        assert logged["bucket_ms"] == 100
        assert logged["received"] == 263344 and logged["sent"] == 2528
        assert [bucket["start_ms"] for bucket in logged["buckets"]] == [4300, 4400]
        assert [bucket["width_ms"] for bucket in logged["buckets"]] == [100, 100]
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
        assert 'class="traffic-stage"' in dashboard, "timeline must be the full-width primary view"
        assert '<table class="peer-ledger">' in dashboard
        assert 'aria-label="Logged hosts"' in dashboard
        assert 'id="peers"' not in dashboard, "a second chart must not compete with the timeline"
        assert 'Measurement notes' in dashboard
        embedded_traffic = json.loads(dashboard.split('<script id="traffic-data" type="application/json">', 1)[1].split('</script>', 1)[0])
        assert embedded_traffic["warmup_ms"] == 3000
        assert embedded_traffic["milestones"] == [
            {"label": "Signature burst", "time_ms": 4100},
            {"label": "First subnet proof", "time_ms": 4200},
            {"label": "Final proof", "time_ms": 4500},
        ]
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
            # Exercise the real dashboard JS, not just its syntax. A gap must
            # return to zero; rates use each bucket's width, not bytes per bucket.
            rate_fixture = {
                "node": "7", "run": "test", "warmup_ms": 800,
                "milestones": [{"label": "Signature burst", "time_ms": 1100},
                               {"label": "First subnet proof", "time_ms": 1200},
                               {"label": "Final proof", "time_ms": 1400}], "traffic": {
                    "bucket_ms": 100, "sent": 3000000, "received": 1000000, "peers": [],
                    "buckets": [
                        {"start_ms": 1000, "width_ms": 200, "outbound": {"signature": 2000000}, "inbound": {"proof_payload": 1000000}},
                        {"start_ms": 1400, "width_ms": 100, "outbound": {"signature": 1000000}, "inbound": {}},
                    ],
                },
            }
            harness = "const fixture = " + json.dumps(rate_fixture) + ";\n" + r"""
const assert = require('node:assert/strict');
const elements = new Map();
global.document = {getElementById(id) {
  if (!elements.has(id)) elements.set(id, {textContent: id === 'traffic-data' ? JSON.stringify(fixture) : '', checked: false,
    addEventListener(event, handler) { this[event] = handler; }});
  return elements.get(id);
}};
const plots = new Map();
global.Plotly = {
  newPlot(id, traces, layout) { plots.set(id, {traces, layout}); },
  restyle(id, changes) {
    for (const trace of plots.get(id).traces) {
      for (const [key, value] of Object.entries(changes)) {
        const [field, property] = key.split('.');
        trace[field][property] = value;
      }
    }
  },
};
""" + TRAFFIC_JS + r"""
const timeline = plots.get('timeline');
assert.deepEqual(timeline.layout.xaxis.range, [0, 1.5], 'include the run start, not just traffic');
assert.equal(timeline.layout.shapes[0].x0, 0);
assert.equal(timeline.layout.shapes[0].x1, 0.8);
assert.match(timeline.layout.annotations[0].text, /warmup.*traffic not.*captured/i);
assert.ok(timeline.layout.shapes.some(shape => shape.type === 'line' && shape.x0 === 1.4));
assert.ok(timeline.layout.annotations.some(note => note.text.includes('Final proof')));
assert.notEqual(timeline.layout.annotations[1].y, timeline.layout.annotations[2].y, 'nearby milestones need separate label lanes');
const sent = timeline.traces.find(trace => trace.legendgroup === 'signature' && trace.stackgroup === 'sent');
const received = timeline.traces.find(trace => trace.legendgroup === 'proof_payload' && trace.stackgroup === 'received');
assert.ok(sent, 'sent traffic must be stacked areas, not bars');
assert.ok(received, 'received traffic must have its own stack');
assert.equal(sent.type, 'scatter');
assert.equal(sent.line.shape, 'spline', 'default timeline should have curved outlines');
assert.ok(sent.line.smoothing > 0 && sent.line.smoothing <= 1);
assert.deepEqual(sent.x, [1, 1.2, 1.4, 1.5]);
assert.deepEqual(sent.y, [10, 0, 10, 0]);
assert.deepEqual(received.y, [-5, 0, 0, 0]);
assert.match(timeline.layout.yaxis.title.text, /MB\/s/);
assert.equal(elements.get('peak').textContent, '10.00 MB/s');
const rawToggle = document.getElementById('raw-buckets');
assert.equal(typeof rawToggle.change, 'function', 'raw bucket toggle must be wired');
rawToggle.checked = true;
rawToggle.change();
assert.ok(timeline.traces.every(trace => trace.line.shape === 'hv'));
assert.deepEqual(sent.y, [10, 0, 10, 0], 'switching views must not alter measured rates');
rawToggle.checked = false;
rawToggle.change();
assert.ok(timeline.traces.every(trace => trace.line.shape === 'spline'));
assert.equal(elements.get('peak').textContent, '10.00 MB/s');
"""
            traffic_js_path.write_text(harness, encoding="utf-8")
            result = subprocess.run(["node", str(traffic_js_path)], capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
            # Older snapshots may not carry warmup metadata: do not invent it.
            unknown_warmup = harness.replace('"warmup_ms": 800', '"warmup_ms": null').split("const timeline = plots.get('timeline');", 1)[0]
            unknown_warmup += "assert.equal(plots.get('timeline').layout.xaxis.range[0], 0);\nassert.ok(plots.get('timeline').layout.shapes.every(shape => shape.type !== 'rect'));"
            traffic_js_path.write_text(unknown_warmup, encoding="utf-8")
            result = subprocess.run(["node", str(traffic_js_path)], capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
            # The dashboard is its own page: the summary report's helpers are not in scope.
            assert "number(" not in TRAFFIC_JS, "traffic.js must define its own formatters"
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
