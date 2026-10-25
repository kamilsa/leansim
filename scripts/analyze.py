#!/usr/bin/env python3
"""Build an offline, interactive summary of one or more leanSim Shadow runs."""

import argparse
import json
import math
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from report import generate_html


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


def subnet_host_summary(hosts):
    """Per subnet, the classes and countries of the hosts subscribed to it."""
    subnets = sorted({subnet for host in hosts.values() for subnet in host.get("subscribed_subnets") or []})
    summary = {}
    for subnet_id in subnets:
        classes = defaultdict(int)
        countries = defaultdict(lambda: {"supernode": 0, "regular": 0, "unknown": 0, "validators": 0})
        for host in hosts.values():
            if subnet_id not in (host.get("subscribed_subnets") or []):
                continue
            kind = node_class(host)
            classes[kind] += 1
            country = countries[host.get("country") or "unknown"]
            country[kind] += 1
            country["validators"] += len(host.get("validator_ids") or [])
        summary[subnet_id] = {
            "classes": {kind: classes[kind] for kind in NODE_CLASSES},
            "countries": sorted(
                ({"country": name, **totals} for name, totals in countries.items()),
                key=lambda row: (-(row["supernode"] + row["regular"] + row["unknown"]), row["country"]),
            ),
        }
    return summary


def subnet_proof_rows(local_proofs, t0, hosts):
    """Per subnet, when each of its aggregators finished a subnet proof (ms
    after t0): min/p25/median/p75/max, and every proof as [ms, node, class]."""
    by_subnet = defaultdict(list)
    for node_id, subnet_id, time_ms in local_proofs:
        by_subnet[subnet_id].append([time_ms - t0, node_id, node_class(hosts.get(node_id))])
    rows = []
    for subnet_id, proofs in sorted(by_subnet.items()):
        proofs.sort(key=lambda proof: (proof[0], -1 if proof[1] is None else proof[1]))
        stats = frequency_percentiles(Counter(proof[0] for proof in proofs), (25, 50, 75))
        rows.append({"subnet": subnet_id, "count": stats["count"], "min": proofs[0][0], "p25": stats["p25"],
                     "p50": stats["p50"], "p75": stats["p75"], "max": proofs[-1][0], "proofs": proofs})
    return rows


def host_duties(host, top_layer):
    """Which proofs a host aggregates: its subnets, its group seats per tree
    layer, and whether it sits in the final (top-layer) group."""
    layers = defaultdict(set)
    final = False
    for seat in host.get("recursive_seats") or []:
        if not isinstance(seat, (list, tuple)) or len(seat) != 2:
            continue
        layer, index = seat
        if layer == top_layer:
            final = True
        else:
            layers[layer].add(index)
    return {
        "subnets": sorted(host.get("aggregated_subnets") or []),
        "layers": {str(layer): sorted(indices) for layer, indices in sorted(layers.items())},
        "final": final,
    }


def host_card(host, top_layer=None):
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
        "duties": host_duties(host, top_layer),
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


def read_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


# Experiment settings the summary's configuration section reports, in display order.
CONFIG_KEYS = (
    "validator_count", "subnet_count", "subnet_subscriptions_per_node", "subscribe_to_duty_subnets",
    "local_threshold", "mesh_warmup_ms", "burst_time_ms", "burst_jitter_ms",
    "signature_payload_bytes", "signature_aggregation_rate",
    "committee_aggregators", "local_aggregators_per_subnet",
    "recursive_aggregation", "recursive_aggregation_arity", "recursive_aggregation_time_ms",
    "recursive_group_size", "recursive_proofs_per_child", "aggregate_proof_bytes",
    "gossipsub_mesh_n", "gossipsub_mesh_n_low", "gossipsub_mesh_n_high", "gossipsub_heartbeat_interval_ms",
    "gossipsub_flood_publish", "gossipsub_idontwant",
)


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
        "config": {key: experiment[key] for key in CONFIG_KEYS if key in experiment},
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
    # Per subnet: first sighting of each of its validators anywhere, and every
    # delivery to a subscribed host of each class.
    subnet_counts = defaultdict(lambda: defaultdict(Counter))
    subnet_first = defaultdict(dict)
    for (node_id, subnet_id), seen in received_by_node_subnet.items():
        counter = subnet_counts[subnet_id][node_class(hosts.get(node_id))]
        firsts = subnet_first[subnet_id]
        for key, time_ms in seen.items():
            counter[time_ms - t0] += 1
            previous = firsts.get(key)
            if previous is None or time_ms < previous:
                firsts[key] = time_ms
    signature_cdf_by_subnet = {}
    for subnet_id, firsts in subnet_first.items():
        lines = {"first_seen": frequency_cdf(Counter(time_ms - t0 for time_ms in firsts.values()))}
        for kind in NODE_CLASSES:
            if subnet_counts[subnet_id].get(kind):
                lines[kind] = frequency_cdf(subnet_counts[subnet_id][kind])
        signature_cdf_by_subnet[subnet_id] = lines
    experiment = manifest.get("experiment") if isinstance(manifest.get("experiment"), dict) else {}
    traffic = traffic_summary(traffic_buckets, traffic_peers, peer_ids)
    # The final group is the plan's top layer; fall back to where a final proof appeared.
    plan_groups = read_json(output_dir / "aggregation-plan.json").get("groups")
    plan_layers = [group.get("layer") for group in plan_groups or [] if isinstance(group, dict) and isinstance(group.get("layer"), int)]
    top_layer = max(plan_layers, default=final_layer)
    for node_id, logged in traffic.items():
        logged["host"] = host_card(hosts.get(int(node_id)), top_layer)

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
            "subnet_proofs": subnet_proof_rows(local_proofs, t0, hosts),
            "subnet_hosts": subnet_host_summary(hosts),
            "signature_cdf_by_subnet": signature_cdf_by_subnet,
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
        history = merge_history([], [primary, overlay], append=False)
        assert len(history) == 2
        assert len(merge_history(history, [primary, overlay], append=False)) == 2
        assert len(merge_history(history, [primary, overlay], append=True)) == 3
        history_path = primary_dir / "runs-history.json"
        history_path.write_text("malformed", encoding="utf-8")
        assert load_history(history_path) == []
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
    generate_html(snapshots[0], summary_path)
    print("Analyzed %d director%s: %s" % (len(snapshots), "y" if len(snapshots) == 1 else "ies", summary_path))
    print("History snapshots: %d; primary events: %d" % (len(history), snapshots[0]["metrics"]["parsed_events"]))
    if args.serve:
        serve_directory(primary_dir, args.port)


if __name__ == "__main__":
    main()
