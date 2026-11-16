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
    "Churn",
    "MeshDegree",
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
    "TransportStats",
}

# TransportStats counters summed over hosts (see metrics::events::TransportStats).
TRANSPORT_FIELDS = (
    "ihave_ids_sent", "ihave_bytes_sent", "iwant_ids_sent", "iwant_bytes_sent",
    "idontwant_ids_sent", "idontwant_bytes_sent", "idontwant_ids_received", "forwards_suppressed", "queued_forwards_dropped",
    "iwant_responses", "iwant_response_duplicates", "fanout_sigs_sent",
    "have_sent", "have_bytes_sent", "want_sent", "want_ids_sent", "want_bytes_sent",
    "pull_sigs_served", "pull_bytes_served", "pulled_received", "pulled_duplicates",
    "coded_sent", "coded_bytes_sent", "coded_received", "coded_innovative", "coded_decoded",
    "coded_mismatches", "acks_sent", "sync_failures", "pending_rows",
    "bundles_sent", "bundle_sigs_sent", "bundle_bytes_sent", "bundle_framing_bytes_sent",
    "requested_sigs_served", "backlog_sigs_sent", "metadata_sent", "metadata_bytes_sent", "available_ids_sent",
    "request_ids_sent", "pushes_avoided", "lazy_sigs_sent", "announce_ids_sent", "requests_already_sent",
    "requests_suppressed", "requests_avoided", "invalid_partials",
    "restart_notices_sent", "restart_reconnects",
)
SIG_VIAS = ("gossip", "pull", "coded", "bundle", "backlog", "requested")
MESH_SAMPLES = ("signing", "exit")


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
# Classes split by churn: delivery charts show a class's churny hosts apart from its stable ones.
NODE_GROUPS = ("supernode", "supernode_churny", "regular", "regular_churny", "unknown")
# Host classes with churn settings of their own (<class>_churn_fraction and so on).
CHURN_CLASSES = ("supernode", "regular")
# How long a peer keeps its connection to a crashed host: libp2p-quic's max_idle_timeout.
QUIC_IDLE_TIMEOUT_MS = 10_000
# Points per line of the hosts-online chart.
MAX_AVAILABILITY_POINTS = 600


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


def node_group(host):
    """node_class, with "_churny" appended for a host the manifest marks as churny."""
    kind = node_class(host)
    return kind + "_churny" if kind != "unknown" and host.get("churny") else kind


def proof_label(layer, final_layer):
    if layer == 0:
        return "Subnet proofs"
    if layer == final_layer:
        return "Final proof"
    return f"Layer {layer} proofs"


def arrival_rows(signature_counts, proof_held, final_layer, t0, hosts):
    """Box-plot rows: per message and host class (churny hosts apart), the spread
    of the times (ms after t0) at which hosts first held it. Signatures count
    once per (receiving host, validator); proofs once per (host, proof), whether
    the host built the proof or fetched it."""
    rows = []

    def add(message, counts_by_class):
        for kind in NODE_GROUPS:
            stats = frequency_percentiles(counts_by_class.get(kind, {}))
            if stats:
                rows.append({"message": message, "class": kind, **stats})

    add("Signatures", signature_counts)
    for layer in sorted(proof_held):
        counts = defaultdict(Counter)
        for held in proof_held[layer].values():
            for node_id, time_ms in held.items():
                counts[node_group(hosts.get(node_id))][time_ms - t0] += 1
        add(proof_label(layer, final_layer), counts)
    return rows


def country_rows(hosts):
    """Hosts per country split by class, plus the validators they run; most hosts first."""
    countries = defaultdict(lambda: {"supernode": 0, "regular": 0, "unknown": 0, "validators": 0})
    for host in hosts:
        country = countries[host.get("country") or "unknown"]
        country[node_class(host)] += 1
        country["validators"] += len(host.get("validator_ids") or [])
    return sorted(
        ({"country": name, **totals} for name, totals in countries.items()),
        key=lambda row: (-(row["supernode"] + row["regular"] + row["unknown"]), row["country"]),
    )


def subnet_host_summary(hosts):
    """Per subnet, the classes and countries of the hosts subscribed to it, and
    the hosts that aggregate it (manifest aggregated_subnets)."""
    subnets = sorted({subnet for host in hosts.values()
                      for subnet in (host.get("subscribed_subnets") or []) + (host.get("aggregated_subnets") or [])})
    summary = {}
    for subnet_id in subnets:
        subscribers = [host for host in hosts.values() if subnet_id in (host.get("subscribed_subnets") or [])]
        aggregators = [hosts[node_id] for node_id in sorted(hosts)
                       if subnet_id in (hosts[node_id].get("aggregated_subnets") or [])]
        classes = Counter(node_class(host) for host in subscribers)
        summary[subnet_id] = {
            "classes": {kind: classes[kind] for kind in NODE_CLASSES},
            "countries": country_rows(subscribers),
            "aggregators": [{
                "node": host["node_id"], "country": host.get("country"), "class": node_class(host),
                "uplink_mbps": host.get("uplink_mbps"), "downlink_mbps": host.get("downlink_mbps"),
                "validators": len(host.get("validator_ids") or []),
            } for host in aggregators],
            "aggregator_countries": country_rows(aggregators),
        }
    return summary


def subnet_proof_rows(local_proofs, t0, hosts):
    """Per subnet, when each of its aggregators finished a subnet proof (ms
    after t0): min/p25/median/p75/max, and every proof as [ms, node, class],
    the class with "_churny" for a churny host."""
    by_subnet = defaultdict(list)
    for node_id, subnet_id, time_ms in local_proofs:
        by_subnet[subnet_id].append([time_ms - t0, node_id, node_group(hosts.get(node_id))])
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


def power_bins(hosts, value_of, include_zero=True):
    """Hosts binned by the highest power of two at or below value_of(host):
    0, 1, 2-3, 4-7, ... with hosts per class and the validators they run."""
    bins = defaultdict(lambda: {"supernode": 0, "regular": 0, "unknown": 0, "validators": 0})
    for host in hosts:
        value = value_of(host)
        low = 1 << (value.bit_length() - 1) if value else 0
        bins[low][node_class(host)] += 1
        bins[low]["validators"] += len(host.get("validator_ids") or [])
    top = max(bins) if bins else 0
    lows = ([0] if include_zero else []) + [1 << power for power in range(top.bit_length())]
    return [{"low": low, "high": low * 2 - 1 if low else 0, **bins[low]} for low in lows]


def aggregator_population(hosts):
    """Hosts that aggregate at least one subnet: class split with link rates,
    countries and how many subnets each one aggregates; None without duties."""
    aggregators = [host for host in hosts.values() if host.get("aggregated_subnets")]
    if not aggregators:
        return None
    classes = defaultdict(lambda: {"hosts": 0, "validators": 0})
    for host in aggregators:
        totals = classes[(node_class(host), host.get("uplink_mbps"), host.get("downlink_mbps"))]
        totals["hosts"] += 1
        totals["validators"] += len(host.get("validator_ids") or [])
    return {
        "hosts": len(aggregators),
        "validators": sum(len(host.get("validator_ids") or []) for host in aggregators),
        "subnets": len({subnet for host in aggregators for subnet in host["aggregated_subnets"]}),
        "classes": [
            {"class": kind, "uplink_mbps": up, "downlink_mbps": down, **totals}
            for (kind, up, down), totals in sorted(
                classes.items(), key=lambda item: (NODE_CLASSES.index(item[0][0]), -item[1]["hosts"], str(item[0][1:]))
            )
        ],
        "countries": country_rows(aggregators),
        "subnets_per_host": power_bins(aggregators, lambda host: len(host["aggregated_subnets"]), include_zero=False),
    }


def host_population(hosts, experiment):
    """Host and validator counts by bandwidth class, validators-per-host bins
    (0, 1, 2-3, 4-7, ...) and countries, from the manifest; None without nodes."""
    if not hosts:
        return None
    classes = defaultdict(lambda: {"hosts": 0, "validators": 0})
    for host in hosts.values():
        kind = node_class(host)
        count = len(host.get("validator_ids") or [])
        totals = classes[(kind, host.get("uplink_mbps"), host.get("downlink_mbps"))]
        totals["hosts"] += 1
        totals["validators"] += count
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
        "validators_per_host": power_bins(hosts.values(), lambda host: len(host.get("validator_ids") or [])),
        "countries": country_rows(hosts.values()),
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
    "gossipsub_flood_publish", "gossipsub_gossip", "gossipsub_idontwant", "gossipsub_idontwant_threshold_bytes",
    "signature_sync", "sync_interval_ms", "sync_grace_ms", "sync_pull_batch",
    "sync_coded_degree", "sync_coded_redundancy", "sync_coded_per_tick",
    "churn_tick_ms", "regular_churn_fraction", "regular_churn_leave_probability", "regular_churn_rejoin_probability",
    "supernode_churn_fraction", "supernode_churn_leave_probability", "supernode_churn_rejoin_probability",
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
    # Per delivery path: unique and duplicate receptions, and the bytes they carried.
    via_counts = {via: {"unique": 0, "duplicate": 0, "bytes": 0} for via in SIG_VIAS}
    transport = {field: 0 for field in TRANSPORT_FIELDS}
    transport_nodes = set()
    # Churn: each host's (ts_ms, online) events in log order, the hosts that have
    # crashed so far, and the signatures hosts got again after losing them in a crash.
    churn_events = defaultdict(list)
    crashed = set()
    relearned = defaultdict(list)
    relearned_via = {via: 0 for via in SIG_VIAS}
    proofs_seen = set()
    repeated_proofs = 0
    # Sample ("signing", "exit") -> (node, subnet) -> mesh peers.
    mesh_degrees = defaultdict(dict)
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
            elif name == "Churn":
                node_id = integer(event.get("node_id"))
                timestamp = number(event.get("ts_ms"))
                if node_id is not None and timestamp is not None and isinstance(event.get("online"), bool):
                    churn_events[node_id].append((timestamp, event["online"]))
                    if not event["online"] and timestamp > 0:
                        crashed.add(node_id)
            elif name == "MeshDegree":
                node_id = integer(event.get("node_id"))
                subnet_id = integer(event.get("subnet_id"))
                peers = integer(event.get("peers"))
                if None not in (node_id, subnet_id, peers) and peers >= 0 and event.get("at") in MESH_SAMPLES:
                    mesh_degrees[event["at"]][(node_id, subnet_id)] = peers
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
                via = event.get("via") if event.get("via") in SIG_VIAS else "gossip"
                if byte_size is not None and byte_size >= 0:
                    via_counts[via]["bytes"] += byte_size
                if duplicate:
                    via_counts[via]["duplicate"] += 1
                    duplicate_sigs += 1
                    continue
                timestamp = number(event.get("ts_ms"))
                node_id = integer(event.get("node_id"))
                subnet_id = integer(event.get("subnet_id"))
                key = validator_key(event, "from_id")
                # A host that crashed lost every signature: one it held before and gets
                # again is neither a first copy nor a duplicate.
                if node_id in crashed and timestamp is not None and key in received_by_node_subnet.get((node_id, subnet_id), ()):
                    relearned_via[via] += 1
                    relearned[(node_id, subnet_id)].append(timestamp)
                    continue
                via_counts[via]["unique"] += 1
                unique_receive_events += 1
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
                    # An aggregator back from a crash can prove its subnet again; the first proof counts.
                    if node_id is not None and (node_id, subnet_id) in proofs_seen:
                        repeated_proofs += 1
                        continue
                    proofs_seen.add((node_id, subnet_id))
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
            elif name == "TransportStats":
                # A churny host logs its stats once per session.
                transport_nodes.add(event.get("node_id", ("anonymous", len(transport_nodes))))
                for field in TRANSPORT_FIELDS:
                    value = integer(event.get(field))
                    if value is not None and value >= 0:
                        transport[field] += value
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
                    received[key] = min(received.get(key, own_time), own_time)
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
                        held[key] = min(held.get(key, own_time), own_time)
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
    for node_id in churn_events:
        if node_id in hosts:
            hosts[node_id]["churny"] = True
    transport_hosts = len(transport_nodes)
    # Every chart in summary.html measures time from the first signature sent.
    t0 = min(sent_times) if sent_times else 0
    signature_counts = defaultdict(Counter)
    for (node_id, _), seen in received_by_node_subnet.items():
        counter = signature_counts[node_group(hosts.get(node_id))]
        for time_ms in seen.values():
            counter[time_ms - t0] += 1
    signature_cdf = {"first_seen": frequency_cdf(Counter(time_ms - t0 for time_ms in arrival_times))}
    for kind in NODE_GROUPS:
        if signature_counts.get(kind):
            signature_cdf[kind] = frequency_cdf(signature_counts[kind])
    # Per subnet: first sighting of each of its validators anywhere, and every
    # delivery to a subscribed host of each class.
    subnet_counts = defaultdict(lambda: defaultdict(Counter))
    subnet_first = defaultdict(dict)
    for (node_id, subnet_id), seen in received_by_node_subnet.items():
        counter = subnet_counts[subnet_id][node_group(hosts.get(node_id))]
        firsts = subnet_first[subnet_id]
        for key, time_ms in seen.items():
            counter[time_ms - t0] += 1
            previous = firsts.get(key)
            if previous is None or time_ms < previous:
                firsts[key] = time_ms
    signature_cdf_by_subnet = {}
    for subnet_id, firsts in subnet_first.items():
        lines = {"first_seen": frequency_cdf(Counter(time_ms - t0 for time_ms in firsts.values()))}
        for kind in NODE_GROUPS:
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
    subnet_hosts = subnet_host_summary(hosts)
    churn = churn_summary(
        hosts, experiment, churn_events, sent_times, sent_sources_by_subnet, sent_by_node,
        received_by_node_subnet, relearned, threshold_fraction, t0,
    )
    if churn:
        churn["counters"] = {
            "relearned": relearned_via,
            "relearned_total": sum(relearned_via.values()),
            "repeated_proofs": repeated_proofs,
            "restart_notices_sent": transport["restart_notices_sent"],
            "restart_reconnects": transport["restart_reconnects"],
            "sync_failures": transport["sync_failures"],
            "failed_proof_pulls": proof_traffic["failed_pulls"],
        }
        # Pages about one host or one subnet get what they show of the churn.
        offline = churn.pop("offline_ms")
        for node_id, logged in traffic.items():
            if int(node_id) in offline:
                logged["offline_ms"] = offline[int(node_id)]
                logged["host"]["churn"] = {"crashes": crashes_in(offline[int(node_id)])}
        by_subnet = churn.pop("subnets")
        for subnet_id, info in subnet_hosts.items():
            info["churn"] = by_subnet.get(subnet_id, {"churny": 0, "online_at_signing": None, "missed_signatures": None})
            for aggregator in info["aggregators"]:
                if aggregator["node"] in offline:
                    aggregator["crashes"] = crashes_in(offline[aggregator["node"]])

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
            "signature_transport": transport_summary(via_counts, transport, transport_hosts, len(signing_hosts)),
            "mesh": mesh_summary(mesh_degrees, sent_sources_by_subnet, via_counts, transport, unique_receive_events),
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
            "subnet_hosts": subnet_hosts,
            "signature_cdf_by_subnet": signature_cdf_by_subnet,
            "subnet_completion_ms": subnet_completion(hosts, received_by_node_subnet, sent_by_node, sent_sources_by_subnet, t0),
            "population": host_population(hosts, experiment),
            "aggregators": aggregator_population(hosts),
            "churn": churn,
        },
        "cdf": cdf,
        "node_stats": nodes,
    }


def transport_summary(via_counts, transport, hosts, signing_hosts):
    """Bytes on the wire for signature transport, by category, from the receivers'
    gossip, pull and bundle logs and the senders' TransportStats; None without those."""
    if not hosts:
        return None
    wire = {
        "gossip_signatures": via_counts["gossip"]["bytes"],
        "pulled_signatures": via_counts["pull"]["bytes"],
        # EIP-8334 bundles: each signature with its index, pushed (new or backlog) or
        # requested, then what the frames add to them, and the parts metadata.
        "bundled_signatures": sum(via_counts[via]["bytes"] for via in ("bundle", "backlog", "requested")),
        "bundle_framing": transport["bundle_framing_bytes_sent"],
        "parts_metadata": transport["metadata_bytes_sent"],
        "coded_packets": transport["coded_bytes_sent"],
        "bitmaps": transport["have_bytes_sent"],
        "pull_requests": transport["want_bytes_sent"],
        "gossip_control": transport["ihave_bytes_sent"] + transport["iwant_bytes_sent"] + transport["idontwant_bytes_sent"],
        # One byte per ack; small next to everything else.
        "sync_acks": transport["acks_sent"],
    }
    wire["total"] = sum(wire.values())
    return {
        "hosts": hosts,
        "deliveries": via_counts,
        "wire_bytes": wire,
        "wire_bytes_per_host": {key: value / hosts for key, value in wire.items()},
        "counters": transport,
        "signing_hosts": signing_hosts,
    }


def mesh_summary(mesh_degrees, signers_by_subnet, via_counts, transport, first_copies):
    """Mesh degrees per sample, and how many copies of a signature a mesh link carried.

    An eager push sends every signature over every mesh link at least once: the
    side that has it first sends it, and both sides do when their copies cross.
    Links are counted from the degrees at signing (half their sum per subnet).
    Copies on mesh links are the pushed copies received (gossip forwards without
    IWANT responses, or bundle pushes), less the copies publishers sent into
    subnets they do not subscribe to. None without MeshDegree events."""
    if not mesh_degrees:
        return None
    degree = {}
    for sample in MESH_SAMPLES:
        values = sorted(mesh_degrees.get(sample, {}).values())
        if not values:
            continue
        histogram = defaultdict(int)
        for value in values:
            histogram[value] += 1
        degree[sample] = {
            "count": len(values),
            "mean": sum(values) / len(values),
            "min": values[0],
            "p50": median(values),
            "max": values[-1],
            "histogram": {str(value): histogram[value] for value in sorted(histogram)},
        }
    sample = "signing" if "signing" in degree else "exit"
    links_by_subnet = defaultdict(float)
    for (_, subnet), peers in mesh_degrees[sample].items():
        links_by_subnet[subnet] += peers / 2
    link_copies_min = sum(links * len(signers_by_subnet.get(subnet, ())) for subnet, links in links_by_subnet.items())
    pushed = sum(via_counts[via]["unique"] + via_counts[via]["duplicate"] for via in ("gossip", "bundle", "backlog"))
    pushed_duplicates = sum(via_counts[via]["duplicate"] for via in ("gossip", "bundle", "backlog"))
    pushed -= transport["iwant_responses"]
    pushed_duplicates -= transport["iwant_response_duplicates"]
    fanout = transport["fanout_sigs_sent"]
    link_copies = pushed - fanout
    crossing = link_copies - link_copies_min
    return {
        "degree": degree,
        "links": sum(links_by_subnet.values()),
        "links_sampled_at": sample,
        "fanout_copies": fanout,
        "link_copies": link_copies,
        "link_copies_min": link_copies_min,
        "copies_per_link": link_copies / link_copies_min if link_copies_min else None,
        "crossing_copies": crossing,
        "push_duplicates_per_first_copy": pushed_duplicates / first_copies if first_copies else None,
        # What pushes would leave if no two copies crossed on a link.
        "one_copy_per_link_duplicates_per_first_copy": (pushed_duplicates - crossing) / first_copies if first_copies else None,
    }


def subnet_completion(hosts, received_by_node_subnet, sent_by_node, signers_by_subnet, t0, fractions=(0.9, 1.0)):
    """When each subscribed host held a fraction of its subnets' signatures.

    One entry per (host, subnet) the host subscribes to or aggregates, from the
    manifest (a host with no subscriptions listed is in the subnets it signs in,
    as the simulator defaults): the time from the first signature sent until the host held
    ceil(fraction x signers) of the subnet's signatures, its own validators
    counting from when they signed. Percentiles count pairs that never got there
    as infinitely late. A pure propagation metric: it needs no aggregators. None
    without subscriptions in the manifest."""
    pairs = []
    for node_id, host in hosts.items():
        subscribed = host.get("subscribed_subnets") or host.get("signing_subnets") or ()
        subnets = set(subscribed) | set(host.get("aggregated_subnets") or ())
        pairs.extend((node_id, subnet) for subnet in subnets if signers_by_subnet.get(subnet))
    if not pairs:
        return None
    reached = {fraction: [] for fraction in fractions}
    for node_id, subnet in pairs:
        held = dict(received_by_node_subnet.get((node_id, subnet), {}))
        for own_subnet, key, own_time in sent_by_node.get(node_id, ()):
            if own_subnet == subnet:
                # A host back from a crash can be sent its own signature; it held it from when it signed.
                held[key] = min(held.get(key, own_time), own_time)
        times = sorted(held.values())
        signers = len(signers_by_subnet[subnet])
        for fraction in fractions:
            needed = math.ceil(signers * fraction - 1e-9)
            if needed and len(times) >= needed:
                reached[fraction].append(times[needed - 1] - t0)

    def at(values, percent):
        index = math.ceil(len(pairs) * percent / 100) - 1
        return values[index] if 0 <= index < len(values) else None

    summary = {"pairs": len(pairs)}
    for fraction, values in reached.items():
        values.sort()
        key = f"{round(fraction * 100)}pct"
        summary[key] = {
            "reached": len(values),
            "p50": at(values, 50),
            "p95": at(values, 95),
            "p99": at(values, 99),
            "max": at(values, 100),
        }
    return summary


def offline_windows(events, run_ms):
    """A host's [from_ms, until_ms) offline windows, from its Churn events as
    (ts_ms, online) in log order. A host still offline when the log ends stays
    so until the end of the run."""
    windows = []
    since = None
    for timestamp, online in events:
        if online and since is not None:
            windows.append([since, timestamp])
            since = None
        elif not online and since is None:
            since = timestamp
    if since is not None:
        windows.append([since, max(since, run_ms or since)])
    return windows


def crashes_in(windows):
    """Times a host went offline during the run; starting it offline is not one."""
    return sum(1 for start, _ in windows if start > 0)


def is_offline(windows, time_ms):
    return any(start <= time_ms < end for start, end in windows)


def availability_series(windows_by_host, hosts, run_ms, step_ms, t0):
    """[[ms after t0, percent of `hosts` online], ...] every `step_ms` of the run."""
    changes = Counter()
    for windows in windows_by_host:
        for start, end in windows:
            changes[start] += 1
            changes[end] -= 1
    times = sorted(changes)
    points = []
    offline = 0
    index = 0
    for at in range(0, int(run_ms), step_ms):
        while index < len(times) and times[index] <= at:
            offline += changes[times[index]]
            index += 1
        points.append([at - t0, round((hosts - offline) * 100 / hosts, 3)])
    return points


def catch_up_summary(times, pairs):
    """How long rejoined hosts took to hold a subnet's signatures again, over
    `pairs` (rejoin, subnet) pairs of which `times` (ms after the rejoin) got
    there. Percentiles and the CDF count the others as never."""
    times = sorted(times)

    def at(percent):
        index = math.ceil(pairs * percent / 100) - 1
        return times[index] if 0 <= index < len(times) else None

    cdf = [[time_ms, round((index + 1) * 100 / pairs, 4)] for index, time_ms in enumerate(times)]
    if len(cdf) > MAX_CDF_POINTS:
        step = (len(cdf) - 1) / (MAX_CDF_POINTS - 1)
        cdf = [cdf[round(index * step)] for index in range(MAX_CDF_POINTS)]
    return {"rejoins": pairs, "caught_up": len(times), "p50": at(50), "p95": at(95), "cdf": cdf}


def churn_summary(hosts, experiment, churn_events, sent_times, signers_by_subnet, sent_by_node,
                  received_by_node_subnet, relearned, threshold_fraction, t0):
    """What churn did to the run, or None for a run without churny hosts.

    Offline windows come from the hosts' Churn events (the manifest's drawn
    windows for a churny host that logged none). Reports each class's settings
    and what they imply, its hosts online at the median signing time, crashes,
    rejoins and signatures missed (validators that never signed), the share of
    hosts online over the run, how long a host that rejoined after the last
    signature was sent took to hold the local threshold of each of its subnets
    again, and subnet completion for stable and churny hosts apart.
    """
    churny = {node_id for node_id, host in hosts.items() if host.get("churny")}
    if not churny:
        return None
    run_ms = (number(experiment.get("run_timeout_secs")) or 0) * 1000
    if not run_ms:
        run_ms = max((timestamp for events in churn_events.values() for timestamp, _ in events), default=0)
    offline = {
        node_id: offline_windows(churn_events[node_id], run_ms) if node_id in churn_events
        else [list(window) for window in hosts[node_id].get("offline_windows_ms") or []]
        for node_id in sorted(churny)
    }
    tick_ms = integer(experiment.get("churn_tick_ms")) or 100
    signing_ms = median(sent_times)
    sent_validators = {int(key.split(":")[1]) for keys in signers_by_subnet.values() for key in keys if key.startswith("validator:")}
    committee = None
    if integer(experiment.get("validator_count")) and integer(experiment.get("subnet_count")):
        committee = max(1, experiment["validator_count"] // experiment["subnet_count"])

    def online_at_signing(node_ids):
        if signing_ms is None:
            return None
        return sum(1 for node_id in node_ids if not is_offline(offline.get(node_id, ()), signing_ms))

    def missed(node_ids):
        return sum(1 for node_id in node_ids for validator in hosts[node_id].get("validator_ids") or [] if validator not in sent_validators)

    settings = {}
    classes = []
    for kind in CHURN_CLASSES:
        members = [node_id for node_id, host in hosts.items() if node_class(host) == kind]
        leave = number(experiment.get(f"{kind}_churn_leave_probability"))
        rejoin = number(experiment.get(f"{kind}_churn_rejoin_probability"))
        fraction = number(experiment.get(f"{kind}_churn_fraction"))
        if fraction is not None:
            settings[kind] = {
                "fraction": fraction, "leave_probability": leave, "rejoin_probability": rejoin,
                "mean_session_ms": tick_ms / leave if leave else None,
                "mean_gap_ms": tick_ms / rejoin if rejoin else None,
                "availability": rejoin / (leave + rejoin) if leave is not None and rejoin else None,
            }
        if not members:
            continue
        own = [node_id for node_id in members if node_id in churny]
        classes.append({
            "class": kind,
            "hosts": len(members),
            "churny": len(own),
            "online_at_signing": online_at_signing(members),
            "crashes": sum(crashes_in(offline[node_id]) for node_id in own),
            "rejoins": sum(1 for node_id in own for _, end in offline[node_id] if end < run_ms),
            "validators": sum(len(hosts[node_id].get("validator_ids") or []) for node_id in members),
            "churny_validators": sum(len(hosts[node_id].get("validator_ids") or []) for node_id in own),
            "missed_signatures": missed(members),
        })

    step_ms = max(tick_ms, math.ceil(run_ms / MAX_AVAILABILITY_POINTS / tick_ms) * tick_ms) if run_ms else tick_ms
    availability = {"all": availability_series(offline.values(), len(hosts), run_ms, step_ms, t0)}
    for row in classes:
        if row["churny"]:
            windows = [offline[node_id] for node_id in churny if node_class(hosts[node_id]) == row["class"]]
            availability[row["class"]] = availability_series(windows, row["hosts"], run_ms, step_ms, t0)

    # Catch-up: every stretch online that began after the last signature was sent.
    fraction = threshold_fraction or 0.9
    signed_by = max(sent_times, default=None)
    caught = defaultdict(list)
    pairs = Counter()
    for node_id in sorted(churny):
        host = hosts[node_id]
        subnets = sorted(set(host.get("subscribed_subnets") or host.get("signing_subnets") or ()) | set(host.get("aggregated_subnets") or ()))
        windows = offline[node_id]
        for index, (_, joined) in enumerate(windows):
            if signed_by is None or joined < signed_by or joined >= run_ms:
                continue
            until = windows[index + 1][0] if index + 1 < len(windows) else run_ms
            for subnet in subnets:
                signers = len(signers_by_subnet.get(subnet, ()))
                needed = math.ceil(signers * fraction - 1e-9)
                if not needed:
                    continue
                held = sorted(
                    time_ms
                    for time_ms in list(received_by_node_subnet.get((node_id, subnet), {}).values()) + relearned.get((node_id, subnet), [])
                    if joined <= time_ms < until
                )
                kind = node_class(host)
                pairs[kind] += 1
                if len(held) >= needed:
                    caught[kind].append(held[needed - 1] - joined)
    catch_up = {kind: catch_up_summary(caught[kind], pairs[kind]) for kind in NODE_CLASSES if pairs[kind]}

    # Per subnet: its churny subscribers, those online at signing, and the signatures its committee missed.
    subnets = {}
    missed_by_subnet = Counter()
    if committee:
        last = integer(experiment.get("subnet_count")) - 1
        for host in hosts.values():
            for validator in host.get("validator_ids") or []:
                if validator not in sent_validators:
                    missed_by_subnet[min(validator // committee, last)] += 1
    subscribers = defaultdict(list)
    for node_id, host in hosts.items():
        for subnet in host.get("subscribed_subnets") or []:
            subscribers[subnet].append(node_id)
    for subnet, node_ids in subscribers.items():
        subnets[subnet] = {
            "churny": sum(1 for node_id in node_ids if node_id in churny),
            "online_at_signing": online_at_signing(node_ids),
            "missed_signatures": missed_by_subnet[subnet] if committee else None,
        }

    def completion(node_ids):
        return subnet_completion({node_id: hosts[node_id] for node_id in node_ids}, received_by_node_subnet,
                                 sent_by_node, signers_by_subnet, t0)

    return {
        "tick_ms": tick_ms,
        "idle_timeout_ms": QUIC_IDLE_TIMEOUT_MS,
        "settings": settings,
        "hosts": len(hosts),
        "churny_hosts": len(churny),
        "online_at_signing": online_at_signing(hosts),
        "signing_ms": signing_ms,
        "missed_signatures": missed(hosts),
        "classes": classes,
        "availability": availability,
        "catch_up_fraction": fraction,
        "catch_up": catch_up,
        "completion": {"stable": completion(sorted(set(hosts) - churny)), "churny": completion(sorted(churny))},
        "offline_ms": offline,
        "subnets": subnets,
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

        transport_dir = root / "transport"
        stdout = transport_dir / "shadow.data" / "hosts" / "host-1" / "stdout"
        stdout.parent.mkdir(parents=True)
        stdout.write_text("\n".join((
            '{"event":"SigSent","node_id":0,"validator_id":0,"subnet_id":0,"seq":0,"ts_ms":100,"byte_size":10}',
            '{"event":"SigReceived","node_id":1,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":120,"byte_size":10}',
            '{"event":"SigReceived","node_id":2,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":130,"byte_size":12,"via":"pull"}',
            '{"event":"SigReceived","node_id":3,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":140,"byte_size":0,"via":"coded"}',
            '{"event":"SigReceived","node_id":3,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":true,"ts_ms":150,"byte_size":10}',
            '{"event":"TransportStats","node_id":1,"have_bytes_sent":5,"coded_bytes_sent":40,"idontwant_bytes_sent":3,"acks_sent":2}',
            '{"event":"TransportStats","node_id":2,"want_bytes_sent":4,"ihave_bytes_sent":1}',
            '{"event":"SigReceived","node_id":4,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":125,"byte_size":18,"via":"bundle"}',
            '{"event":"SigReceived","node_id":4,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":true,"ts_ms":126,"byte_size":18,"via":"bundle"}',
            '{"event":"SigReceived","node_id":5,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":400,"byte_size":18,"via":"requested"}',
            '{"event":"SigReceived","node_id":5,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":true,"ts_ms":401,"byte_size":18,"via":"backlog"}',
            '{"event":"TransportStats","node_id":4,"bundle_framing_bytes_sent":6,"metadata_bytes_sent":7,"pushes_avoided":3}',
        )), encoding="utf-8")
        signature_transport = build_snapshot(transport_dir)["metrics"]["signature_transport"]
        assert signature_transport["deliveries"]["gossip"] == {"unique": 1, "duplicate": 1, "bytes": 20}
        assert signature_transport["deliveries"]["pull"]["bytes"] == 12
        assert signature_transport["deliveries"]["coded"]["unique"] == 1
        wire = signature_transport["wire_bytes"]
        assert (wire["gossip_signatures"], wire["pulled_signatures"], wire["coded_packets"]) == (20, 12, 40)
        assert (wire["bitmaps"], wire["pull_requests"], wire["gossip_control"], wire["sync_acks"]) == (5, 4, 4, 2)
        assert signature_transport["deliveries"]["bundle"] == {"unique": 1, "duplicate": 1, "bytes": 36}
        assert signature_transport["deliveries"]["requested"]["unique"] == 1
        assert signature_transport["deliveries"]["backlog"] == {"unique": 0, "duplicate": 1, "bytes": 18}
        assert (wire["bundled_signatures"], wire["bundle_framing"], wire["parts_metadata"]) == (72, 6, 7)
        assert wire["total"] == 87 + 72 + 6 + 7
        assert signature_transport["counters"]["pushes_avoided"] == 3
        assert signature_transport["hosts"] == 3

        # Churn: host 1 crashes at 300 ms and is back at 500 ms with nothing. The
        # signature it gets again is neither a first copy nor a duplicate, its
        # second proof of the subnet is not counted, and its two sessions' stats
        # are one host's. Host 2 starts offline and is back before signing.
        churn_dir = root / "churn"
        stdout = churn_dir / "shadow.data" / "hosts" / "host-1" / "stdout"
        stdout.parent.mkdir(parents=True)
        stdout.write_text("\n".join((
            '{"event":"SigSent","node_id":0,"validator_id":0,"subnet_id":0,"seq":0,"ts_ms":100,"byte_size":10}',
            '{"event":"SigReceived","node_id":1,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":120,"byte_size":10}',
            '{"event":"LocalProofGenerated","node_id":1,"subnet_id":0,"sig_count":1,"latency_ms":150}',
            '{"event":"TransportStats","node_id":1}',
            '{"event":"Churn","node_id":1,"online":false,"ts_ms":300}',
            '{"event":"Churn","node_id":1,"online":true,"ts_ms":500}',
            '{"event":"SigReceived","node_id":1,"from_id":0,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":560,"byte_size":10,"via":"pull"}',
            '{"event":"LocalProofGenerated","node_id":1,"subnet_id":0,"sig_count":1,"latency_ms":600}',
            '{"event":"TransportStats","node_id":1,"restart_notices_sent":1}',
            '{"event":"Churn","node_id":2,"online":false,"ts_ms":0}',
            '{"event":"Churn","node_id":2,"online":true,"ts_ms":50}',
        )), encoding="utf-8")
        (churn_dir / "run-manifest.json").write_text(json.dumps({
            "experiment": {"local_threshold": 1.0, "run_timeout_secs": 1, "validator_count": 3, "subnet_count": 1,
                           "regular_churn_fraction": 1.0, "regular_churn_leave_probability": 0.01,
                           "regular_churn_rejoin_probability": 0.05},
            "nodes": [
                {"node_id": 0, "supernode": True, "validator_ids": [0], "subscribed_subnets": [0]},
                {"node_id": 1, "supernode": False, "validator_ids": [1], "subscribed_subnets": [0], "aggregated_subnets": [0]},
                {"node_id": 2, "supernode": False, "validator_ids": [2], "subscribed_subnets": [0]},
            ],
        }), encoding="utf-8")
        churn_metrics = build_snapshot(churn_dir)["metrics"]
        churn = churn_metrics["churn"]
        assert churn_metrics["signature_transport"]["deliveries"]["pull"] == {"unique": 0, "duplicate": 0, "bytes": 10}
        assert churn_metrics["signature_transport"]["hosts"] == 1
        assert churn_metrics["unique_signature_events"] == 1
        assert churn["counters"]["relearned"]["pull"] == 1 and churn["counters"]["repeated_proofs"] == 1
        assert [proof[:2] for proof in churn_metrics["subnet_proofs"][0]["proofs"]] == [[50, 1]]
        assert (churn["churny_hosts"], churn["online_at_signing"], churn["missed_signatures"]) == (2, 3, 2)
        regular = churn["classes"][1]
        assert (regular["class"], regular["crashes"], regular["rejoins"]) == ("regular", 1, 2)
        assert churn["catch_up"]["regular"] == {"rejoins": 1, "caught_up": 1, "p50": 60, "p95": 60, "cdf": [[60, 100.0]]}
        assert build_snapshot(transport_dir)["metrics"]["churn"] is None

        # Three hosts in a triangle mesh on one subnet, and host 9 publishing two
        # signatures into it from outside (fanout) to hosts 1 and 2. Each signature
        # crosses the three links four times: one link carries it both ways.
        mesh_dir = root / "mesh"
        stdout = mesh_dir / "shadow.data" / "hosts" / "host-1" / "stdout"
        stdout.parent.mkdir(parents=True)
        received = []
        for validator in (0, 1):
            received += [(1, False), (2, False), (3, False), (1, True), (2, True), (3, True)]
        stdout.write_text("\n".join(
            [f'{{"event":"MeshDegree","node_id":{node},"subnet_id":0,"peers":2,"at":"signing","ts_ms":90}}' for node in (1, 2, 3)]
            + ['{"event":"MeshDegree","node_id":1,"subnet_id":0,"peers":3,"at":"exit","ts_ms":900}',
               '{"event":"MeshDegree","node_id":1,"subnet_id":0,"peers":2,"at":"sometime","ts_ms":900}']
            + [f'{{"event":"SigSent","node_id":9,"validator_id":{validator},"subnet_id":0,"seq":0,"ts_ms":100,"byte_size":10}}' for validator in (0, 1)]
            + [f'{{"event":"SigReceived","node_id":{node},"from_id":9,"validator_id":{index // 6},"subnet_id":0,"duplicate":{str(duplicate).lower()},"ts_ms":120,"byte_size":10}}'
               for index, (node, duplicate) in enumerate(received)]
            + ['{"event":"TransportStats","node_id":9,"fanout_sigs_sent":4}']
        ), encoding="utf-8")
        mesh = build_snapshot(mesh_dir)["metrics"]["mesh"]
        assert mesh["degree"]["signing"] == {"count": 3, "mean": 2.0, "min": 2, "p50": 2, "max": 2, "histogram": {"2": 3}}
        assert mesh["degree"]["exit"]["max"] == 3
        assert (mesh["links"], mesh["links_sampled_at"], mesh["fanout_copies"]) == (3.0, "signing", 4)
        # 12 copies received, 4 from the publisher: 8 on 3 links x 2 signatures.
        assert (mesh["link_copies"], mesh["link_copies_min"], mesh["crossing_copies"]) == (8, 6.0, 2.0)
        assert abs(mesh["copies_per_link"] - 8 / 6) < 1e-9
        assert mesh["push_duplicates_per_first_copy"] == 1.0
        assert abs(mesh["one_copy_per_link_duplicates_per_first_copy"] - 4 / 6) < 1e-9
        assert build_snapshot(transport_dir)["metrics"]["mesh"] is None

        # Subnet completion: in subnet 0 validators 0 (host 1's own, signed at 100),
        # 1 (host 3's, at 110) and 2 (host 4's, at 105) sign. Host 1 completes at 170,
        # host 2 at 180; host 4 lists no subscriptions, so it counts in the subnet it
        # signs in, where it never gets the others.
        completion_dir = root / "completion"
        stdout = completion_dir / "shadow.data" / "hosts" / "host-1" / "stdout"
        stdout.parent.mkdir(parents=True)
        stdout.write_text("\n".join((
            '{"event":"SigSent","node_id":1,"validator_id":0,"subnet_id":0,"seq":0,"ts_ms":100,"byte_size":10}',
            '{"event":"SigSent","node_id":3,"validator_id":1,"subnet_id":0,"seq":0,"ts_ms":110,"byte_size":10}',
            '{"event":"SigSent","node_id":4,"validator_id":2,"subnet_id":0,"seq":0,"ts_ms":105,"byte_size":10}',
            '{"event":"SigReceived","node_id":1,"from_id":3,"validator_id":1,"subnet_id":0,"duplicate":false,"ts_ms":160,"byte_size":10}',
            '{"event":"SigReceived","node_id":1,"from_id":4,"validator_id":2,"subnet_id":0,"duplicate":false,"ts_ms":170,"byte_size":10}',
            '{"event":"SigReceived","node_id":2,"from_id":1,"validator_id":0,"subnet_id":0,"duplicate":false,"ts_ms":130,"byte_size":10}',
            '{"event":"SigReceived","node_id":2,"from_id":1,"validator_id":0,"subnet_id":0,"duplicate":true,"ts_ms":135,"byte_size":10}',
            '{"event":"SigReceived","node_id":2,"from_id":3,"validator_id":1,"subnet_id":0,"duplicate":false,"ts_ms":150,"byte_size":10}',
            '{"event":"SigReceived","node_id":2,"from_id":4,"validator_id":2,"subnet_id":0,"duplicate":false,"ts_ms":180,"byte_size":10}',
        )), encoding="utf-8")
        (completion_dir / "run-manifest.json").write_text(json.dumps({
            "experiment": {"local_threshold": 0.9},
            "nodes": [
                {"node_id": 1, "subscribed_subnets": [0], "aggregated_subnets": []},
                {"node_id": 2, "subscribed_subnets": [0, 5], "aggregated_subnets": []},
                {"node_id": 3, "subscribed_subnets": [], "aggregated_subnets": []},
                # No subscriptions listed: in the subnet it signs in, where it holds
                # its own signature but never gets validator 0's.
                {"node_id": 4, "signing_subnets": [0]},
            ],
        }), encoding="utf-8")
        completion = build_snapshot(completion_dir)["metrics"]["subnet_completion_ms"]
        # Subnet 5 has no signers, so three pairs. 90% of 3 signers is all three; the
        # pair that never gets there counts as infinitely late.
        assert completion["pairs"] == 3
        assert completion["90pct"] == {"reached": 2, "p50": 80, "p95": None, "p99": None, "max": None}
        assert completion["100pct"] == completion["90pct"]
        assert build_snapshot(transport_dir)["metrics"]["subnet_completion_ms"] is None

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
