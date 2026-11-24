#!/usr/bin/env python3
"""Run matched proof-only Shadow arms and summarize coverage, latency and traffic."""
import argparse
import csv
import json
import math
import random
import runpy
import shlex
import subprocess
import tomllib
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHADOW = runpy.run_path(str(ROOT / "shadow-sim.py"))
MODES = ("announce_pull", "gossipsub", "eip8411", "waggle")
DEADLINES = (1000, 2000, 4000, 6000, 8000, 12000)
IMAGE = "leansim-shadow:subnet-proofs"


def json_write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def make_case(args, seed, copies):
    case = make_network_case(args, seed, copies)
    if mesh := getattr(args, "gossip_mesh", None):
        low, target, high = mesh
        exp = case[0]
        outbound = exp["gossipsub_mesh_outbound_min"]
        if not (outbound <= low <= target <= high and 0 < target and 2 * outbound <= target):
            raise SystemExit(f"invalid mesh degrees {low}/{target}/{high} with outbound minimum {outbound}")
        # Apply after assigning peers: mixed placement uses the original mesh
        # target when choosing subnet seed connections.
        exp.update(gossipsub_mesh_n_low=low, gossipsub_mesh_n=target, gossipsub_mesh_n_high=high)
    return case


def make_network_case(args, seed, copies):
    if getattr(args, "network_config", None):
        return make_mixed_case(args, seed, copies)
    exp = SHADOW["experiment_defaults"]({
        "run_id": "pq-subnet-proofs", "validator_count": args.nodes, "subnet_count": args.subnets,
        "local_aggregators_per_subnet": copies, "geo_seed": seed, "use_geo_latency": True,
        "run_timeout_secs": args.seconds, "aggregate_proof_bytes": args.proof_bytes,
        "gossipsub_mesh_n": 8, "gossipsub_mesh_n_low": 4, "gossipsub_mesh_n_high": 12,
        "gossipsub_mesh_outbound_min": 2, "gossipsub_heartbeat_interval_ms": 300,
        "gossipsub_idontwant_threshold_bytes": args.idontwant_bytes,
        "network_defaults": {"uplink_mbps": 25, "downlink_mbps": 50, "latency_ms": 50},
    })
    SHADOW["validate_experiment"](exp)
    nodes = SHADOW["assign_nodes"](exp)
    countries, latency = SHADOW["assign_countries"](len(nodes), seed)
    supernodes = SHADOW["supernode_ids"](nodes, exp)
    # One dial per pair. A randomized ring guarantees a connected overlay;
    # each node also chooses `dials` random peers. Shadow directly routes each link.
    rng = random.Random(seed)
    ring = list(range(len(nodes)))
    rng.shuffle(ring)
    edges = {tuple(sorted((left, right))) for left, right in zip(ring, ring[1:] + ring[:1])}
    for source in range(len(nodes)):
        for target in rng.sample([i for i in range(len(nodes)) if i != source], args.dials):
            edges.add(tuple(sorted((source, target))))
    out = defaultdict(list)
    for left, right in sorted(edges):
        source, target = (left, right) if rng.getrandbits(1) else (right, left)
        out[source].append(target)
    for node in nodes:
        i = node["node_id"]
        node.update(country=countries[i], seed_addrs=[nodes[j]["listen_addr"] for j in out[i]],
                    uplink_mbps=1000 if i in supernodes else 25, downlink_mbps=1000 if i in supernodes else 50)
    # Spread producers across link speeds by drawing from each synthetic committee.
    count = len(nodes) // args.subnets
    producers = [{"subnet": subnet, "producer": node} for subnet in range(args.subnets)
                 for node in sorted(rng.sample(range(subnet * count, (subnet + 1) * count), copies))]
    return exp, nodes, latency, producers, sorted(edges)


def make_mixed_case(args, seed, copies):
    config = args.network_config.resolve()
    exp = {k: v for k, v in tomllib.loads(config.read_text()).items() if k not in SHADOW["RUNNER_SECTIONS"]}
    if not exp.get("node_map") or not exp.get("all_hosts") or exp.get("subnet_count") != args.subnets:
        raise SystemExit("mixed network requires node_map, all_hosts, and matching subnet_count")
    exp.update(node_map=str(config.parent / exp["node_map"]), run_id="pq-subnet-proofs",
               geo_seed=seed, run_timeout_secs=args.seconds, aggregate_proof_bytes=args.proof_bytes,
               gossipsub_idontwant_threshold_bytes=args.idontwant_bytes)
    exp = SHADOW["experiment_defaults"](exp)
    SHADOW["validate_experiment"](exp)
    nodes = SHADOW["assign_nodes"](exp)
    countries, latency = SHADOW["assign_countries"](len(nodes), seed) if exp["use_geo_latency"] else ([None] * len(nodes), None)
    supernodes = SHADOW["supernode_ids"](nodes, exp)
    by_addr = {node["listen_addr"]: node["node_id"] for node in nodes}
    edges = set()
    for node, country in zip(nodes, countries):
        i = node["node_id"]
        node["country"] = country
        for direction in ("uplink", "downlink"):
            field = f"{direction}_mbps"
            node[field] = exp[f"supernode_{field}"] if i in supernodes else exp["network_defaults"][field]
        node["explicit_peer_addrs"] = sorted(node.get("explicit_peer_addrs", []))
        dials = []
        for target in node["seed_addrs"]:
            pair = tuple(sorted((i, by_addr[target])))
            if pair not in edges:
                edges.add(pair)
                dials.append(target)
        node["seed_addrs"] = dials
    # Use the first eligible unused host in a seeded order per subnet. Select in
    # rounds so the one-producer roster is also the first round of the two-producer roster.
    rng = random.Random(seed)
    candidates = []
    for subnet in range(args.subnets):
        hosts = [node["node_id"] for node in nodes if subnet in node["signing_subnets"]]
        rng.shuffle(hosts)
        candidates.append(hosts)
    used, producers = set(), []
    for _ in range(copies):
        for subnet, hosts in enumerate(candidates):
            host = next((host for host in hosts if host not in used), None)
            if host is None:
                raise SystemExit(f"not enough distinct proof producers for subnet {subnet}")
            used.add(host)
            producers.append({"subnet": subnet, "producer": host})
    return exp, nodes, latency, producers, sorted(edges)


def generate(path, mode, case, args):
    exp, nodes, latency, producers, edges = case
    path.mkdir(parents=True, exist_ok=False)
    settings = {"mode": mode, "release_ms": args.release_ms, "stagger_ms": args.stagger_ms,
                "commitment_lead_ms": args.commitment_lead_ms, "chunks": args.chunks, "producers": producers}
    json_write(path / "proof-settings.json", settings)
    json_write(path / "network.json", {"nodes": nodes, "edges": edges, "experiment": exp})
    # Physical latency graph, separate from the libp2p overlay.
    countries = [n["country"] for n in nodes] if latency is not None else None
    SHADOW["write_topology"](path / "topology.gml", nodes, exp, countries, latency)
    for node in nodes:
        config = {key: node[key] for key in ("node_id", "role", "subnet_id", "listen_addr", "seed_addrs")}
        config["experiment"] = exp
        node["config_path"] = str(path / f"node-{node['node_id']}.toml")
        SHADOW["write_toml"](Path(node["config_path"]), config)
    command = f'subnet-proof --settings {shlex.quote(str(path / "proof-settings.json"))}'
    binary = str(getattr(args, "native_binary", None) or SHADOW["LEANSIM_BIN_DOCKER"])
    SHADOW["write_shadow_yaml"](path / "shadow.yaml", nodes, exp, binary, command=command)
    for node in nodes:
        del node["config_path"]


def run_shadow(path, image, parallelism, native_binary=None):
    command = SHADOW["shadow_command"](parallelism, False)
    if not native_binary:
        command = ["docker", "run", "--rm", "--platform", "linux/arm64", "--security-opt",
                   "seccomp=unconfined", "--shm-size", "4g", "-v", f"{path}:{path}", "-w", str(path),
                   "--entrypoint", "/bin/bash", image, "-c", shlex.join(command)]
    log_path = path / "shadow.log"
    with log_path.open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=path, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit(f"Shadow exited {result.returncode}; see {log_path}")


def percentile(values, pct):
    return sorted(values)[math.ceil(len(values) * pct) - 1] if values else None


def summarize(path):
    settings = json.loads((path / "proof-settings.json").read_text())
    network = json.loads((path / "network.json").read_text())
    exp = network["experiment"]
    nodes = {n["node_id"] for n in network["nodes"]}
    subnets = set(range(exp["subnet_count"]))
    proofs = {(p["subnet"], p["producer"]) for p in settings["producers"]}
    release, completion, traffic = {}, {}, {}
    for stdout in (path / "shadow.data" / "hosts").glob("node-*/*.stdout"):
        for line in stdout.read_text().splitlines():
            if not line.startswith('{"'):
                continue
            event = json.loads(line)
            node = event["node_id"]
            assert node == int(stdout.parent.name.removeprefix("node-"))
            kind = event["event"]
            if kind == "proof_traffic":
                assert node not in traffic
                traffic[node] = event
                continue
            subnet, producer = event["subnet"], event["producer"]
            assert (subnet, producer) in proofs
            if kind == "proof_release":
                assert node == producer and (subnet, producer) not in release
                release[subnet, producer] = event["ms"]
            elif kind == "proof_complete":
                assert (node, subnet, producer) not in completion
                completion[node, subnet, producer] = event["ms"]
    assert set(traffic) == nodes, f"missing host traffic in {path}"
    assert set(release) == proofs, f"missing producers in {path}"
    assert all((p, s, p) in completion for s, p in proofs), f"missing local proof in {path}"
    origin = min(release.values())
    first = defaultdict(dict)
    deliveries = []
    for (node, subnet, producer), ms in completion.items():
        assert ms >= release[subnet, producer], "completion precedes release"
        first[node][subnet] = min(first[node].get(subnet, math.inf), ms)
        if node != producer:
            deliveries.append(ms - release[subnet, producer])
    ready = {node: max(times.values()) - origin for node, times in first.items() if set(times) == subnets}
    with (path / "receivers.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["node_id", "ready_ms", "subnets_received", "quic_stream_bytes_sent", "connected_peers"])
        writer.writerows((node, ready.get(node), len(first[node]), traffic[node]["bytes"], traffic[node]["peers"])
                         for node in sorted(nodes))
    sent = sum(t["bytes"] for t in traffic.values())
    assert sum(len(n["seed_addrs"]) for n in network["nodes"]) == len(network["edges"])
    return {"mode": settings["mode"], "seed": exp["geo_seed"], "nodes": len(nodes), "proofs": len(proofs),
            "proof_bytes": exp["aggregate_proof_bytes"], "edges": len(network["edges"]),
            "mean_connected_peers": sum(t["peers"] for t in traffic.values()) / len(nodes),
            "ready": len(ready), "distinct_deliveries": len(deliveries), "possible_deliveries": len(proofs) * (len(nodes) - 1),
            "ready_p50_ms": percentile(ready.values(), .50), "ready_p95_ms": percentile(ready.values(), .95),
            "ready_p99_ms": percentile(ready.values(), .99), "ready_last_ms": max(ready.values(), default=None),
            "proof_p95_ms": percentile(deliveries, .95),
            "ready_by_ms": {ms: sum(at <= ms for at in ready.values()) for ms in DEADLINES},
            "quic_stream_bytes": sent, "mean_sent_bytes": sent / len(nodes),
            "bytes_over_one_copy_per_delivery": sent / (len(proofs) * (len(nodes) - 1) * exp["aggregate_proof_bytes"]),
            "pending_fetches": sum(t["pending_fetches"] for t in traffic.values()), "directory": str(path)}


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    layout = parser.add_mutually_exclusive_group()
    layout.add_argument("--nodes", type=int)
    layout.add_argument("--network-config", type=Path, help="Existing mixed-network TOML with a node map relative to it")
    parser.add_argument("--subnets", type=int, default=16)
    parser.add_argument("--copies", type=int, nargs="+", default=[1, 2])
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43])
    parser.add_argument("--modes", choices=MODES, nargs="+", default=MODES)
    parser.add_argument("--gossip-mesh", nargs=3, type=int, metavar=("LOW", "TARGET", "HIGH"),
                        help="Override runtime GossipSub mesh degrees without changing seed connections")
    parser.add_argument("--dials", type=int, default=12)
    parser.add_argument("--proof-bytes", type=int, default=200_000)
    parser.add_argument("--chunks", type=int, default=16)
    parser.add_argument("--release-ms", type=int, default=5000)
    parser.add_argument("--stagger-ms", type=int, default=0)
    parser.add_argument("--commitment-lead-ms", type=int, default=500,
                        help="Start of the traffic count before the release; no arm sends a commitment ahead")
    parser.add_argument("--idontwant-bytes", type=int, default=1000)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--parallelism", type=int, default=8)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--base-image", default="kamilsa/shadow-arm:latest")
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--native-binary", type=Path, help="Run installed Shadow with this leansim binary instead of Docker")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.nodes = 512 if args.nodes is None else args.nodes
    if not args.network_config and not (1 <= args.subnets <= args.nodes and args.nodes % args.subnets == 0
            and 0 <= args.dials < args.nodes and max(args.copies) <= args.nodes // args.subnets):
        parser.error("invalid synthetic network parameters")
    if not (1 <= min(args.copies) and 1 <= args.chunks <= 256 and args.chunks & (args.chunks - 1) == 0
            and 1 <= args.proof_bytes <= 2 * 1024 * 1024 - 1024 and 0 <= args.stagger_ms
            and 0 <= args.commitment_lead_ms < args.release_ms < args.seconds * 1000 - args.stagger_ms):
        parser.error("invalid proof or timing parameters")
    if args.native_binary:
        args.native_binary = args.native_binary.resolve()
        if args.build or not args.native_binary.is_file():
            parser.error("--native-binary requires an existing executable and cannot be combined with --build")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if args.build:
        subprocess.run(["docker", "build", "--platform", "linux/arm64", "-f", "docker/Dockerfile",
                        "--build-arg", f"SHADOW_IMAGE={args.base_image}", "-t", args.image, "."], cwd=ROOT, check=True)
    records = []
    for copies in args.copies:
        for seed in args.seeds:
            case = make_case(args, seed, copies)
            for mode in args.modes:
                path = output / f"copies{copies}-seed{seed}-{mode}"
                print(f"Running {path.name}", flush=True)
                generate(path, mode, case, args)
                run_shadow(path, args.image, args.parallelism, args.native_binary)
                summary = summarize(path)
                json_write(path / "summary.json", summary)
                records.append(summary)
                json_write(output / "comparison.json", records)
                print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
