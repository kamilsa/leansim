#!/usr/bin/env python3
"""Prepare one integrated slot; verify all stages from native Shadow events."""
import argparse
import csv
import hashlib
import json
import math
import runpy
import shlex
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIM = runpy.run_path(str(ROOT / "shadow-sim.py"))
EVENTS = {
    "SigSent", "LocalProofGenerated", "WaggleCommitteeHeld", "WaggleProposerReady",
    "WaggleGlobalGenerated", "WaggleGlobalHeld", "NodeStats", "TransportStats",
}


def load(path):
    return json.loads(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def prepare(args):
    path = args.output.resolve()
    if path.exists():
        raise SystemExit(f"output directory already exists: {path}")
    exp = tomllib.loads(args.config.read_text())
    if args.node_map is not None:
        exp["node_map"] = str(args.node_map.resolve())
    node_map = SIM["resolve_path"](exp["node_map"])
    if args.smoke:
        # Preserve the transports, signature/proof sizes and four duties per committee.
        # At this size keep all synthetic hosts on each of two subnets.
        exp.update(validator_count=128, subnet_count=2, run_id=f'{exp["run_id"]}-smoke', topology_degree=24)
    exp = SIM["experiment_defaults"](exp)
    SIM["validate_experiment"](exp)
    binary = args.binary.resolve(strict=True)
    manifest = SIM["generate_run"](exp, path, str(binary), 0, "native")
    SIM["write_run_meta"](path, manifest)
    nodes = manifest["nodes"]
    ids = {n["node_id"] for n in nodes}
    validators = [v for n in nodes for v in n["validator_ids"]]
    assert sorted(validators) == list(range(exp["validator_count"]))
    assert len(nodes) == len(ids) == len({key for key, _ in SIM["load_node_map"](node_map)})
    producers = [{"subnet": s, "producer": n["node_id"]} for n in nodes for s in n["aggregated_subnets"]]
    counts = Counter(p["subnet"] for p in producers)
    assert counts == {s: exp["local_aggregators_per_subnet"] for s in range(exp["subnet_count"])}
    # A deterministic proposer duty, sampled from the placed validator set. The
    # first proof of each committee is used, independently of its producer.
    proposer_validator = int.from_bytes(hashlib.sha256(f'leansim-proposer:{exp["geo_seed"]}'.encode()).digest()[:8], "little") % len(validators)
    proposer = next(n["node_id"] for n in nodes if proposer_validator in n["validator_ids"])
    settings = {"proposer": proposer, "proposer_validator": proposer_validator, "producers": producers}
    save(path / "pipeline-settings.json", settings)
    save(path / "provenance.json", {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                                      "node_map_sha256": hashlib.sha256(node_map.read_bytes()).hexdigest()})
    yaml = path / "shadow.yaml"
    text = yaml.read_text()
    settings_arg = shlex.quote(str(path / "pipeline-settings.json"))
    prefix = 'args: "node --config '
    assert text.count(prefix) == len(nodes)
    yaml.write_text(text.replace(prefix, f'args: "node --waggle-pipeline {settings_arg} --config '))
    print(f'{len(nodes)} hosts, {len(validators)} validators, {len(counts)} committees, {len(producers)} duties, proposer node {proposer}', flush=True)


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1] if values else None


def summarize(path):
    if "Shadow completed successfully" not in (path / "shadow.log").read_text(errors="replace"):
        raise SystemExit(f"Shadow did not finish successfully: {path / 'shadow.log'}")
    manifest = load(path / "run-manifest.json")
    settings = load(path / "pipeline-settings.json")
    exp = manifest["experiment"]
    nodes = {n["node_id"]: n for n in manifest["nodes"]}
    roster = {(p["subnet"], p["producer"]) for p in settings["producers"]}
    pnode = settings["proposer"]
    published, signed, globals_at, quic = {}, {}, {}, {}
    held = defaultdict(dict)
    variants = Counter()
    exits, transport = set(), set()
    ready, generated = [], []
    sigs = exp["validator_count"] // exp["subnet_count"]
    for file in sorted((path / "shadow.data" / "hosts").glob("*/*stdout*")):
        for line in file.open():
            if not line.startswith('{"event":') or line.split('"', 4)[3] not in EVENTS:
                continue
            event = json.loads(line)
            kind, node = event["event"], event["node_id"]
            assert node in nodes
            if kind == "SigSent":
                validator = event["validator_id"]
                assert validator not in signed and validator in nodes[node]["validator_ids"]
                assert event["byte_size"] == exp["signature_payload_bytes"] and event["subnet_id"] == validator // sigs
                signed[validator] = event["ts_ms"]
            elif kind == "LocalProofGenerated":
                key = (event["subnet_id"], node)
                assert key in roster and key not in published
                assert event["sig_count"] == int(exp["local_threshold"] * sigs)
                published[key] = event["latency_ms"]
            elif kind == "WaggleCommitteeHeld":
                key = (event["subnet_id"], event["producer"])
                assert key in roster and key not in held[node]
                held[node][key] = event["ts_ms"]
                variants[key] += 1
            elif kind == "WaggleProposerReady":
                assert node == pnode
                ready.append(event["ts_ms"])
            elif kind == "WaggleGlobalGenerated":
                assert node == pnode
                generated.append(event["ts_ms"])
            elif kind == "WaggleGlobalHeld":
                assert event["producer"] == pnode and node not in globals_at
                globals_at[node] = event["ts_ms"]
            elif kind == "NodeStats":
                assert node not in exits
                exits.add(node)
            elif kind == "TransportStats":
                assert node not in transport
                transport.add(node)
        stderr = file.with_name(file.name.replace(".stdout", ".stderr"))
        if stderr.is_file():
            for line in stderr.open():
                if line.startswith("QUIC send buffers: "):
                    n = int(file.parent.name.removeprefix("node-"))
                    assert n not in quic
                    quic[n] = sum(int(line.split()[i]) for i in (3, 8))
    assert exits == transport == nodes.keys()
    assert len(signed) == exp["validator_count"]
    assert all(at >= published[key] for proofs in held.values() for key, at in proofs.items())
    first_sig = min(signed.values())
    keys = set(range(exp["subnet_count"]))

    def readiness(variants_at):
        first = {}
        for (subnet, _), ts in variants_at.items():
            first[subnet] = min(first.get(subnet, ts), ts)
        return max(first.values()) if first.keys() == keys else None

    ready_hosts = {n: t for n, v in held.items() if (t := readiness(v)) is not None}
    assert ready == ([ready_hosts[pnode]] if pnode in ready_hosts else [])
    if generated:
        assert len(generated) == 1 and generated[0] >= ready[0] + exp["recursive_aggregation_time_ms"] - 1
        assert globals_at[pnode] >= generated[0] and min(globals_at.values()) == globals_at[pnode]
    else:
        assert not globals_at
    coverage = Counter(key[0] for key in published)
    relative = lambda t: None if t is None else t - first_sig
    summary = {
        "hosts": len(nodes), "seed": manifest["seed"], "signature_bytes": exp["signature_payload_bytes"],
        "signatures": len(signed), "signature_send_spread_ms": max(signed.values()) - first_sig,
        "first_signature_ts_ms": first_sig, "proof_bytes": exp["aggregate_proof_bytes"], "chunks": 64,
        "proof_duties": len(roster), "proofs_produced": len(published),
        "proofs_produced_by_committee": dict(sorted(coverage.items())),
        "first_proof_ms": relative(min(published.values(), default=None)),
        "last_proof_ms": relative(max(published.values(), default=None)),
        "committee_variant_deliveries": sum(variants.values()), "possible_variant_deliveries": len(roster) * len(nodes),
        "all_committee_proofs_hosts": len(ready_hosts),
        "all_committee_proofs_p95_ms": relative(percentile(list(ready_hosts.values()), .95)),
        "proposer_host": pnode, "proposer_validator": settings["proposer_validator"],
        "proposer_ready_ms": relative(ready[0]) if ready else None,
        "global_generated_ms": relative(generated[0]) if generated else None,
        "global_proof_hosts": len(globals_at),
        "global_proof_p50_ms": relative(percentile(list(globals_at.values()), .50)),
        "global_proof_p95_ms": relative(percentile(list(globals_at.values()), .95)),
        "global_proof_last_ms": relative(max(globals_at.values(), default=None)),
        "global_coverage_by_ms": {str(deadline): sum(v - first_sig <= deadline for v in globals_at.values())
                                  for deadline in (4000, 6000, 8000, 10000, 12000)},
        "exits": len(exits), "transport_reporters": len(transport),
        "quic_stream_traffic_reporters": len(quic), "quic_stream_traffic_bytes": sum(quic.values()) if quic else None,
    }
    save(path / "pipeline-summary.json", summary)
    with (path / "pipeline-receivers.csv").open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(("node_id", "committee_variants", "all_committees_ms", "global_proof_ms"))
        writer.writerows((n, len(held.get(n, {})), relative(ready_hosts.get(n)), relative(globals_at.get(n))) for n in sorted(nodes))
    print(json.dumps(summary), flush=True)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    prep = subs.add_parser("prepare")
    prep.add_argument("output", type=Path)
    prep.add_argument("--binary", type=Path, required=True)
    prep.add_argument("--config", type=Path, required=True)
    prep.add_argument("--node-map", type=Path)
    prep.add_argument("--smoke", action="store_true")
    summary = subs.add_parser("summary")
    summary.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args)
    else:
        summarize(args.output)
