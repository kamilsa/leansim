#!/usr/bin/env python3
"""Pull the 32k batch's metrics from the simulation server and boil each run down to
the numbers the report uses (sweeps/32k-mix/results.json), printing a summary table.

The server's SSH host comes from LEANSIM_REMOTE; --no-pull skips the copy and
summarises what is already here.

Only the small metric files are copied (runs-history.json, run-manifest.json,
run-meta.json) into output-32k-mix/<job>/; raw logs stay on the server, or
are already deleted there.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
REMOTE = os.environ.get("LEANSIM_REMOTE", "")
REMOTE_DIR = os.environ.get("LEANSIM_REMOTE_DIR", "/home/kamilsa/dev/leansim")
LOCAL_OUT = REPO / "output-32k-mix"


def pull():
    if not REMOTE:
        sys.exit("set LEANSIM_REMOTE to the simulation server's SSH host, or pass --no-pull")
    LOCAL_OUT.mkdir(exist_ok=True)
    subprocess.run(["rsync", "-az", "-e", "ssh", "--include=*/", "--include=runs-history.json",
                    "--include=run-manifest.json", "--include=run-meta.json", "--exclude=*",
                    f"{REMOTE}:{REMOTE_DIR}/output-32k-mix/", f"{LOCAL_OUT}/"], check=True)
    subprocess.run(["rsync", "-az", "-e", "ssh", f"{REMOTE}:{REMOTE_DIR}/sweeps/32k-mix/status.tsv",
                    f"{HERE}/status.tsv"], check=True)


def status_rows():
    rows = {}
    path = HERE / "status.tsv"
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split("\t")
            rows[parts[0]] = parts
    return rows


def summarize(name, status):
    run = LOCAL_OUT / name
    history = json.loads((run / "runs-history.json").read_text())
    x = history["snapshots"][-1]["metrics"]
    experiment = json.loads((run / "run-manifest.json").read_text())["experiment"]
    st = x["signature_transport"]
    dl, c, w = st["deliveries"], st["counters"], st["wire_bytes"]
    first = x["unique_signature_events"]
    mesh = x["mesh"]
    arrivals = {r["class"]: r for r in x["arrivals"] if r["message"] == "Signatures"}
    completion = x["subnet_completion_ms"]
    payload = sum(w.get(key, 0) for key in ("gossip_signatures", "bundled_signatures", "pulled_signatures", "coded_packets"))
    duplicates = x["duplicate_signature_events"]
    pushed_dup = mesh["push_duplicates_per_first_copy"] * first
    return {
        "name": name,
        "mesh_n": experiment["gossipsub_mesh_n"],
        "propagation": experiment.get("signature_propagation", "gossipsub"),
        "signature_sync": experiment.get("signature_sync", "none"),
        "bundle_tick_ms": experiment.get("bundle_tick_ms"),
        "bundle_max_signatures": experiment.get("bundle_max_signatures"),
        "bundle_stagger_ms": experiment.get("bundle_stagger_ms"),
        "bundle_announce": experiment.get("bundle_announce"),
        "bundle_request_delay_ms": experiment.get("bundle_request_delay_ms"),
        "hosts": len(json.loads((run / "run-manifest.json").read_text())["nodes"]),
        "validators": x["unique_validators"],
        "first_copies": first,
        "dup_per_first": x["duplicate_to_unique_ratio"],
        "push_dup_per_first": mesh["push_duplicates_per_first_copy"],
        "other_dup_per_first": (duplicates - pushed_dup) / first,
        "iwant_dup_per_first": c.get("iwant_response_duplicates", 0) / first,
        "requested_dup_per_first": dl["requested"]["duplicate"] / first,
        "pulled_first_copies": (c.get("iwant_responses", 0) - c.get("iwant_response_duplicates", 0)
                                + dl["requested"]["unique"] + dl["pull"]["unique"] + dl["coded"]["unique"]),
        "delivery_regular": [arrivals["regular"][k] for k in ("p5", "p25", "p50", "p75", "p95")],
        "delivery_supernode": [arrivals["supernode"][k] for k in ("p5", "p25", "p50", "p75", "p95")],
        "completion_pairs": completion["pairs"],
        "completion90": completion["90pct"],
        "completion100": completion["100pct"],
        "wire_gb": w["total"] / 1e9,
        "overhead_gb": (w["total"] - payload) / 1e9,
        "metadata_gb": w.get("parts_metadata", 0) / 1e9,
        "gossip_control_gb": w.get("gossip_control", 0) / 1e9,
        "degree_mean": mesh["degree"]["signing"]["mean"],
        "degree_min": mesh["degree"]["signing"]["min"],
        "degree_max": mesh["degree"]["signing"]["max"],
        "degree_histogram": mesh["degree"]["signing"]["histogram"],
        "copies_per_link": mesh["copies_per_link"],
        "floor_push_dup_per_first": mesh["one_copy_per_link_duplicates_per_first_copy"],
        "fanout_copies": mesh["fanout_copies"],
        "counters": {k: c.get(k, 0) for k in (
            "ihave_ids_sent", "iwant_ids_sent", "iwant_responses", "iwant_response_duplicates",
            "idontwant_ids_sent", "forwards_suppressed", "queued_forwards_dropped",
            "bundles_sent", "bundle_sigs_sent", "pushes_avoided", "lazy_sigs_sent", "backlog_sigs_sent",
            "announce_ids_sent", "available_ids_sent", "request_ids_sent", "requested_sigs_served",
            "requests_avoided", "requests_suppressed", "requests_already_sent", "invalid_partials",
            "want_ids_sent", "pulled_received", "pulled_duplicates", "coded_sent", "coded_decoded")},
        "peak_gib": float(status[4]) if status else None,
        "wall_min": float(status[3]) if status else None,
    }


def main():
    if "--no-pull" not in sys.argv:
        pull()
    status = status_rows()
    queue = [line.strip() for line in (HERE / "queue.txt").read_text().splitlines() if line.strip()]
    results, missing = {}, []
    for name in queue:
        if status.get(name, [None, None])[1] == "ok" and (LOCAL_OUT / name / "runs-history.json").exists():
            results[name] = summarize(name, status.get(name))
        else:
            missing.append(name)
    (HERE / "results.json").write_text(json.dumps(results, indent=1) + "\n")
    print(f"{len(results)} of {len(queue)} runs collected" + (f"; not yet: {', '.join(missing)}" if missing else ""))
    head = f"{'run':<24}{'dup':>6}{'push':>6}{'pull':>6}{'deliv p50/p95':>15}{'90% p50/p95':>14}{'100% max':>9}{'GB':>7}{'links':>7}{'complete':>10}"
    print(head)
    for r in results.values():
        complete = f"{r['completion100']['reached']}/{r['completion_pairs']}"
        print(f"{r['name']:<24}{r['dup_per_first']:>6.2f}{r['push_dup_per_first']:>6.2f}{r['other_dup_per_first']:>6.2f}"
              f"{r['delivery_regular'][2]:>8}/{r['delivery_regular'][4]:<6}{r['completion90']['p50']:>7}/{r['completion90']['p95']:<6}"
              f"{r['completion100']['max'] or '-':>9}{r['wire_gb']:>7.1f}{r['copies_per_link']:>7.2f}{complete:>10}")


if __name__ == "__main__":
    main()
