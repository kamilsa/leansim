#!/bin/bash
# Two proof rounds a 12 s slot apart (releases at 6 s and 18 s) on the 3,713-host
# 32k-mix map, every strategy of the proof propagation report plus SEACAST.
# 200 kB proofs, 64 pieces (SEACAST: 64 data + 64 parity chunks), 40 s runs.
# Sequential cases on logical CPUs 0-23; another user's Shadow holds 48-95.
set -euo pipefail
cd "$(dirname "$0")"
test "$(sha256sum < nodes_3713_mix.csv | cut -d' ' -f1)" = 226b9104a2826c35e2934b27db9b3fd26e6cc29ee71fe125ace718e936900027
test "$(sha256sum < mixed-network.toml | cut -d' ' -f1)" = 5bb32468961fd49605655c8472e97809ca11f78960be4f2e680086a805d9a825
sha256sum target/release/leansim nodes_3713_mix.csv mixed-network.toml > provenance-two-slots.sha256
OUT=output-two-slots
mkdir -p $OUT
TIMING=(--rounds 2 --slot-ms 12000 --release-ms 6000 --stagger-ms 0 --idontwant-bytes 1000)

date -u +"smoke %FT%TZ"
for lead in 500 0; do
  rm -rf $OUT/smoke-lead$lead
  python3 scripts/subnet-proof-campaign.py $OUT/smoke-lead$lead --nodes 16 --subnets 4 --copies 2 --seeds 42 --dials 3 \
    --proof-bytes 32768 --chunks 16 --seconds 30 --parallelism 4 --commitment-lead-ms $lead "${TIMING[@]}" \
    --modes announce_pull gossipsub eip8411 waggle seacast --native-binary target/release/leansim > $OUT/smoke-lead$lead.log 2>&1
done
python3 - <<'PY'
import json
runs = {lead: json.load(open(f"output-two-slots/smoke-lead{lead}/comparison.json")) for lead in (500, 0)}
for lead, rows in runs.items():
    assert len(rows) == 5, rows
    for row in rows:
        assert "Shadow completed successfully" in open(row["directory"] + "/shadow.log").read()[-4000:], row["mode"]
        assert len(row["rounds"]) == 2 and [r["release_ms"] for r in row["rounds"]] == [6000, 18000], row["mode"]
        for r in row["rounds"]:
            assert r["ready"] == r["nodes"] == 16 and r["distinct_deliveries"] == r["possible_deliveries"] == 120, (lead, r)
            assert r["pending_fetches"] == 0 and r["quic_stream_bytes"] > 0, (lead, r)
for a, b in zip(*runs.values()):
    for ra, rb in zip(a["rounds"], b["rounds"]):
        key = ("ready_p50_ms", "ready_p95_ms", "ready_last_ms")
        assert [ra[k] for k in key] == [rb[k] for k in key], (a["mode"], ra["round"])
        print(a["mode"], ra["round"], [ra[k] for k in key], round(ra["mean_sent_bytes"]))
print("smoke gate passed")
PY

COMMON=(--network-config mixed-network.toml --subnets 16 --seeds 42 43 --proof-bytes 200000 --chunks 64
        --commitment-lead-ms 500 --seconds 40 --parallelism 24 --native-binary target/release/leansim "${TIMING[@]}")
run() { local name=$1; shift; date -u +"$name start %FT%TZ"; python3 scripts/subnet-proof-campaign.py $OUT/$name "${COMMON[@]}" "$@"; }
run waggle --modes waggle --copies 1 2 4
run seacast --modes seacast --copies 1 2 4
run announce-pull --modes announce_pull --copies 1 2 4
run gossipsub-m8 --modes gossipsub --copies 1 2 4
run gossipsub-m4 --modes gossipsub --copies 4 --gossip-mesh 3 4 6
run pieces-m4 --modes eip8411 --copies 4 --gossip-mesh 3 4 6
date -u +"done %FT%TZ"
