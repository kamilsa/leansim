#!/bin/bash
# SEACAST proof arm on the 3,713-host 32k-mix map, matched to the published matrix:
# 1/2/4 proofs per committee x seeds 42/43, 200 kB proofs, K = 64 data chunks
# coded to N = 128 (rate 1/2), release at 5 s, 25 s run, traffic count from 4.5 s.
# Sequential cases on 24 logical CPUs (0-23); another user's Shadow holds 48-95.
set -euo pipefail
cd "$(dirname "$0")"
test "$(sha256sum < nodes_3713_mix.csv | cut -d' ' -f1)" = 226b9104a2826c35e2934b27db9b3fd26e6cc29ee71fe125ace718e936900027
test "$(sha256sum < mixed-network.toml | cut -d' ' -f1)" = 5bb32468961fd49605655c8472e97809ca11f78960be4f2e680086a805d9a825
sha256sum target/release/leansim nodes_3713_mix.csv mixed-network.toml > provenance.sha256
date -u +"smoke %FT%TZ"
rm -rf smoke-seacast smoke-waggle
python3 scripts/subnet-proof-campaign.py smoke-seacast --nodes 16 --subnets 4 --copies 2 --seeds 42 --dials 3 \
  --proof-bytes 32768 --chunks 16 --seconds 14 --parallelism 4 --modes seacast waggle \
  --native-binary target/release/leansim > smoke-seacast.log 2>&1
python3 - <<'PY'
import json
rows = json.load(open("smoke-seacast/comparison.json"))
assert len(rows) == 2, rows
for r in rows:
    assert r["ready"] == r["nodes"] == 16 and r["distinct_deliveries"] == r["possible_deliveries"] == 120, r
    assert "Shadow completed successfully" in open(r["directory"] + "/shadow.log").read()[-4000:], r["mode"]
    print(r["mode"], r["ready_p50_ms"], r["ready_p95_ms"], r["ready_last_ms"], round(r["mean_sent_bytes"]), r["chunks_signed"], r["chunks_unsigned"])
s = next(r for r in rows if r["mode"] == "seacast")["seacast"]
print(json.dumps(s))
assert s["decode_failures"] == 0 and s["chunks_invalid"] == 0 and s["chunks_unverifiable"] == 0
print("smoke gate passed")
PY
date -u +"seacast start %FT%TZ"
python3 scripts/subnet-proof-campaign.py output-seacast-c64 --network-config mixed-network.toml --subnets 16 \
  --seeds 42 43 --copies 1 2 4 --modes seacast --proof-bytes 200000 --chunks 64 \
  --release-ms 5000 --stagger-ms 0 --commitment-lead-ms 500 --idontwant-bytes 1000 --seconds 25 \
  --parallelism 24 --native-binary target/release/leansim
date -u +"done %FT%TZ"
