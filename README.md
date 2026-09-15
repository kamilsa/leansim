# leansim

`leansim` simulates hierarchical validator signature aggregation over real
`rust-libp2p` QUIC and gossipsub nodes running in the
[Shadow](https://shadow.github.io/) discrete-event network simulator.

Validators publish signatures, local aggregators collect each subnet's
threshold, and global aggregators combine local proofs. Experiments can model
uniform or country-based latency, supernode bandwidth, sparse network graphs,
and gossipsub mesh settings.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- Docker for the default `docker` runner
- Rust and a Linux `shadow` executable on `PATH` for the `native` runner

The Docker runner targets `linux/arm64`, including Apple Silicon. Shadow runs
Linux binaries, so macOS users should use Docker.

## Run

The launcher defaults to `experiments/geo-128.toml`.

```bash
# Build (if needed) and run the default experiment.
uv run shadow-sim.py

# Run a specific experiment.
uv run shadow-sim.py experiments/smoke.toml

# Generate shadow.yaml, topology.gml, node TOMLs, and run-manifest.json only.
uv run shadow-sim.py experiments/smoke.toml --dry-run

# Rebuild the Docker image and discard the output directory's prior campaign.
uv run shadow-sim.py experiments/smoke.toml --rebuild --clean

# Run and serve an offline interactive report at http://0.0.0.0:4321/summary.html.
uv run shadow-sim.py experiments/smoke.toml --clean --serve

# Rebuild and serve the report from existing results without simulating.
uv run shadow-sim.py experiments/smoke.toml --serve-only

# Rebuild only the existing report.
uv run shadow-sim.py experiments/smoke.toml --summary-only

# Also generate output/netviz-trace.bctrace for the external netviz UI.
uv run shadow-sim.py experiments/smoke.toml --netviz

# Include histories from other output directories in the served report.
uv run shadow-sim.py experiments/smoke.toml --serve-only --overlay other-output
```

`--serve` appends each completed run to `runs-history.json`, writes a
self-contained `summary.html` with Plotly embedded, and serves the output
directory until Ctrl+C. The report works without a network connection after it
has been generated.

## Configure

Experiments retain leansim's original flat simulation settings and
`[network_defaults]` table. The launcher adds these tables:

```toml
[run]
# "docker" builds leansim into a Shadow image. "native" builds with cargo and
# runs the Shadow executable found on PATH. "local" is accepted as an alias.
runner = "docker"
runs = 1
parallelism = 10

[docker]
shadow_image = "kamilsa/shadow-arm:latest"
image_name = "leansim-shadow:local"
rebuild = false

[output]
dir = "output"
```

Each run uses `geo_seed + run_index` and replaces `shadow.data` in the output
directory. The launcher snapshots the resulting metrics immediately, so a
multi-run campaign is retained in `runs-history.json` even though Shadow's raw
logs are replaced on the next run.

`validator_count` is the number of signing nodes. In each subnet, the first
`local_aggregators_per_subnet` validators also collect signatures and publish
local proofs; they are not additional hosts. Global aggregators remain
dedicated hosts, so total nodes equal `validator_count + global_aggregator_count`.

The launcher validates experiment counts and thresholds before building. In
particular, `validator_count` must be divisible by `subnet_count`.

Gossipsub publication uses the normal mesh by default:

```toml
# Set to a positive value to choose this many remote local aggregators in each
# signing node's subnet. They become reciprocal gossipsub explicit peers.
gossipsub_explicit_aggregator_count = 0

# false sends local publications to mesh peers and explicit peers only. Set true
# to also publish directly to every connected subscribed peer.
gossipsub_flood_publish = false
```

The explicit aggregator count must be smaller than
`local_aggregators_per_subnet`, because local aggregators also sign and cannot
select themselves. Explicit peers are additional direct forwarding links and do
not count toward `gossipsub_mesh_n`.

## Output

For an output directory such as `output/`, a run produces:

```text
output/
├── shadow.yaml                 # generated Shadow configuration
├── topology.gml                # generated network graph
├── configs/node_<id>.toml      # one node config per simulated process
├── run-manifest.json           # actual node, country, bandwidth, and role assignments
├── run-meta.json               # runner, seed, and campaign index
├── shadow.data/hosts/.../*.stdout
├── runs-history.json           # persisted analysis snapshots
├── summary.html                # offline interactive report
└── netviz-trace.bctrace        # present when --netviz is used
```

`run-manifest.json` is the topology source of truth. The netviz exporter reads
it rather than reconstructing seeded geo or supernode assignments.

## Analysis

The generated report contains signature-arrival CDFs, threshold timing,
per-subnet local proof latency, global proof latency, duplicate traffic, and
per-node byte/message counters. It has no web framework or npm dependency.

Run the analyzer directly when needed:

```bash
uv run --group analyze python scripts/analyze.py output
uv run --group analyze python scripts/analyze.py output --serve --port 4321
uv run --group analyze python scripts/analyze.py --self-test
```

## Parameter sweeps

`sweep.py` creates one temporary experiment TOML per point and delegates each
run to `shadow-sim.py`. It writes each run beneath the selected output root and
collects the snapshots into `results.csv`.

```bash
uv run sweep.py experiments/smoke.toml \
  --param signature_payload_bytes=1024,3072,8192 \
  --param network_defaults.uplink_mbps=25,50 \
  --output sweep-output
```

## Netviz

`--netviz` produces JSONL `.bctrace` data with `decoderName: "leansim"`. Load
the trace in the external netviz Vite app. The trace uses observed forwarding
paths for mesh edges and the generated run manifest for role, country, and
bandwidth metadata.

## Development

```bash
cargo fmt --check
cargo test
uv run shadow-sim.py experiments/smoke.toml --dry-run
uv run --group analyze python scripts/analyze.py --self-test
```
