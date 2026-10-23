# leansim

`leansim` simulates hierarchical validator signature aggregation over real
`rust-libp2p` QUIC and gossipsub nodes running in the
[Shadow](https://shadow.github.io/) discrete-event network simulator.

Validators publish signatures and local aggregators collect each subnet's
threshold into a local proof (computed, not transmitted: global aggregation was
removed and will be redesigned). Experiments can model
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

`validator_count` is the number of signing validators. In each subnet, the first
`local_aggregators_per_subnet` validators also collect signatures and compute
local proofs; they are not additional hosts, so there are `validator_count`
hosts unless validators share hosts (see below).

The launcher validates experiment counts and thresholds before building. In
particular, `validator_count` must be divisible by `subnet_count`.

### Several validators per physical node

As on Ethereum mainnet, one physical node can run many validators. Co-location
comes from a nodes.csv node map (below); without `node_map`, every validator
runs on its own host.

A host publishes one signature per validator it runs, back to back after a
single burst delay. Validator ids are split into contiguous subnets of
`validator_count / subnet_count`, and an aggregating host counts its own
validators' signatures immediately. Countries, supernodes, and bandwidth are
assigned per host.

### Ethereum-style node map (nodes.csv)

Set `node_map` to a nodes.csv table (`node_type, peer_key, validator_count, ...`,
one row per physical node) for a topology closer to mainnet:

```toml
validator_count = 512
node_map = "nodes.csv"                 # relative to the repo root
subnet_subscriptions_per_node = 2     # default 2
subnet_count = 8
```

`validator_count` validator slots are sampled from the map's nodes, so the
validators-per-host distribution matches the real network (a node with 20
validators is 20x more likely to receive validators than one with 1).
`no_validator` nodes are sampled on top, preserving their real share of the host
population (~20%), and run as gossip-only relays: they subscribe, forward, and
occupy bandwidth, but never sign.

Every node subscribes to `subnet_subscriptions_per_node` random subnets,
independent of the subnets its validators publish to — as on Ethereum, a
validator's attestations go to the subnet duty assigns, not the subnets its
node is subscribed to. Publishing to a non-subscribed subnet works through
gossipsub's fanout cache. With `subscribe_to_duty_subnets = true`, validator
hosts additionally subscribe to the subnets their validators publish in, so a
node's subscription count scales with the validators it runs, as beacon nodes
on mainnet (duty subnets plus the random gossip ones); relays keep the random
ones only. Local aggregators are promoted from each subnet's subscribers, so
an aggregator always collects a subnet it is subscribed to. With `node_map`,
node ids are unrelated to validator ids.

Gossipsub publication uses the normal mesh by default:

```toml
# Set to a positive value to choose this many remote local aggregators in each
# signing node's subnet. They become reciprocal gossipsub explicit peers.
gossipsub_explicit_aggregator_count = 0

# false sends local publications to mesh peers and explicit peers only. Set true
# to also publish directly to every connected subscribed peer.
gossipsub_flood_publish = false
```

The first gossipsub heartbeat fires after `gossipsub_heartbeat_initial_delay_ms`,
which defaults to `gossipsub_heartbeat_interval_ms`. Until then a node's mesh
holds only the first `gossipsub_mesh_n_low` peers to subscribe, which are its
lowest-latency neighbours, and no IHAVE gossip is sent. With libp2p's 5 s
default (set `gossipsub_heartbeat_initial_delay_ms = 5000` to reproduce it),
signatures stayed inside their region until about 5 s after start.

Every host waits the same mesh warmup before signing, so all of them vote at
once: 1,500 ms, or 3,000 ms when any host dials more than 200 peers. The
launcher derives it from the busiest host and records it as `mesh_warmup_ms`
(set it in the experiment to override). With per-host warmups, hosts past the
dial threshold signed late and dropped the gossip that reached them while
still warming up.

The explicit aggregator count must be smaller than
`local_aggregators_per_subnet`, because local aggregators also sign and cannot
select themselves. Explicit peers are additional direct forwarding links and do
not count toward `gossipsub_mesh_n`.

#### Committee aggregators

With `committee_aggregators = true` (requires `node_map`), aggregation follows
Ethereum's committee model:

- Each validator belongs to exactly one committee: `validator_count / subnet_count`
  validators per committee, as contiguous id blocks. Ids are dealt over randomly
  sampled node-map slots, so every committee is a random set of validators.
- Committee `i` attests on subnet `i` (one slot of `subnet_count` committees).
- Aggregators are picked by Ethereum's `is_aggregator` lottery: a validator wins when
  `hash(geo_seed, validator)[0:8] % max(1, committee_size / local_aggregators_per_subnet) == 0`,
  so `local_aggregators_per_subnet` is the expected number per committee. The host
  of a winning validator aggregates that committee's subnet. Hosts without
  validators never aggregate. A host with winners in several committees
  aggregates all of them; several winners on one host still make one aggregator.
- Each aggregated subnet gets its own ≥ `local_threshold` proof. Proofs compute in
  parallel (`sig_count / signature_aggregation_rate` each) without pausing the
  host's gossip. They are logged, not transmitted.

Without the flag, `local_aggregators_per_subnet` hosts are promoted among each
subnet's subscribers, one subnet per host, possibly relays.

## Output

For an output directory such as `output/`, a run produces:

```text
output/
├── shadow.yaml                 # generated Shadow configuration
├── topology.gml                # generated network graph
├── configs/node_<id>.toml      # one node config per simulated process
├── run-manifest.json           # actual node, validator, country, bandwidth, and role assignments
├── run-meta.json               # runner, seed, and campaign index
├── shadow.data/hosts/.../*.stdout
├── runs-history.json           # persisted analysis snapshots
└── summary.html                # offline interactive report
```

`run-manifest.json` is the topology source of truth: read it rather than
reconstructing seeded geo or supernode assignments.

## Analysis

The generated report contains signature-arrival CDFs, threshold timing,
per-subnet local proof latency, duplicate traffic, and
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

## Development

```bash
cargo fmt --check
cargo test
uv run shadow-sim.py experiments/smoke.toml --dry-run
uv run --group analyze python scripts/analyze.py --self-test
```
