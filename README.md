# leansim

Hierarchical signature aggregation network simulator. Runs real `rust-libp2p` (QUIC + gossipsub) binaries inside the [Shadow](https://shadow.github.io/) discrete-event network simulator.

## Prerequisites

### Natively
- Rust toolchain (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Shadow 3.3+ ([download](https://github.com/shadow/shadow/releases) or build from source — needs cmake, glib2, libclang, python3)

### Via Docker
- Docker + Docker Compose

## Build

### Natively
```bash
make build
```

### Via Docker (multi-stage cross-compile)
```bash
make docker-build
```

Builds inside `kamilsa/shadow-arm` image, then copies the binary out to `target/release/leansim`.

## Run a simulation

Pick an experiment from `experiments/`:

| Config | Validators | Aggregators | Total nodes | Latency |
|--------|-----------|-------------|-------------|---------|
| `smoke.toml` | 4 | 1 | 6 | uniform 50ms |
| `local-baseline.toml` | 32 | 1 | 33 | uniform 50ms |
| `local-bench.toml` | 128 | 8 | 136 | uniform 50ms |
| `local-256.toml` | 256 | 8 | 264 | uniform 50ms |
| `local-512.toml` | 512 | 32 | 544 | uniform 50ms |
| `local-1024.toml` | 1024 | 64 | 1088 | uniform 50ms |
| `geo-bench.toml` | 128 | 8 | 136 | country-based geo |
| `128-validators.toml` | 128 | 1 | 129 | uniform 50ms |

### Quick start with Make

```bash
# Run a simulation (generates config, runs it, produces shadow.data)
make run        # uses experiments/geo-128.toml by default

# Pick a different experiment
make run SCENARIO=experiments/smoke.toml                 # native
make docker-run SCENARIO=experiments/smoke.toml          # Docker

# Generate netviz trace from completed simulation output
make netviz                                              # native
make docker-netviz                                       # Docker
```

Configurable variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SCENARIO` | `experiments/geo-128.toml` | Experiment config |
| `OUTPUT_DIR` | `output` | Working directory for `shadow.yaml` + `shadow.data` |
| `NETVIZ_OUT` | `netviz-trace.bctrace` | Output trace filename |
| `PARALLELISM` | `10` | Number of parallel Shadow threads |

### Manual steps

```bash
# 1. Generate Shadow config and per-node TOMLs
./target/release/leansim gen-shadow \
  --experiment experiments/smoke.toml \
  --out shadow.yaml

# 2. Run the simulation (from project root — topology.gml is a relative path)
~/.local/bin/shadow shadow.yaml > shadow.log 2>&1

# 3. Generate netviz trace
./target/release/leansim netviz \
  --experiment experiments/smoke.toml \
  --shadow-data shadow.data \
  --out smoke.bctrace
```

**Note:** If step 1 fails with a path pointing to `.../netviz/target/release/leansim`, fix it:

```bash
sed -i 's|/netviz/target/release/leansim|/target/release/leansim|g' shadow.yaml
```

This happens when `gen-shadow` is run from the `netviz/` subdirectory — it uses `current_dir()` to resolve the binary path. Running from the project root avoids it.

## Visualize in netviz

```bash
cd netviz
npm install
npx vite --host 0.0.0.0
# Open http://localhost:5173/
```

Load the `.bctrace` file in the UI. The `decoderName: "leansim"` field in the trace header auto-selects the correct decoder.

Netviz shows:
- **Nodes** positioned by force-directed layout, colored by state (idle → published → receiving → aggregated)
- **Arcs** animating signature and proof messages along actual mesh edges
- **Ring overlays** per node: received signatures, duplicates, proofs
- **Message dropdown** to trace a single validator's signature through the network
- **Stats panel** with per-node metrics and CDF/race charts

## How it works

```
experiment.toml  →  gen-shadow  →  shadow.yaml + topology.gml + configs/node_*.toml
                                      │
                                shadow shadow.yaml
                                      │
                                shadow.data/hosts/*/stdout  (JSONL events)
                                      │
                                netviz  →  .bctrace
```

Each node runs `lean-sim node` inside Shadow. Validators publish synthetic signatures to a gossipsub topic. Local aggregators collect unique signatures until a threshold, then publish a proof. The gossip flooding produces duplicates — these are captured via a patched `libp2p-gossipsub` that emits a `DuplicateMessage` event instead of silently dropping them.
