# Leansim: Signature Aggregation Simulation

## Project Overview
Leansim is a Rust-based network simulation tool designed to evaluate the performance of post-quantum (PQ) signature aggregation for the Lean consensus mechanism. It uses the **Shadow** discrete-event network simulator to model complex networking conditions (bandwidth, latency, packet loss) without a physical testbed.

The simulation executes real application code using the **QUIC** transport protocol (via the `quinn` crate) and a simplified, custom **Gossipsub** implementation. Cryptographic operations are simulated using artificial delays based on configurable rates.

### Key Technologies
- **Rust**: Main implementation language.
- **Shadow**: Network simulator (requires `~/.local/bin/shadow`).
- **Quinn**: QUIC transport implementation.
- **Tokio**: Asynchronous runtime.
- **Python**: Used for generating Shadow configuration files.

### Architecture
The simulation follows a hierarchical model:
1. **Subnet (Local) Aggregation**: Validators propagate 3KB PQ-signatures. Local Aggregators collect these and generate a **Local SNARK (SNARK1)** once a threshold (default 90%) is met.
2. **Global Aggregation**: Global Aggregators collect SNARK1s from all subnets and generate a **Global SNARK (SNARK2)** once the global threshold (default 2/3 + 1) is met.

## Building and Running

### Prerequisites
- Rust and Cargo installed.
- Shadow simulator installed at `~/.local/bin/shadow`.
- Python 3 for configuration generation.

### Key Commands
- **Build the project**:
  ```bash
  cargo build --release
  ```
- **Generate Shadow configuration**:
  ```bash
  # Generate for a specific subnet size (e.g., 1024 nodes)
  python3 gen_shadow_config.py 1024
  ```
- **Run the simulation**:
  ```bash
  # Clear old data and run
  rm -rf shadow.data && ~/.local/bin/shadow shadow.json > shadow.log 2>&1
  ```
- **Collect results**:
  ```bash
  # Grep for latency and message stats from node outputs
  grep -r "SIMULATION_RESULT" shadow.data/hosts/
  grep -r "SNARK1_LATENCY_MS" shadow.data/hosts/
  grep -r "NODE_STATS" shadow.data/hosts/
  ```

## Simulation Parameters
Parameters are primarily defined in `src/config.rs` and can be overridden via CLI arguments in `src/main.rs`.

- **Message Sizes**: Signature (3 KB), SNARK (128 KB).
- **Thresholds**: SNARK1 (90% of subnet), SNARK2 (66% of total signatures).
- **Network Defaults**: 100 Mbps bandwidth, 50ms latency, 1% packet loss.

## Development Conventions
- **Modularity**: Networking logic should be kept modular to allow swapping the pub/sub implementation (e.g., for libp2p).
- **Shadow Compatibility**: Use the local `patch/quinn-udp` to ensure `quinn` works correctly within the Shadow environment (resolves "Protocol not available" errors).
- **Deterministic Simulation**: Be cautious with `Instant::now()` and `tokio::time::sleep`; Shadow intercepts these to provide deterministic simulation time.
- **Result Reporting**: Nodes report results by printing specific prefixes (`SIMULATION_RESULT`, `SNARK1_LATENCY_MS`, `NODE_STATS`) to `stdout`, which Shadow captures in individual host directories under `shadow.data/hosts/`.
