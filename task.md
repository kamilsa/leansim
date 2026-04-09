# Signature Aggregation Simulation Task Definition

Based on the performance evaluation in `report.md`, this task defines the requirements and parameters for simulating post-quantum signature aggregation for the Lean consensus mechanism.

## 1. Primary Objectives
The main objective is to **measure and analyze global signature aggregation performance** under a variety of compute and network assumptions:
- **Compute Assumptions**: Evaluate the impact of different signature aggregation rates and recursive SNARK aggregation (recursion) rates on total latency.
- **Network Assumptions**:
    - **Bandwidth**: Analyze performance across different limits (e.g., 50Mbps vs. 100-200Mbps).
    - **Latency & Reliability**: Measure the impact of varying network latencies and **packet loss rates** between peers.
    - **Transport Configuration**: Evaluate performance if **QUIC** with its features.
    - **Topologies**: Compare different peer-to-peer topologies and configurations (e.g., variations in Gossipsub mesh parameters or alternatives).
- **Secondary Evaluation**: Observe the differences between Gossipsub 1.1 and 1.2 (`idontwant`) and other protocol optimizations.

## 2. Simulation Approach
This task focuses on **network simulation** using the **Shadow discrete-event network simulator** (installed at `~/.local/bin/shadow`) to accurately model different networking conditions (bandwidth, latency, packet loss, topologies) without needing a physical testbed.
- **Real Application Code & Transport**: The simulation will execute real application code using a **real QUIC implementation** as the underlying transport protocol.
- **No Real Cryptography**: Real post-quantum signature generation, aggregation, and verification are not performed.
- **Time-Based Simulation**: Cryptographic operations are simulated by introducing artificial delays (sleeps) based on the rates defined in the parameters (e.g., aggregation rate, verification time).
- **Focus**: The primary goal is to model the network overhead, bandwidth utilization, and protocol efficiency under the physical constraints of large PQ signatures.

### Implementation Note: Gossipsub
We implement a **simplified, custom Gossipsub** rather than reusing libp2p. Scoring and other advanced libp2p features are out of scope for now. However, the implementation must still support testing the efficiency of **Gossipsub control messages** (e.g., `IDONTWANT` from Gossipsub 1.2) to evaluate their impact on bandwidth in PQ-signature scenarios. The networking logic should be kept **modular** so that the underlying pub/sub implementation can be swapped out (e.g., for a libp2p-based implementation) in the future without restructuring the rest of the codebase.

## 3. Network & Aggregation Model
The model uses a hierarchical structure:
1. **Subnet (Local) Aggregation**:
   - 8 subnets, each with 1,024 validators.
   - Validators propagate 3KB PQ-signatures via the chosen topology (primarily Gossipsub).
   - **Local Aggregators** (10% of subnet validators) collect signatures and generate a **Local SNARK (SNARK1)** once the threshold (90%) is met.
2. **Global Aggregation**:
   - 100 **Global Aggregators** collect SNARK1s from the 8 subnets.
   - Once SNARK1s proving 2/3 + 1 of total signatures are collected, a **Global SNARK (SNARK2)** is generated.

## 4. Simulation Parameters (Default Configuration)
| Parameter | Value |
| :--- | :--- |
| **Network Size** | 8 subnets, 1024 validators/subnet |
| **Aggregators** | 102 local per subnet, 100 global |
| **Bandwidth (max_bitrate)** | 50 Mbps |
| **Signature Size** | 3072 bytes |
| **SNARK Size** | 128 KB |
| **SNARK1 Threshold** | 0.9 (922 signatures) |
| **SNARK2 Threshold** | 0.66 (5407 signatures) |
| **Aggregation Rate** | 1000 signatures/second |
| **Recursion Rate** | 10 SNARKs/second |
| **Verification Time** | 30μs (Signature), 2ms (SNARK) |

## 5. Protocol Optimizations to Evaluate
- **QUIC Features**:
    - **0-RTT**: Measure latency improvements from zero round-trip time connection resumption.
    - **Unreliable Datagrams**: Evaluate the use of QUIC datagrams for time-sensitive signature propagation to avoid head-of-line blocking.
- **Gossipsub 1.1 vs 1.2**: Test the effectiveness of `idontwant` control messages in high-bandwidth PQ-signature scenarios.
- **SNARK1 Early Announcement**: Local aggregators announce the start of SNARK1 generation to Global Aggregators to trigger early `IWANT` requests.
- **Pull-based SNARK Fetching**: Implementation of an efficient pull mechanism for SNARK1s to avoid redundant "Push" traffic.
- **Propagation Filtering**: Limit global aggregators to propagating only one valid SNARK1 per subnet to reduce network noise.

## 6. Performance Targets
- **Aggregation Latency**: Minimize time to reach SNARK2 completion across various network and compute conditions.
- **Duplicate Factor**: Maintain an average duplicate count below 1.5 per unique signature.
