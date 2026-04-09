# Signature Aggregation Simulation Report

## 1. Executive Summary
This simulation evaluated the performance of post-quantum signature aggregation for the Lean consensus mechanism using the Shadow network simulator. We compared a baseline flooding approach with an optimized Gossipsub-like protocol featuring fanout-limited propagation and IHAVE/IWANT control messages for large data (SNARKs).

## 2. Simulation Setup
- **Network**: 4 subnets, 128 validators, 16 local aggregators, 4 global aggregators.
- **Conditions**: 100 Mbps bandwidth, 50ms latency, 1% packet loss.
- **Message Sizes**: 3 KB (Signatures), 128 KB (SNARKs).
- **Topology**: Random graph with degree 8.

## 3. Results Comparison

| Metric | Baseline (Flooding) | Optimized (Fanout 3 + IHAVE/IWANT) |
| :--- | :---: | :---: |
| **Global Aggregation Latency** | ~1300 ms | ~1250 ms |
| **Average Duplicate Factor** | 13.5 | 3.3 |
| **Network Efficiency** | Very Low | High |

### 4. Key Findings
- **Duplicate Factor Reduction**: The implementation of a limited fanout (3) for signatures and an IHAVE/IWANT (advertise-before-push) mechanism for SNARKs reduced the duplicate factor by **75%** (from 13.5 to 3.3).
- **Latency Impact**: Despite the additional round-trips introduced by the IHAVE/IWANT handshake for SNARKs, the overall latency did not increase. This suggests that the bandwidth savings from avoiding redundant large message transfers compensate for the control message overhead.
- **Protocol Effectiveness**: The IHAVE/IWANT mechanism is highly effective for the 128 KB SNARK messages, preventing network congestion that would otherwise occur in a pure flooding scenario at scale.

## 5. Conclusion & Recommendations
The optimized protocol significantly improves bandwidth utilization while maintaining high performance. To reach the target duplicate factor of 1.5, further refinements such as dynamic mesh scoring or adaptive fanout could be explored. The use of QUIC as a transport proved stable and efficient under the simulated conditions once the "quinn-udp" patch was applied to handle Shadow's environment.
