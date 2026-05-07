use anyhow::Result;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::messages::wire::WireMessage;
use crate::metrics::events::{emit, JsonlEvent};
use crate::network::swarm::GossipsubBehaviour;
use crate::node::state::NodeState;
use libp2p::Swarm;

/// Global aggregator: process one incoming gossipsub message.
/// If it's a LocalProof, track the covered validator count per (sender, subnet).
/// Once the global proof target is reached, record completion.
pub async fn handle_message(
    state: &Arc<NodeState>,
    _swarm: &mut Swarm<GossipsubBehaviour>,
    msg: &WireMessage,
) -> Result<()> {
    if let WireMessage::LocalProof {
        sender_id,
        subnet_id,
        covered_validator_count,
        ..
    } = msg
    {
        // Dedup per (sender_id, subnet_id) — keep the latest proof from each
        let key = (*sender_id, *subnet_id);
        state.received_proofs.insert(key, *covered_validator_count);

        // Sum covered signatures across all received proofs
        let total_covered: usize = state.received_proofs.iter().map(|e| *e.value()).sum();
        let target = (state.total_validators() as f64 * state.config.global_proof_target) as usize;

        if total_covered >= target {
            let already_completed = state.snark2_completed.swap(true, Ordering::SeqCst);
            if !already_completed {
                // Simulate global aggregation computation time
                let proof_count = state.received_proofs.len();
                let compute_delay = std::time::Duration::from_secs_f64(
                    proof_count as f64 / state.config.global_aggregation_rate as f64,
                );
                tokio::time::sleep(compute_delay).await;

                let latency_ms = state.elapsed_ms();
                emit(&JsonlEvent::GlobalProofCompleted {
                    node_id: state.node_id,
                    total_sigs: total_covered,
                    proof_count,
                    latency_ms,
                });
                tracing::info!(
                    "global_aggregator {} completed GlobalProof (sigs={}, proofs={}, latency_ms={})",
                    state.node_id,
                    total_covered,
                    proof_count,
                    latency_ms,
                );
            }
        }
    }

    Ok(())
}
