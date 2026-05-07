use anyhow::Result;
use libp2p::gossipsub::IdentTopic;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::messages::wire::WireMessage;
use crate::metrics::events::{emit, JsonlEvent};
use crate::network::swarm::{self, GossipsubBehaviour};
use crate::network::topics;
use crate::node::state::NodeState;
use libp2p::Swarm;

/// Local aggregator: process one incoming gossipsub message.
/// If it's a ValidatorSignature from our subnet, count it. Once threshold is reached,
/// publish a LocalProof.
pub async fn handle_message(
    state: &Arc<NodeState>,
    swarm: &mut Swarm<GossipsubBehaviour>,
    msg: &WireMessage,
) -> Result<()> {
    if let WireMessage::ValidatorSignature {
        sender_id,
        subnet_id,
        ..
    } = msg
    {
        if *subnet_id != state.subnet_id {
            return Ok(());
        }

        // Track unique validators
        state.received_sigs.insert(*sender_id, ());

        let count = state.received_sigs.len();
        let threshold = (state.validators_per_subnet() as f64 * state.config.local_threshold) as usize;

        if count >= threshold {
            let already_sent = state.snark1_sent.swap(true, Ordering::SeqCst);
            if !already_sent {
                // Simulate aggregation computation time
                let compute_delay = std::time::Duration::from_secs_f64(
                    count as f64 / state.config.signature_aggregation_rate as f64,
                );
                tokio::time::sleep(compute_delay).await;

                let proof = WireMessage::LocalProof {
                    run_id: state.config.run_id.clone(),
                    sender_id: state.node_id,
                    subnet_id: state.subnet_id,
                    covered_validator_count: count,
                    sequence_id: state.next_seq(),
                    created_timestamp_ms: state.elapsed_ms(),
                    padding: vec![],
                }
                .with_payload_size(state.config.proof_payload_bytes);

                let topic = IdentTopic::new(topics::aggregation_topic(&state.config.run_id));
                swarm::publish(swarm, &topic, &proof)?;

                let latency_ms = state.elapsed_ms();
                let byte_size = proof.encode().len() as u64;
                emit(&JsonlEvent::LocalProofGenerated {
                    node_id: state.node_id,
                    subnet_id: state.subnet_id,
                    sig_count: count,
                    latency_ms,
                    byte_size,
                });
                tracing::info!(
                    "local_aggregator {} published LocalProof (subnet={}, sigs={}, latency_ms={})",
                    state.node_id,
                    state.subnet_id,
                    count,
                    latency_ms,
                );
            }
        }
    }

    Ok(())
}
