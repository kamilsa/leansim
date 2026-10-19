use anyhow::Result;
use libp2p::gossipsub::IdentTopic;
use rand::Rng;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::messages::wire::WireMessage;
use crate::metrics::events::{emit, JsonlEvent};
use crate::network::swarm::{self, GossipsubBehaviour};
use crate::network::topics;
use crate::node::state::NodeState;
use libp2p::Swarm;

/// Validator init: sleep burst_time + random jitter, then publish one synthetic signature
/// per validator on this host. Co-located validators share the host's clock, so they sign
/// back to back after a single delay.
pub async fn validator_init(
    state: &Arc<NodeState>,
    swarm: &mut Swarm<GossipsubBehaviour>,
) -> Result<()> {
    let config = &state.config;

    let jitter = {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..=config.burst_jitter_ms)
    };
    let delay = Duration::from_millis(config.burst_time_ms + jitter);
    tokio::time::sleep(delay).await;

    for &validator_id in &state.validator_ids {
        let subnet_id = config.subnet_for_validator(validator_id);
        let seq = state.next_seq();
        let msg = WireMessage::ValidatorSignature {
            run_id: config.run_id.clone(),
            sender_id: state.node_id,
            validator_id,
            subnet_id,
            sequence_id: seq,
            created_timestamp_ms: state.elapsed_ms(),
            padding: vec![],
        }
        .with_payload_size(config.signature_payload_bytes);

        let topic = IdentTopic::new(topics::subnet_topic(&config.run_id, subnet_id));
        swarm::publish(swarm, &topic, &msg)?;

        let byte_size = config.signature_payload_bytes as u64;
        state.bytes_sent_sig.fetch_add(byte_size, Ordering::Relaxed);
        state.msgs_sent_sig.fetch_add(1, Ordering::Relaxed);
        emit(&JsonlEvent::SigSent {
            node_id: state.node_id,
            validator_id: Some(validator_id),
            subnet_id,
            seq,
            ts_ms: state.elapsed_ms(),
            byte_size,
        });
    }

    state.sig_sent.store(true, Ordering::SeqCst);
    tracing::info!(
        "node {} published {} validator signature(s)",
        state.node_id,
        state.validator_ids.len()
    );

    Ok(())
}
