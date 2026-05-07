use anyhow::Result;
use libp2p::gossipsub::IdentTopic;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;

use crate::messages::wire::WireMessage;
use crate::network::swarm::{self, GossipsubBehaviour};
use crate::network::topics;
use crate::node::state::NodeState;
use libp2p::Swarm;

/// Validator init: sleep burst_time + random jitter, then publish one synthetic signature.
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

    let msg = WireMessage::ValidatorSignature {
        run_id: config.run_id.clone(),
        sender_id: state.node_id,
        subnet_id: state.subnet_id,
        sequence_id: state.next_seq(),
        created_timestamp_ms: state.elapsed_ms(),
        padding: vec![],
    }
    .with_payload_size(config.signature_payload_bytes);

    let topic = IdentTopic::new(topics::subnet_topic(&config.run_id, state.subnet_id));
    swarm::publish(swarm, &topic, &msg)?;

    state.sig_sent.store(true, std::sync::atomic::Ordering::SeqCst);
    tracing::info!("validator {} published signature", state.node_id);

    Ok(())
}
