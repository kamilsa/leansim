use anyhow::Result;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::messages::wire::WireMessage;
use crate::metrics::events::{emit, JsonlEvent};
use crate::node::state::NodeState;

/// Gossipsub does not deliver a published message to its source, but a host
/// acting as an aggregator has its own validators' signatures immediately.
pub async fn record_own_signature(state: &Arc<NodeState>) -> Result<()> {
    for &validator_id in &state.validator_ids {
        if state.config.subnet_for_validator(validator_id) == state.subnet_id {
            state.received_sigs.insert(validator_id, ());
        }
    }
    maybe_complete_proof(state).await
}

/// Counts a signature from this aggregator's subnet.
pub async fn handle_message(state: &Arc<NodeState>, msg: &WireMessage) -> Result<()> {
    let WireMessage::ValidatorSignature {
        validator_id,
        subnet_id,
        ..
    } = msg;
    if *subnet_id != state.subnet_id {
        return Ok(());
    }
    state.received_sigs.insert(*validator_id, ());
    maybe_complete_proof(state).await
}

/// At the subnet threshold, waits out the simulated aggregation compute and
/// records the local proof. Proofs are not transmitted: there is no global
/// aggregation stage.
async fn maybe_complete_proof(state: &Arc<NodeState>) -> Result<()> {
    let count = state.received_sigs.len();
    let threshold = (state.validators_per_subnet() as f64 * state.config.local_threshold) as usize;
    if count < threshold || state.snark1_sent.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let compute_delay = std::time::Duration::from_secs_f64(
        count as f64 / state.config.signature_aggregation_rate as f64,
    );
    tokio::time::sleep(compute_delay).await;

    let latency_ms = state.elapsed_ms();
    emit(&JsonlEvent::LocalProofGenerated {
        node_id: state.node_id,
        subnet_id: state.subnet_id,
        sig_count: count,
        latency_ms,
    });
    tracing::info!(
        "local_aggregator {} completed LocalProof (subnet={}, sigs={}, latency_ms={})",
        state.node_id,
        state.subnet_id,
        count,
        latency_ms,
    );
    Ok(())
}
