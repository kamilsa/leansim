use std::time::Duration;

use crate::messages::wire::WireMessage;
use crate::metrics::events::{emit, JsonlEvent};
use crate::node::state::{NodeState, PendingProof};

/// Seeds every aggregated subnet with this host's own validators' signatures:
/// gossipsub does not deliver a published message back to its source.
pub fn record_own_signatures(state: &NodeState) {
    for &validator_id in &state.validator_ids {
        let subnet = state.config.subnet_for_validator(validator_id);
        record_signature(state, subnet, validator_id);
    }
}

/// Handles one gossip message on a local aggregator.
pub fn handle_message(state: &NodeState, msg: &WireMessage) {
    let WireMessage::ValidatorSignature {
        validator_id,
        subnet_id,
        ..
    } = msg;
    record_signature(state, *subnet_id, *validator_id);
}

/// Counts a signature for an aggregated subnet. At the threshold the subnet's
/// local proof is scheduled to finish after the simulated aggregation compute;
/// each subnet's proof runs independently and the host keeps relaying gossip.
pub fn record_signature(state: &NodeState, subnet: u32, validator_id: u32) {
    if !state.aggregates(subnet) {
        return;
    }
    let count = state.record_sig(subnet, validator_id);
    let threshold = (state.validators_per_subnet() as f64 * state.config.local_threshold) as usize;
    if count < threshold || !state.claim_proof(subnet) {
        return;
    }
    let compute =
        Duration::from_secs_f64(count as f64 / state.config.signature_aggregation_rate as f64);
    state.schedule_proof(PendingProof {
        due: tokio::time::Instant::now() + compute,
        subnet,
        sig_count: count,
    });
}

/// Logs every local proof whose compute has finished and returns them, so the
/// caller can announce them to their layer-1 group.
pub fn complete_due_proofs(state: &NodeState) -> Vec<PendingProof> {
    let done = state.take_due_proofs(tokio::time::Instant::now());
    for proof in &done {
        let latency_ms = state.elapsed_ms();
        emit(&JsonlEvent::LocalProofGenerated {
            node_id: state.node_id,
            subnet_id: proof.subnet,
            sig_count: proof.sig_count,
            latency_ms,
        });
        tracing::info!(
            "local_aggregator {} completed LocalProof (subnet={}, sigs={}, latency_ms={})",
            state.node_id,
            proof.subnet,
            proof.sig_count,
            latency_ms,
        );
    }
    done
}
