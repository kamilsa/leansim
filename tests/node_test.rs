use std::sync::Arc;
use std::time::Duration;

use leansim::config::experiment::{ExperimentConfig, NetworkDefaults, NodeRole};
use leansim::messages::wire::WireMessage;
use leansim::node::state::{NodeState, PendingProof};

fn test_config() -> ExperimentConfig {
    ExperimentConfig {
        run_id: "test".into(),
        run_timeout_secs: 60,
        validator_count: 100,
        subnet_count: 4,
        local_aggregators_per_subnet: 2,
        local_threshold: 0.9,
        burst_time_ms: 2000,
        burst_jitter_ms: 500,
        signature_aggregation_rate: 1000,
        signature_payload_bytes: 3072,
        gossipsub_mesh_n_low: 4,
        gossipsub_mesh_n: 6,
        gossipsub_mesh_n_high: 12,
        gossipsub_mesh_outbound_min: 2,
        gossipsub_heartbeat_interval_ms: 1000,
        gossipsub_heartbeat_initial_delay_ms: None,
        gossipsub_explicit_aggregator_count: 0,
        gossipsub_flood_publish: false,
        network_defaults: NetworkDefaults::default(),
        use_geo_latency: false,
        geo_seed: 0,
        geo_jitter: 0.0,
        supernode_fraction: 0.0,
        supernode_uplink_mbps: 1000,
        supernode_downlink_mbps: 1000,
        topology_degree: 0,
    }
}

fn make_state(role: NodeRole, subnet_id: u32) -> Arc<NodeState> {
    Arc::new(NodeState::new(1, role, subnet_id, test_config()))
}

#[test]
fn dedup_mark_seen_first_time() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    let id = [42u8; 32];
    let was_seen = state.mark_seen(id);
    assert!(!was_seen, "first insert should not be a duplicate");
}

#[test]
fn dedup_mark_seen_second_time() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    let id = [42u8; 32];
    state.mark_seen(id);
    let was_seen = state.mark_seen(id);
    assert!(was_seen, "second insert should be a duplicate");
}

#[test]
fn duplicate_suppression_by_message_id() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    let msg = WireMessage::ValidatorSignature {
        run_id: "r".into(),
        sender_id: 10,
        validator_id: 10,
        subnet_id: 0,
        sequence_id: 1,
        created_timestamp_ms: 100,
        padding: vec![],
    };
    let id = msg.message_id();
    assert!(!state.is_duplicate(&id));
    state.mark_seen(id);
    assert!(state.is_duplicate(&id));
}

#[test]
fn seq_counter_monotonic() {
    let state = make_state(NodeRole::Validator, 0);
    let a = state.next_seq();
    let b = state.next_seq();
    let c = state.next_seq();
    assert_eq!(a, 0);
    assert_eq!(b, 1);
    assert_eq!(c, 2);
}

#[test]
fn elapsed_ms_increases() {
    let state = make_state(NodeRole::Validator, 0);
    let t1 = state.elapsed_ms();
    // Spin briefly to let time advance
    std::thread::sleep(std::time::Duration::from_millis(10));
    let t2 = state.elapsed_ms();
    assert!(t2 >= t1, "elapsed_ms should be monotonic");
}

#[test]
fn signing_subnets_cover_every_colocated_validator() {
    // 25 validators per subnet: ids 3 and 24 are in subnet 0, 30 in 1, 99 in 3.
    let state = NodeState::new(1, NodeRole::Validator, 0, test_config())
        .with_validator_ids(vec![3, 24, 30, 99]);
    assert_eq!(
        state.signing_subnets().into_iter().collect::<Vec<_>>(),
        vec![0, 1, 3]
    );
}

#[test]
fn legacy_local_aggregator_aggregates_its_subnet() {
    let state = make_state(NodeRole::LocalAggregator, 3);
    assert_eq!(state.aggregated_subnets.iter().copied().collect::<Vec<_>>(), vec![3]);
    assert!(make_state(NodeRole::Validator, 3).aggregated_subnets.is_empty());
}

#[test]
fn record_sig_counts_unique_validators_per_subnet() {
    let state = NodeState::new(1, NodeRole::LocalAggregator, 0, test_config())
        .with_aggregated_subnets(vec![0, 2]);
    assert!(state.aggregates(2));
    assert!(!state.aggregates(1));
    assert_eq!(state.record_sig(0, 5), 1);
    assert_eq!(state.record_sig(0, 5), 1);
    assert_eq!(state.record_sig(0, 6), 2);
    // Another committee's subnet keeps its own count.
    assert_eq!(state.record_sig(2, 60), 1);
}

#[test]
fn claim_proof_succeeds_once_per_subnet() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    assert!(state.claim_proof(0));
    assert!(!state.claim_proof(0));
    assert!(state.claim_proof(1));
}

#[tokio::test]
async fn due_proofs_are_taken_in_order_and_later_ones_wait() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    let now = tokio::time::Instant::now();
    let later = now + Duration::from_secs(5);
    state.schedule_proof(PendingProof { due: later, subnet: 1, sig_count: 22 });
    state.schedule_proof(PendingProof { due: now, subnet: 2, sig_count: 23 });
    state.schedule_proof(PendingProof { due: now, subnet: 0, sig_count: 24 });
    assert_eq!(state.next_proof_due(), Some(now));
    let due: Vec<u32> = state.take_due_proofs(now).iter().map(|proof| proof.subnet).collect();
    assert_eq!(due, vec![0, 2]);
    assert_eq!(state.next_proof_due(), Some(later));
}

use leansim::node::local_aggregator;

#[tokio::test]
async fn proof_is_scheduled_once_when_threshold_is_reached() {
    // 25 validators per subnet at 0.9 → threshold 22; 1000 sigs/s → 22 ms compute.
    let state = make_state(NodeRole::LocalAggregator, 0);
    for validator_id in 0..21u32 {
        local_aggregator::record_signature(&state, 0, validator_id);
    }
    assert_eq!(state.next_proof_due(), None);
    let before = tokio::time::Instant::now();
    local_aggregator::record_signature(&state, 0, 21);
    let due = state.next_proof_due().expect("proof scheduled at threshold");
    assert!(due > before && due <= before + Duration::from_millis(23), "{:?}", due - before);
    // Later signatures neither reschedule nor duplicate the proof.
    local_aggregator::record_signature(&state, 0, 22);
    let proofs = state.take_due_proofs(due);
    assert_eq!(proofs.len(), 1);
    assert_eq!((proofs[0].subnet, proofs[0].sig_count), (0, 22));
}

#[tokio::test]
async fn signatures_for_subnets_not_aggregated_are_ignored() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    for validator_id in 25..50u32 {
        local_aggregator::record_signature(&state, 1, validator_id);
    }
    assert!(state.sigs_by_subnet.get(&1).is_none());
    assert_eq!(state.next_proof_due(), None);
}

#[tokio::test]
async fn own_signatures_seed_every_aggregated_subnet() {
    let state = NodeState::new(1, NodeRole::LocalAggregator, 0, test_config())
        .with_validator_ids(vec![3, 30, 99])
        .with_aggregated_subnets(vec![0, 1]);
    local_aggregator::record_own_signatures(&state);
    assert_eq!(state.sigs_by_subnet.get(&0).unwrap().len(), 1); // validator 3
    assert_eq!(state.sigs_by_subnet.get(&1).unwrap().len(), 1); // validator 30
    assert!(state.sigs_by_subnet.get(&3).is_none()); // 99 is in subnet 3, not aggregated
}

#[test]
fn threshold_not_met_below_count() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    // 25 validators per subnet, 90% threshold = 22.5 → 22 (floor for usize cast)
    let threshold = (25usize as f64 * 0.9) as usize;
    assert_eq!(threshold, 22);
    let count = (0..21u32).map(|i| state.record_sig(0, i)).last().unwrap();
    assert!(count < threshold);
}

#[test]
fn threshold_met_exactly() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    let threshold = (25usize as f64 * 0.9) as usize;
    let count = (0..22u32).map(|i| state.record_sig(0, i)).last().unwrap();
    assert!(count >= threshold);
}
