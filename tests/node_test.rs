use std::sync::atomic::Ordering;
use std::sync::Arc;

use leansim::config::experiment::{ExperimentConfig, NetworkDefaults, NodeRole};
use leansim::messages::wire::WireMessage;
use leansim::node::state::NodeState;

fn test_config() -> ExperimentConfig {
    ExperimentConfig {
        run_id: "test".into(),
        run_timeout_secs: 60,
        validator_count: 100,
        subnet_count: 4,
        local_aggregators_per_subnet: 2,
        global_aggregator_count: 5,
        local_threshold: 0.9,
        global_proof_target: 0.66,
        burst_time_ms: 2000,
        burst_jitter_ms: 500,
        signature_aggregation_rate: 1000,
        global_aggregation_rate: 10,
        signature_payload_bytes: 3072,
        proof_payload_bytes: 131072,
        gossipsub_mesh_n_low: 4,
        gossipsub_mesh_n: 6,
        gossipsub_mesh_n_high: 12,
        gossipsub_mesh_outbound_min: 2,
        gossipsub_heartbeat_interval_ms: 1000,
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
fn received_sigs_unique_counting() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    // Insert same validator twice — only one entry in DashMap
    state.received_sigs.insert(5, ());
    state.received_sigs.insert(5, ());
    assert_eq!(state.received_sigs.len(), 1);
    state.received_sigs.insert(6, ());
    assert_eq!(state.received_sigs.len(), 2);
}

#[test]
fn threshold_not_met_below_count() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    // 25 validators per subnet, 90% threshold = 22.5 → 22 (floor for usize cast)
    let threshold = (25usize as f64 * 0.9) as usize;
    assert_eq!(threshold, 22);

    // Insert 21 sigs (below threshold)
    for i in 0..21u32 {
        state.received_sigs.insert(i, ());
    }
    assert!(state.received_sigs.len() < threshold);
}

#[test]
fn threshold_met_exactly() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    let threshold = (25usize as f64 * 0.9) as usize;
    assert_eq!(threshold, 22);

    // Insert exactly 22 sigs
    for i in 0..22u32 {
        state.received_sigs.insert(i, ());
    }
    assert!(state.received_sigs.len() >= threshold);
}

#[test]
fn snark1_sent_gate_prevents_double_publish() {
    let state = make_state(NodeRole::LocalAggregator, 0);
    // First call: should succeed (returns false = not previously set)
    let first = state.snark1_sent.swap(true, Ordering::SeqCst);
    assert!(!first);
    // Second call: should see it was already set
    let second = state.snark1_sent.swap(true, Ordering::SeqCst);
    assert!(second);
}

#[test]
fn global_aggregator_proof_tracking() {
    let state = make_state(NodeRole::GlobalAggregator, 0);
    // Insert proofs from different subnets
    state.received_proofs.insert((10, 0), 22); // sender 10, subnet 0, 22 sigs
    state.received_proofs.insert((11, 1), 20); // sender 11, subnet 1, 20 sigs
    state.received_proofs.insert((12, 0), 25); // sender 12, subnet 0 overwrites sender 10 for same subnet

    // Note: using (sender_id, subnet_id) as key — different senders in same subnet are different keys
    // So we have 3 unique entries
    assert_eq!(state.received_proofs.len(), 3);

    let total: usize = state.received_proofs.iter().map(|e| *e.value()).sum();
    assert_eq!(total, 22 + 20 + 25);
}

#[test]
fn global_threshold_calculation() {
    let _state = make_state(NodeRole::GlobalAggregator, 0);
    // 100 total validators, 66% threshold = 66
    let target = (100usize as f64 * 0.66) as usize;
    assert_eq!(target, 66);
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
