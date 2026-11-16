use leansim::config::experiment::{
    ExperimentConfig, NetworkDefaults, NodeConfig, NodeRole, SignaturePropagation, SignatureSync,
};
use leansim::network::swarm::warmup_ms;

fn base_config() -> ExperimentConfig {
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
        recursive_aggregation_time_ms: 276,
        recursive_proofs_per_child: 1,
        aggregate_proof_bytes: 262_144,
        traffic_log_bucket_ms: 100,
        gossipsub_mesh_n_low: 4,
        gossipsub_mesh_n: 6,
        gossipsub_mesh_n_high: 12,
        gossipsub_mesh_outbound_min: 2,
        gossipsub_heartbeat_interval_ms: 1000,
        gossipsub_heartbeat_initial_delay_ms: None,
        mesh_warmup_ms: None,
        gossipsub_explicit_aggregator_count: 0,
        gossipsub_flood_publish: false,
        gossipsub_gossip: true,
        gossipsub_idontwant_threshold_bytes: 0,
        signature_sync: SignatureSync::None,
        sync_interval_ms: 100,
        sync_grace_ms: 300,
        sync_pull_batch: 16,
        sync_pull_timeout_ms: 1000,
        sync_coded_degree: 0,
        sync_coded_redundancy: 1.1,
        sync_coded_per_tick: 8,
        sync_refresh_ms: 1000,
        signature_propagation: SignaturePropagation::Gossipsub,
        bundle_tick_ms: 20,
        bundle_max_signatures: 50,
        bundle_request_timeout_ms: 1000,
        bundle_request_delay_ms: 0,
        bundle_stagger_ms: 0,
        bundle_announce: false,
        churn_tick_ms: 100,
        regular_churn_fraction: 0.0,
        regular_churn_leave_probability: 0.01,
        regular_churn_rejoin_probability: 0.05,
        supernode_churn_fraction: 0.0,
        supernode_churn_leave_probability: 0.01,
        supernode_churn_rejoin_probability: 0.05,
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

#[test]
fn default_network_values() {
    let nd = NetworkDefaults::default();
    assert_eq!(nd.uplink_mbps, 50);
    assert_eq!(nd.downlink_mbps, 50);
    assert_eq!(nd.latency_ms, 50);
}

#[test]
fn valid_config_passes_validation() {
    let exp = base_config();
    exp.validate().unwrap();
}

#[test]
fn explicit_aggregator_and_flood_publish_defaults_deserialize() {
    let exp: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
"#,
    )
    .unwrap();

    assert_eq!(exp.gossipsub_explicit_aggregator_count, 0);
    assert!(!exp.gossipsub_flood_publish);
    assert!(exp.gossipsub_gossip);
}

#[test]
fn gossip_can_be_switched_off() {
    let exp: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
gossipsub_gossip = false
"#,
    )
    .unwrap();

    assert!(!exp.gossipsub_gossip);
}

#[test]
fn flood_publish_override_deserializes() {
    let exp: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
gossipsub_flood_publish = true
"#,
    )
    .unwrap();

    assert!(exp.gossipsub_flood_publish);
}

#[test]
fn empty_run_id_rejected() {
    let mut exp = base_config();
    exp.run_id = String::new();
    assert!(exp.validate().is_err());
}

#[test]
fn zero_subnet_count_rejected() {
    let mut exp = base_config();
    exp.subnet_count = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn zero_validator_count_rejected() {
    let mut exp = base_config();
    exp.validator_count = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn fewer_validators_than_subnets_rejected() {
    let mut exp = base_config();
    exp.validator_count = 3;
    exp.subnet_count = 4;
    assert!(exp.validate().is_err());
}

#[test]
fn too_many_local_aggregators_rejected() {
    let mut exp = base_config();
    exp.local_aggregators_per_subnet = 26;
    assert!(exp.validate().is_err());
}

#[test]
fn too_many_explicit_aggregators_rejected() {
    let mut exp = base_config();
    exp.gossipsub_explicit_aggregator_count = 2;
    assert!(exp.validate().is_err());
}

#[test]
fn explicit_aggregators_require_a_remote_aggregator() {
    let mut exp = base_config();
    exp.local_aggregators_per_subnet = 1;
    exp.gossipsub_explicit_aggregator_count = 1;
    assert!(exp.validate().is_err());
}

#[test]
fn invalid_local_threshold_rejected() {
    let mut exp = base_config();
    exp.local_threshold = 0.0;
    assert!(exp.validate().is_err());
    exp.local_threshold = 1.5;
    assert!(exp.validate().is_err());
}

#[test]
fn zero_aggregation_rate_rejected() {
    let mut exp = base_config();
    exp.signature_aggregation_rate = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn zero_payload_bytes_rejected() {
    let mut exp = base_config();
    exp.signature_payload_bytes = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn validators_per_subnet_rounds_down() {
    let exp = base_config();
    // 100 validators / 4 subnets = 25
    assert_eq!(exp.validators_per_subnet(), 25);
}

#[test]
fn validators_map_to_contiguous_subnets() {
    let exp = base_config();
    // 100 validators / 4 subnets = 25 per subnet
    assert_eq!(exp.subnet_for_validator(0), 0);
    assert_eq!(exp.subnet_for_validator(24), 0);
    assert_eq!(exp.subnet_for_validator(25), 1);
    assert_eq!(exp.subnet_for_validator(99), 3);
}

fn node_config(role: NodeRole, validator_ids: Vec<u32>) -> NodeConfig {
    NodeConfig {
        node_id: 7,
        role,
        subnet_id: 0,
        listen_addr: "/ip4/10.0.0.1/udp/9090/quic-v1".into(),
        seed_addrs: vec![],
        explicit_peer_addrs: vec![],
        selected_aggregator_addrs: vec![],
        validator_ids,
        subscribed_subnets: vec![],
        aggregated_subnets: vec![],
        aggregation_plan: None,
        traffic_log: false,
        offline_windows_ms: vec![],
        inbound_peer_addrs: vec![],
        experiment: base_config(),
    }
}

#[test]
fn relay_signs_nothing_and_defaults_to_no_subscriptions() {
    let node = node_config(NodeRole::Relay, vec![1, 2]);
    assert!(node.signing_validator_ids().is_empty());
}

#[test]
fn validator_less_local_aggregator_signs_nothing() {
    // An aggregator-only host (e.g. a no_validator node promoted from the node map).
    let node = node_config(NodeRole::LocalAggregator, vec![]);
    assert!(node.signing_validator_ids().is_empty());
}

#[test]
fn host_without_validator_ids_signs_as_its_node_id() {
    let node = node_config(NodeRole::Validator, vec![]);
    assert_eq!(node.signing_validator_ids(), vec![7]);
}

#[test]
fn host_signs_for_every_colocated_validator() {
    let node = node_config(NodeRole::LocalAggregator, vec![3, 40, 41]);
    assert_eq!(node.signing_validator_ids(), vec![3, 40, 41]);
}

#[test]
fn validator_ids_default_to_empty_in_node_toml() {
    let node: NodeConfig = toml::from_str(
        r#"
node_id = 2
role = "validator"
subnet_id = 0
listen_addr = "/ip4/10.0.0.3/udp/9090/quic-v1"
seed_addrs = []

[experiment]
run_id = "test"
validator_count = 4
subnet_count = 1
"#,
    )
    .unwrap();
    assert!(node.validator_ids.is_empty());
    assert_eq!(node.signing_validator_ids(), vec![2]);
}

#[test]
fn heartbeat_initial_delay_defaults_to_interval() {
    let mut exp = base_config();
    assert_eq!(exp.heartbeat_initial_delay_ms(), 1000);
    exp.gossipsub_heartbeat_initial_delay_ms = Some(5000);
    assert_eq!(exp.heartbeat_initial_delay_ms(), 5000);
}

#[test]
fn legacy_local_aggregator_aggregates_its_subnet_id() {
    let mut node = node_config(NodeRole::LocalAggregator, vec![3]);
    node.subnet_id = 2;
    assert_eq!(node.aggregated_subnets(), vec![2]);
}

#[test]
fn local_aggregator_aggregates_every_listed_committee_subnet() {
    let mut node = node_config(NodeRole::LocalAggregator, vec![3, 40]);
    node.aggregated_subnets = vec![3, 1, 3];
    assert_eq!(node.aggregated_subnets(), vec![1, 3]);
}

#[test]
fn non_aggregators_aggregate_nothing() {
    for role in [NodeRole::Validator, NodeRole::Relay] {
        let mut node = node_config(role, vec![3]);
        node.aggregated_subnets = vec![1];
        assert!(node.aggregated_subnets().is_empty(), "{role:?}");
    }
}

#[test]
fn warmup_uses_the_run_wide_value_when_set() {
    assert_eq!(warmup_ms(10, Some(3000)), 3000);
    assert_eq!(warmup_ms(500, Some(1500)), 1500);
}

#[test]
fn warmup_falls_back_to_the_host_dial_count() {
    assert_eq!(warmup_ms(200, None), 1500);
    assert_eq!(warmup_ms(201, None), 3000);
}

#[test]
fn mesh_warmup_defaults_to_unset() {
    let exp: ExperimentConfig =
        toml::from_str("run_id = \"t\"\nvalidator_count = 4\nsubnet_count = 1\n").unwrap();
    assert_eq!(exp.mesh_warmup_ms, None);
}

#[test]
fn recursive_settings_default_from_toml() {
    let exp: ExperimentConfig =
        toml::from_str("run_id = \"t\"\nvalidator_count = 4\nsubnet_count = 1\n").unwrap();
    assert_eq!(exp.recursive_aggregation_time_ms, 276);
    assert_eq!(exp.recursive_proofs_per_child, 1);
    assert_eq!(exp.aggregate_proof_bytes, 262_144);
}

#[test]
fn zero_proofs_per_child_rejected() {
    let mut exp = base_config();
    exp.recursive_proofs_per_child = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn proofs_over_the_protocol_limit_rejected() {
    let mut exp = base_config();
    exp.aggregate_proof_bytes = 8 * 1024 * 1024 + 1;
    assert!(exp.validate().is_err());
    exp.aggregate_proof_bytes = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn aggregation_plan_is_optional_in_node_toml() {
    let node: NodeConfig = toml::from_str(
        r#"
node_id = 2
role = "validator"
subnet_id = 0
listen_addr = "/ip4/10.0.0.3/udp/9090/quic-v1"
seed_addrs = []
aggregation_plan = "/tmp/aggregation-plan.json"

[experiment]
run_id = "test"
validator_count = 4
subnet_count = 1
"#,
    )
    .unwrap();
    assert_eq!(
        node.aggregation_plan.as_deref(),
        Some("/tmp/aggregation-plan.json")
    );
    assert_eq!(
        node_config(NodeRole::Validator, vec![]).aggregation_plan,
        None
    );
}

#[test]
fn traffic_logging_is_off_unless_the_config_asks() {
    let node: NodeConfig = toml::from_str(
        r#"
node_id = 2
role = "validator"
subnet_id = 0
listen_addr = "/ip4/10.0.0.3/udp/9090/quic-v1"
seed_addrs = []

[experiment]
run_id = "test"
validator_count = 4
subnet_count = 1
"#,
    )
    .unwrap();
    assert!(!node.traffic_log);
    assert_eq!(node.experiment.traffic_log_bucket_ms, 100);
    let flagged: NodeConfig = toml::from_str(
        r#"
node_id = 2
role = "validator"
subnet_id = 0
listen_addr = "/ip4/10.0.0.3/udp/9090/quic-v1"
seed_addrs = []
traffic_log = true

[experiment]
run_id = "test"
validator_count = 4
subnet_count = 1
"#,
    )
    .unwrap();
    assert!(flagged.traffic_log);
}

#[test]
fn traffic_bucket_width_must_be_positive() {
    let mut exp = base_config();
    exp.traffic_log_bucket_ms = 0;
    assert!(exp.validate().is_err());
    exp.traffic_log_bucket_ms = 100;
    assert!(exp.validate().is_ok());
}

#[test]
fn signature_sync_defaults_to_gossip_only() {
    let exp: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
"#,
    )
    .unwrap();
    assert_eq!(exp.signature_sync, SignatureSync::None);
    assert_eq!(exp.gossipsub_idontwant_threshold_bytes, 0);
    assert_eq!(exp.sync_coded_degree, 0);
    assert_eq!(exp.sync_coded_redundancy, 1.1);
}

#[test]
fn signature_sync_modes_deserialize_and_validate() {
    let exp: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
signature_sync = "coded_repair"
gossipsub_idontwant_threshold_bytes = 1000
sync_coded_degree = 1
"#,
    )
    .unwrap();
    assert_eq!(exp.signature_sync, SignatureSync::CodedRepair);
    assert_eq!(exp.gossipsub_idontwant_threshold_bytes, 1000);
    exp.validate().unwrap();

    let pull: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
signature_sync = "bitmap_pull"
"#,
    )
    .unwrap();
    assert_eq!(pull.signature_sync, SignatureSync::BitmapPull);
}

#[test]
fn signature_sync_rejects_bad_settings() {
    let mut exp = base_config();
    exp.signature_sync = SignatureSync::CodedRepair;
    exp.sync_coded_redundancy = 0.0;
    assert!(exp.validate().is_err());
    exp.sync_coded_redundancy = 1.1;
    exp.sync_interval_ms = 0;
    assert!(exp.validate().is_err());
    // Mode none ignores the sync settings.
    exp.signature_sync = SignatureSync::None;
    exp.validate().unwrap();
}

#[test]
fn signature_propagation_defaults_to_gossipsub() {
    let exp: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
"#,
    )
    .unwrap();
    assert_eq!(exp.signature_propagation, SignaturePropagation::Gossipsub);
    assert_eq!(exp.bundle_tick_ms, 20);
    assert_eq!(exp.bundle_max_signatures, 50);
    assert_eq!(exp.bundle_request_timeout_ms, 1000);
    assert_eq!(exp.bundle_request_delay_ms, 0);
    assert_eq!(exp.bundle_stagger_ms, 0);
    assert!(!exp.bundle_announce);
}

#[test]
fn bundled_propagation_deserializes_and_validates() {
    let exp: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
signature_propagation = "bundled"
bundle_tick_ms = 0
bundle_max_signatures = 8
bundle_request_delay_ms = 100
bundle_stagger_ms = 150
bundle_announce = true
"#,
    )
    .unwrap();
    assert_eq!(exp.signature_propagation, SignaturePropagation::Bundled);
    assert_eq!(exp.bundle_tick_ms, 0);
    assert_eq!(exp.bundle_max_signatures, 8);
    assert_eq!(exp.bundle_request_delay_ms, 100);
    assert_eq!(exp.bundle_stagger_ms, 150);
    assert!(exp.bundle_announce);
    exp.validate().unwrap();
}

#[test]
fn bundled_propagation_rejects_bad_settings() {
    let mut exp = base_config();
    exp.signature_propagation = SignaturePropagation::Bundled;
    exp.validate().unwrap();
    exp.signature_sync = SignatureSync::BitmapPull;
    assert!(
        exp.validate().is_err(),
        "bundles replace gossip, so no sync on top"
    );
    exp.signature_sync = SignatureSync::None;
    exp.bundle_max_signatures = 0;
    assert!(exp.validate().is_err());
    exp.bundle_max_signatures = 50;
    exp.bundle_request_timeout_ms = 0;
    assert!(exp.validate().is_err());
    exp.bundle_request_timeout_ms = 1000;
    exp.bundle_announce = true;
    assert!(exp.validate().is_err(), "announcements need a stagger");
    exp.bundle_stagger_ms = 200;
    exp.validate().unwrap();
    exp.bundle_request_timeout_ms = 0;
    // Gossipsub ignores the bundle settings.
    exp.signature_propagation = SignaturePropagation::Gossipsub;
    exp.validate().unwrap();
}

#[test]
fn churn_is_off_by_default() {
    let exp: ExperimentConfig =
        toml::from_str("run_id = \"t\"\nvalidator_count = 4\nsubnet_count = 1\n").unwrap();
    assert!(!exp.churn_enabled());
    assert_eq!(exp.churn_tick_ms, 100);
    for (fraction, leave, rejoin) in [
        (
            exp.regular_churn_fraction,
            exp.regular_churn_leave_probability,
            exp.regular_churn_rejoin_probability,
        ),
        (
            exp.supernode_churn_fraction,
            exp.supernode_churn_leave_probability,
            exp.supernode_churn_rejoin_probability,
        ),
    ] {
        assert_eq!((fraction, leave, rejoin), (0.0, 0.01, 0.05));
    }
    exp.validate().unwrap();
}

#[test]
fn each_host_class_has_churn_settings_of_its_own() {
    let exp: ExperimentConfig = toml::from_str(
        r#"
run_id = "test"
validator_count = 4
subnet_count = 1
regular_churn_fraction = 0.2
supernode_churn_leave_probability = 0.5
"#,
    )
    .unwrap();
    assert!(exp.churn_enabled());
    assert_eq!(exp.regular_churn_fraction, 0.2);
    assert_eq!(exp.regular_churn_leave_probability, 0.01);
    assert_eq!(exp.supernode_churn_fraction, 0.0, "nothing is inherited");
    assert_eq!(exp.supernode_churn_leave_probability, 0.5);
    exp.validate().unwrap();

    let mut supernodes_only = base_config();
    supernodes_only.supernode_churn_fraction = 1.0;
    assert!(supernodes_only.churn_enabled());
    supernodes_only.validate().unwrap();
}

#[test]
fn churn_rejects_bad_settings() {
    let mut exp = base_config();
    exp.regular_churn_fraction = 1.5;
    assert!(exp.validate().is_err());
    exp.regular_churn_fraction = 0.2;
    exp.validate().unwrap();
    exp.regular_churn_leave_probability = -0.1;
    assert!(exp.validate().is_err());
    exp.regular_churn_leave_probability = 0.01;
    exp.regular_churn_rejoin_probability = 0.0;
    assert!(
        exp.validate().is_err(),
        "churny hosts must be able to return"
    );
    exp.regular_churn_rejoin_probability = 0.05;
    exp.supernode_churn_rejoin_probability = 0.0;
    exp.validate().unwrap();
    exp.supernode_churn_fraction = 0.1;
    assert!(exp.validate().is_err());
    exp.supernode_churn_rejoin_probability = 2.0;
    assert!(exp.validate().is_err());
    exp.supernode_churn_rejoin_probability = 0.05;
    exp.churn_tick_ms = 0;
    assert!(exp.validate().is_err());
    exp.churn_tick_ms = 100;
    exp.gossipsub_explicit_aggregator_count = 1;
    assert!(
        exp.validate().is_err(),
        "an offline explicit aggregator fails the warmup"
    );
}

#[test]
fn online_windows_are_what_the_offline_ones_leave() {
    let mut node = node_config(NodeRole::Validator, vec![]);
    assert_eq!(node.online_windows(60_000), vec![(0, 60_000)]);
    node.offline_windows_ms = vec![[1_000, 3_000], [10_000, 10_100]];
    assert_eq!(
        node.online_windows(60_000),
        vec![(0, 1_000), (3_000, 10_000), (10_100, 60_000)]
    );
    // Offline at the start and at the end of the run.
    node.offline_windows_ms = vec![[0, 500], [59_000, 60_000]];
    assert_eq!(node.online_windows(60_000), vec![(500, 59_000)]);
    node.offline_windows_ms = vec![[0, 60_000]];
    assert!(node.online_windows(60_000).is_empty());
    // Windows past the end of the run are cut off.
    node.offline_windows_ms = vec![[50_000, 70_000], [80_000, 90_000]];
    assert_eq!(node.online_windows(60_000), vec![(0, 50_000)]);
}

#[test]
fn churn_fields_default_to_empty_in_node_toml() {
    let node: NodeConfig = toml::from_str(
        r#"
node_id = 2
role = "validator"
subnet_id = 0
listen_addr = "/ip4/10.0.0.3/udp/9090/quic-v1"
seed_addrs = []
offline_windows_ms = [[0, 300], [1200, 3400]]
inbound_peer_addrs = ["/ip4/10.0.0.4/udp/9090/quic-v1"]

[experiment]
run_id = "test"
validator_count = 4
subnet_count = 1
"#,
    )
    .unwrap();
    assert_eq!(node.offline_windows_ms, vec![[0, 300], [1200, 3400]]);
    assert_eq!(node.inbound_peer_addrs.len(), 1);
    let plain = node_config(NodeRole::Validator, vec![]);
    assert!(plain.offline_windows_ms.is_empty() && plain.inbound_peer_addrs.is_empty());
}
