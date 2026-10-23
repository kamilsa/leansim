use leansim::config::experiment::{ExperimentConfig, NetworkDefaults, NodeConfig, NodeRole};

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
