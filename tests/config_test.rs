use leansim::config::experiment::{ExperimentConfig, NetworkDefaults};

fn base_config() -> ExperimentConfig {
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
fn invalid_global_target_rejected() {
    let mut exp = base_config();
    exp.global_proof_target = 0.0;
    assert!(exp.validate().is_err());
    exp.global_proof_target = 1.5;
    assert!(exp.validate().is_err());
}

#[test]
fn zero_aggregation_rate_rejected() {
    let mut exp = base_config();
    exp.signature_aggregation_rate = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn zero_global_rate_rejected() {
    let mut exp = base_config();
    exp.global_aggregation_rate = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn zero_payload_bytes_rejected() {
    let mut exp = base_config();
    exp.signature_payload_bytes = 0;
    assert!(exp.validate().is_err());
    exp.signature_payload_bytes = 3072;
    exp.proof_payload_bytes = 0;
    assert!(exp.validate().is_err());
}

#[test]
fn validators_per_subnet_rounds_down() {
    let exp = base_config();
    // 100 validators / 4 subnets = 25
    assert_eq!(exp.validators_per_subnet(), 25);
}

#[test]
fn total_nodes_count() {
    let exp = base_config();
    // 100 validators, including 2 local aggregators in each subnet, + 5 global = 105
    assert_eq!(exp.total_nodes(), 105);
}
