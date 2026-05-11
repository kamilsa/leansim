use leansim::config::experiment::{ExperimentConfig, NetworkDefaults};
use leansim::shadow::generator::generate_shadow_config;

fn test_experiment() -> ExperimentConfig {
    ExperimentConfig {
        run_id: "shadow-test".into(),
        run_timeout_secs: 60,
        validator_count: 8,
        subnet_count: 2,
        local_aggregators_per_subnet: 1,
        global_aggregator_count: 1,
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

#[test]
fn generate_shadow_yaml_creates_files() {
    let tmp = std::env::temp_dir().join("leansim_shadow_test");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let exp = test_experiment();
    let out = tmp.join("shadow.yaml");
    generate_shadow_config(&exp, &out).unwrap();

    // shadow.yaml should exist
    assert!(out.exists());

    // topology.gml should exist
    assert!(tmp.join("topology.gml").exists());

    // configs directory with per-node files
    let configs = tmp.join("configs");
    assert!(configs.is_dir());
    let expected_nodes = 11; // 8 validators + 2 local + 1 global
    let count = std::fs::read_dir(&configs).unwrap().count();
    assert_eq!(count, expected_nodes);

    // Each node config should be valid TOML with a NodeConfig
    for i in 0..expected_nodes {
        let path = configs.join(format!("node_{}.toml", i));
        let content = std::fs::read_to_string(&path).unwrap();
        let _: leansim::config::experiment::NodeConfig = toml::from_str(&content).unwrap();
    }

    // Shadow YAML should contain expected host entries
    let yaml = std::fs::read_to_string(&out).unwrap();
    for i in 0..expected_nodes {
        assert!(yaml.contains(&format!("node-{}", i)), "missing node-{}", i);
    }
    assert!(yaml.contains("50 Mbit"), "should contain bandwidth setting");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn network_defaults_in_shadow_yaml() {
    let tmp = std::env::temp_dir().join("leansim_net_test");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let mut exp = test_experiment();
    exp.network_defaults.uplink_mbps = 100;
    exp.network_defaults.downlink_mbps = 200;
    exp.network_defaults.latency_ms = 25;

    let out = tmp.join("shadow.yaml");
    generate_shadow_config(&exp, &out).unwrap();

    let yaml = std::fs::read_to_string(&out).unwrap();
    assert!(yaml.contains("100 Mbit"));
    assert!(yaml.contains("200 Mbit"));

    let _ = std::fs::remove_dir_all(&tmp);
}
