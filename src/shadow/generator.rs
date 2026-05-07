use anyhow::Result;
use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::config::experiment::{ExperimentConfig, NodeConfig, NodeRole};

/// Shadow YAML top-level structure.
#[derive(Serialize)]
struct ShadowConfig {
    general: General,
    network: Network,
    hosts: std::collections::BTreeMap<String, Host>,
}

#[derive(Serialize)]
struct General {
    stop_time: String,
}

#[derive(Serialize)]
struct Network {
    graph: Graph,
}

#[derive(Serialize)]
struct Graph {
    #[serde(rename = "type")]
    graph_type: String,
    file: GraphFile,
}

#[derive(Serialize)]
struct GraphFile {
    path: String,
}

#[derive(Serialize)]
struct Host {
    network_node_id: u32,
    ip_addr: String,
    bandwidth_down: String,
    bandwidth_up: String,
    processes: Vec<Process>,
}

#[derive(Serialize)]
struct Process {
    path: String,
    args: String,
    start_time: String,
}

/// Generate shadow.yaml + topology.gml + configs/node_{id}.toml from an experiment.
pub fn generate_shadow_config(experiment: &ExperimentConfig, output: &Path) -> Result<()> {
    let parent = output.parent().unwrap_or(Path::new("."));
    let abs_parent = if parent.as_os_str().is_empty() {
        std::env::current_dir()?
    } else if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent)
    };

    // Create configs directory
    let configs_dir = abs_parent.join("configs");
    fs::create_dir_all(&configs_dir)?;

    let nodes = assign_nodes(experiment);

    // Generate per-node TOML configs
    for node in &nodes {
        let config_path = configs_dir.join(format!("node_{}.toml", node.node_id));
        let toml_str = toml::to_string_pretty(node).map_err(|e| anyhow::anyhow!("{e}"))?;
        fs::write(&config_path, toml_str)?;
    }

    // Generate topology.gml (complete graph)
    let gml_path = abs_parent.join("topology.gml");
    let gml = generate_gml(&nodes, experiment.network_defaults.latency_ms);
    fs::write(&gml_path, gml)?;

    // Generate shadow.yaml with absolute paths
    let shadow = build_shadow_config(experiment, &nodes, &configs_dir);
    let yaml_str = serde_yaml::to_string(&shadow)?;
    fs::write(output, yaml_str)?;

    tracing::info!(
        "generated {} node configs, topology.gml, and {:?}",
        nodes.len(),
        output
    );

    Ok(())
}

/// Assign roles and addresses to every node.
fn assign_nodes(experiment: &ExperimentConfig) -> Vec<NodeConfig> {
    let mut nodes = Vec::new();
    let mut node_id = 0u32;

    let validators_per_subnet = experiment.validators_per_subnet();

    for subnet in 0..experiment.subnet_count {
        // Validators
        for vi in 0..validators_per_subnet {
            let ip = subnet_ip(subnet as u32, vi as u32);
            let listen_addr = format!("/ip4/{ip}/udp/9090/quic-v1");
            nodes.push(NodeConfig {
                node_id,
                role: NodeRole::Validator,
                subnet_id: subnet as u32,
                listen_addr,
                seed_addrs: Vec::new(), // filled in afterward
                experiment: experiment.clone(),
            });
            node_id += 1;
        }

        // Local aggregators
        for li in 0..experiment.local_aggregators_per_subnet {
            let local_idx = validators_per_subnet + li;
            let ip = subnet_ip(subnet as u32, local_idx as u32);
            let listen_addr = format!("/ip4/{ip}/udp/9090/quic-v1");
            nodes.push(NodeConfig {
                node_id,
                role: NodeRole::LocalAggregator,
                subnet_id: subnet as u32,
                listen_addr,
                seed_addrs: Vec::new(),
                experiment: experiment.clone(),
            });
            node_id += 1;
        }
    }

    // Global aggregators
    for _ in 0..experiment.global_aggregator_count {
        let ip = global_aggregator_ip(node_id);
        let listen_addr = format!("/ip4/{ip}/udp/9090/quic-v1");
        nodes.push(NodeConfig {
            node_id,
            role: NodeRole::GlobalAggregator,
            subnet_id: 0,
            listen_addr,
            seed_addrs: Vec::new(),
            experiment: experiment.clone(),
        });
        node_id += 1;
    }

    // Fill in seed addresses: every node knows all others
    let all_addrs: Vec<String> = nodes.iter().map(|n| n.listen_addr.clone()).collect();
    for node in &mut nodes {
        node.seed_addrs = all_addrs
            .iter()
            .filter(|a| **a != node.listen_addr)
            .cloned()
            .collect();
    }

    nodes
}

/// IP address for a subnet-local node.
fn subnet_ip(subnet: u32, local_id: u32) -> String {
    format!("10.{}.{}.{}", subnet, local_id / 254, local_id % 254 + 1)
}

/// IP address for a global aggregator.
fn global_aggregator_ip(node_id: u32) -> String {
    format!("10.255.{}.{}", node_id / 254, node_id % 254 + 1)
}

/// Generate a complete-graph GML topology with per-edge latency.
fn generate_gml(nodes: &[NodeConfig], latency_ms: u64) -> String {
    let mut gml = String::from("graph [\n");
    gml.push_str("  directed 0\n");

    for node in nodes {
        gml.push_str(&format!(
            "  node [\n    id {}\n    hostname \"node-{}\"\n  ]\n",
            node.node_id, node.node_id
        ));
    }

    // Self-loops required by Shadow
    for node in nodes {
        gml.push_str(&format!(
            "  edge [\n    source {}\n    target {}\n    latency \"1 ms\"\n  ]\n",
            node.node_id, node.node_id
        ));
    }

    // Complete graph: every pair of nodes connected
    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            gml.push_str(&format!(
                "  edge [\n    source {}\n    target {}\n    latency \"{} ms\"\n  ]\n",
                nodes[i].node_id, nodes[j].node_id, latency_ms
            ));
        }
    }

    gml.push_str("]\n");
    gml
}

/// Build the Shadow YAML configuration.
fn build_shadow_config(
    experiment: &ExperimentConfig,
    nodes: &[NodeConfig],
    configs_dir: &Path,
) -> ShadowConfig {
    let nd = &experiment.network_defaults;
    let mut hosts = std::collections::BTreeMap::new();

    for node in nodes {
        let hostname = format!("node-{}", node.node_id);
        let ip = extract_ip(&node.listen_addr);
        let config_path = configs_dir.join(format!("node_{}.toml", node.node_id));

        hosts.insert(
            hostname.clone(),
            Host {
                network_node_id: node.node_id,
                ip_addr: ip,
                bandwidth_down: format!("{} Mbit", nd.downlink_mbps),
                bandwidth_up: format!("{} Mbit", nd.uplink_mbps),
                processes: vec![Process {
                    path: std::env::current_dir()
                        .unwrap_or_default()
                        .join("target/release/leansim")
                        .display()
                        .to_string(),
                    args: format!(
                        "node --config {}",
                        config_path.display()
                    ),
                    start_time: "1s".into(),
                }],
            },
        );
    }

    ShadowConfig {
        general: General {
            stop_time: format!("{}s", experiment.run_timeout_secs + 10),
        },
        network: Network {
            graph: Graph {
                graph_type: "gml".into(),
                file: GraphFile {
                    path: "topology.gml".into(),
                },
            },
        },
        hosts,
    }
}

/// Extract dotted IPv4 address from a multiaddr string like "/ip4/10.0.0.1/udp/9090/quic-v1".
fn extract_ip(listen_addr: &str) -> String {
    listen_addr
        .split('/')
        .nth(2)
        .unwrap_or("0.0.0.0")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::experiment::NetworkDefaults;

    fn test_experiment() -> ExperimentConfig {
        ExperimentConfig {
            run_id: "test".into(),
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
        }
    }

    #[test]
    fn node_count_correct() {
        let exp = test_experiment();
        let nodes = assign_nodes(&exp);
        // 8 validators (4 per subnet * 2) + 2 local aggregators + 1 global = 11
        assert_eq!(nodes.len(), 11);
    }

    #[test]
    fn roles_assigned_correctly() {
        let exp = test_experiment();
        let nodes = assign_nodes(&exp);
        let validators: Vec<_> = nodes.iter().filter(|n| n.role == NodeRole::Validator).collect();
        let locals: Vec<_> = nodes.iter().filter(|n| n.role == NodeRole::LocalAggregator).collect();
        let globals: Vec<_> = nodes.iter().filter(|n| n.role == NodeRole::GlobalAggregator).collect();
        assert_eq!(validators.len(), 8);
        assert_eq!(locals.len(), 2);
        assert_eq!(globals.len(), 1);
    }

    #[test]
    fn seed_addrs_exclude_self() {
        let exp = test_experiment();
        let nodes = assign_nodes(&exp);
        for node in &nodes {
            assert!(!node.seed_addrs.contains(&node.listen_addr));
        }
    }

    #[test]
    fn gml_contains_all_nodes() {
        let exp = test_experiment();
        let nodes = assign_nodes(&exp);
        let gml = generate_gml(&nodes, 50);
        for node in &nodes {
            assert!(gml.contains(&format!("hostname \"node-{}\"", node.node_id)));
        }
        // Verify latency is on edges
        assert!(gml.contains("latency \"50 ms\""));
    }
}
