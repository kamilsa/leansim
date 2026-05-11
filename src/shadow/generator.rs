use anyhow::Result;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::config::experiment::{ExperimentConfig, NodeConfig, NodeRole};
use crate::geo::latency::{CountryLatencyModel, CountryWeights};

const SEED_PEER_COUNT: usize = 50;

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

    let configs_dir = abs_parent.join("configs");
    fs::create_dir_all(&configs_dir)?;

    let nodes = assign_nodes(experiment);

    // Generate per-node TOML configs
    for node in &nodes {
        let config_path = configs_dir.join(format!("node_{}.toml", node.node_id));
        let toml_str = toml::to_string_pretty(node).map_err(|e| anyhow::anyhow!("{e}"))?;
        fs::write(&config_path, toml_str)?;
    }

    // Geo-latency setup
    let geo = if experiment.use_geo_latency {
        let seed = if experiment.geo_seed != 0 {
            experiment.geo_seed
        } else {
            rand::thread_rng().gen()
        };
        Some(GeoContext::new(experiment, seed))
    } else {
        None
    };

    // Determine supernodes
    let mut rng = if experiment.use_geo_latency && experiment.geo_seed != 0 {
        StdRng::seed_from_u64(experiment.geo_seed.wrapping_add(1))
    } else {
        StdRng::from_entropy()
    };
    let supernode_count = (nodes.len() as f64 * experiment.supernode_fraction).ceil() as usize;
    let supernode_ids: HashSet<u32> = if supernode_count > 0 {
        rand::seq::index::sample(&mut rng, nodes.len(), supernode_count)
            .into_iter()
            .map(|i| nodes[i].node_id)
            .collect()
    } else {
        HashSet::new()
    };

    // Generate topology.gml
    let gml_path = abs_parent.join("topology.gml");
    let gml = generate_gml(&nodes, experiment, geo.as_ref(), &mut rng);
    fs::write(&gml_path, gml)?;

    // Generate shadow.yaml
    let shadow = build_shadow_config(experiment, &nodes, &configs_dir, &supernode_ids);
    let yaml_str = serde_yaml::to_string(&shadow)?;
    fs::write(output, yaml_str)?;

    let geo_str = if experiment.use_geo_latency {
        format!("geo-latency ({})", geo.as_ref().unwrap().country_count())
    } else {
        "uniform-latency".to_string()
    };
    tracing::info!(
        "generated {} nodes ({}, {} supernodes), topology.gml, and {:?}",
        nodes.len(),
        geo_str,
        supernode_count,
        output
    );

    Ok(())
}

/// Context for geo-distributed latency generation.
struct GeoContext {
    model: CountryLatencyModel,
    node_countries: Vec<String>,
}

impl GeoContext {
    fn new(experiment: &ExperimentConfig, seed: u64) -> Self {
        let model = CountryLatencyModel::load();
        let weights = CountryWeights::load();
        let mut rng = StdRng::seed_from_u64(seed);
        let node_countries = weights.assign_countries(experiment.total_nodes(), &mut rng);
        Self {
            model,
            node_countries,
        }
    }

    fn country_count(&self) -> usize {
        self.node_countries
            .iter()
            .collect::<HashSet<_>>()
            .len()
    }
}

/// Assign roles and addresses to every node.
fn assign_nodes(experiment: &ExperimentConfig) -> Vec<NodeConfig> {
    let mut nodes = Vec::new();
    let mut node_id = 0u32;
    let validators_per_subnet = experiment.validators_per_subnet();

    for subnet in 0..experiment.subnet_count {
        for vi in 0..validators_per_subnet {
            let ip = subnet_ip(subnet as u32, vi as u32);
            let listen_addr = format!("/ip4/{ip}/udp/9090/quic-v1");
            nodes.push(NodeConfig {
                node_id,
                role: NodeRole::Validator,
                subnet_id: subnet as u32,
                listen_addr,
                seed_addrs: Vec::new(),
                experiment: experiment.clone(),
            });
            node_id += 1;
        }

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

    let all_addrs: Vec<String> = nodes.iter().map(|n| n.listen_addr.clone()).collect();
    let seed = if experiment.geo_seed != 0 {
        experiment.geo_seed
    } else {
        42
    };
    for node in &mut nodes {
        let mut rng = StdRng::seed_from_u64(seed.wrapping_add(node.node_id as u64));
        let mut candidates: Vec<String> = all_addrs
            .iter()
            .filter(|a| **a != node.listen_addr)
            .cloned()
            .collect();
        candidates.shuffle(&mut rng);
        candidates.truncate(SEED_PEER_COUNT.min(candidates.len()));
        node.seed_addrs = candidates;
    }

    nodes
}

fn subnet_ip(subnet: u32, local_id: u32) -> String {
    format!("10.{}.{}.{}", subnet, local_id / 254, local_id % 254 + 1)
}

fn global_aggregator_ip(node_id: u32) -> String {
    format!("10.255.{}.{}", node_id / 254, node_id % 254 + 1)
}

/// Generate a GML topology.
/// When `topology_degree > 0`, produces a sparse random regular-ish graph
/// where each node connects to that many peers. Otherwise falls back to
/// the complete graph (full mesh).
///
/// When geo mode is enabled, uses per-country-pair latencies with optional jitter.
fn generate_gml(
    nodes: &[NodeConfig],
    experiment: &ExperimentConfig,
    geo: Option<&GeoContext>,
    rng: &mut impl Rng,
) -> String {
    let uniform_ms = experiment.network_defaults.latency_ms;
    let degree = experiment.topology_degree;

    let mut gml = String::from("graph [\n");
    gml.push_str("  directed 0\n");

    for node in nodes {
        gml.push_str(&format!(
            "  node [\n    id {}\n    hostname \"node-{}\"\n  ]\n",
            node.node_id, node.node_id
        ));
    }

    // Self-loops (required by Shadow)
    for node in nodes {
        gml.push_str(&format!(
            "  edge [\n    source {}\n    target {}\n    latency \"1 ms\"\n  ]\n",
            node.node_id, node.node_id
        ));
    }

    // Build edge set
    let edges: Vec<(usize, usize)> = if degree > 0 && degree < nodes.len() - 1 {
        // Sparse random graph: each node picks `degree` random neighbours.
        // Collect undirected edges (i < j) into a set to avoid duplicates.
        let mut edge_set = std::collections::HashSet::new();
        for i in 0..nodes.len() {
            let mut candidates: Vec<usize> = (0..nodes.len()).filter(|&j| j != i).collect();
            // Fisher-Yates shuffle to pick `degree` random peers
            for k in 0..degree.min(candidates.len()) {
                let swap_idx = rng.gen_range(k..candidates.len());
                candidates.swap(k, swap_idx);
                let (a, b) = (i, candidates[k]);
                let (lo, hi) = (a.min(b), a.max(b));
                edge_set.insert((lo, hi));
            }
        }
        let mut edges: Vec<(usize, usize)> = edge_set.into_iter().collect();
        edges.sort();
        edges
    } else {
        // Complete graph (original behaviour)
        let mut edges = Vec::new();
        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                edges.push((i, j));
            }
        }
        edges
    };

    for (i, j) in &edges {
        let latency_ms = match geo {
            Some(ref ctx) => {
                let from = &ctx.node_countries[*i];
                let to = &ctx.node_countries[*j];
                let params = ctx.model.get_latency(from, to);
                let ms = if experiment.geo_jitter > 0.0 {
                    let spread = params.base_ms * experiment.geo_jitter;
                    params.base_ms + rng.gen_range(-spread..spread)
                } else {
                    params.base_ms
                };
                ms.max(0.5)
            }
            None => uniform_ms as f64,
        };

        gml.push_str(&format!(
            "  edge [\n    source {}\n    target {}\n    latency \"{:.0} ms\"\n  ]\n",
            nodes[*i].node_id, nodes[*j].node_id, latency_ms
        ));
    }

    gml.push_str("]\n");
    gml
}

/// Build the Shadow YAML configuration with per-node bandwidth (supernodes get 1 Gbps).
fn build_shadow_config(
    experiment: &ExperimentConfig,
    nodes: &[NodeConfig],
    configs_dir: &Path,
    supernode_ids: &HashSet<u32>,
) -> ShadowConfig {
    let nd = &experiment.network_defaults;
    let mut hosts = std::collections::BTreeMap::new();

    for node in nodes {
        let hostname = format!("node-{}", node.node_id);
        let ip = extract_ip(&node.listen_addr);
        let config_path = configs_dir.join(format!("node_{}.toml", node.node_id));

        let (down, up) = if supernode_ids.contains(&node.node_id) {
            (
                format!("{} Mbit", experiment.supernode_downlink_mbps),
                format!("{} Mbit", experiment.supernode_uplink_mbps),
            )
        } else {
            (
                format!("{} Mbit", nd.downlink_mbps),
                format!("{} Mbit", nd.uplink_mbps),
            )
        };

        hosts.insert(
            hostname.clone(),
            Host {
                network_node_id: node.node_id,
                ip_addr: ip,
                bandwidth_down: down,
                bandwidth_up: up,
                processes: vec![Process {
                    path: std::env::current_dir()
                        .unwrap_or_default()
                        .join("target/release/leansim")
                        .display()
                        .to_string(),
                    args: format!("node --config {}", config_path.display()),
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
    fn node_count_correct() {
        let exp = test_experiment();
        let nodes = assign_nodes(&exp);
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
    fn seed_addrs_are_capped_at_50() {
        let mut exp = test_experiment();
        exp.validator_count = 128;
        exp.subnet_count = 1;
        exp.local_aggregators_per_subnet = 1;
        let nodes = assign_nodes(&exp);
        for node in &nodes {
            assert_eq!(node.seed_addrs.len(), SEED_PEER_COUNT);
        }
    }

    #[test]
    fn gml_contains_all_nodes() {
        let exp = test_experiment();
        let nodes = assign_nodes(&exp);
        let mut rng = StdRng::seed_from_u64(42);
        let gml = generate_gml(&nodes, &exp, None, &mut rng);
        for node in &nodes {
            assert!(gml.contains(&format!("hostname \"node-{}\"", node.node_id)));
        }
        assert!(gml.contains("latency \"50 ms\""));
    }

    #[test]
    fn geo_latency_assigns_countries() {
        let mut exp = test_experiment();
        exp.use_geo_latency = true;
        exp.geo_seed = 42;
        let nodes = assign_nodes(&exp);
        let mut rng = StdRng::seed_from_u64(42);
        let gml = generate_gml(&nodes, &exp, Some(&GeoContext::new(&exp, 42)), &mut rng);
        // Should contain varying latencies, not uniform 50ms
        assert!(gml.contains("latency \""));
    }

    #[test]
    fn supernodes_assigned() {
        let mut exp = test_experiment();
        exp.supernode_fraction = 0.05;
        let nodes = assign_nodes(&exp);
        let supernode_count = (nodes.len() as f64 * 0.05).ceil() as usize;
        assert_eq!(supernode_count, 1); // 5% of 11 = 0.55 → 1
    }
}
