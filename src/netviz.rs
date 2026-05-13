use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::config::experiment::{ExperimentConfig, NodeRole};
use crate::metrics::events::JsonlEvent;
use crate::shadow::generator::{assign_nodes, GeoContext};

/// Topology node as written to the netviz header.
#[derive(Serialize)]
struct TopoNode {
    num: u32,
    upload_bw_mbps: u64,
    download_bw_mbps: u64,
    role: String,
    subnet: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
}

/// Topology edge as written to the netviz header.
#[derive(Serialize)]
struct TopoEdge {
    source: u32,
    target: u32,
    latency_ms: f64,
}

/// Netviz trace header (line 1 of the output file).
#[derive(Serialize)]
struct TraceHeader {
    v: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    t0: Option<String>,
    nodes: Vec<String>,
    topology: TraceTopology,
    config: ExperimentConfig,
    #[serde(rename = "decoderName")]
    decoder_name: String,
}

#[derive(Serialize)]
struct TraceTopology {
    nodes: Vec<TopoNode>,
    edges: Vec<TopoEdge>,
}

/// Generate a netviz-compatible `.bctrace` file from an experiment config and Shadow data dir.
pub fn generate(experiment_path: &Path, shadow_data_path: &Path, out_path: &Path) -> Result<()> {
    let experiment: ExperimentConfig = toml::from_str(
        &std::fs::read_to_string(experiment_path)
            .map_err(|e| anyhow::anyhow!("reading experiment: {e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("invalid experiment: {e}"))?;
    experiment
        .validate()
        .map_err(|e| anyhow::anyhow!("validation: {e}"))?;

    let nodes = assign_nodes(&experiment);
    let total = nodes.len();

    // Deterministic RNG for supernodes (match generator.rs seed logic)
    let rng_seed = if experiment.geo_seed != 0 {
        experiment.geo_seed
    } else {
        42
    };
    let mut rng = StdRng::seed_from_u64(rng_seed.wrapping_add(1));
    let supernode_ids = supernode_set(&nodes, &experiment, &mut rng);

    // Geo context (latency per country pair)
    let geo = if experiment.use_geo_latency {
        let seed = if experiment.geo_seed != 0 {
            experiment.geo_seed
        } else {
            rand::thread_rng().gen()
        };
        Some(GeoContext::new(&experiment, seed))
    } else {
        None
    };

    // Read all events and build peer-id → node map
    let raw_events = read_all_events(shadow_data_path)?;
    let peer_to_node = build_peer_map(&raw_events);
    let mesh_edges = build_mesh_edges(&raw_events, &peer_to_node, &experiment, geo.as_ref(), &mut rng);

    // Header
    let header = TraceHeader {
        v: 1,
        t0: None,
        nodes: nodes.iter().map(|n| format!("n{}", n.node_id)).collect(),
        topology: TraceTopology {
            nodes: nodes
                .iter()
                .map(|n| {
                    let (up, down) = if supernode_ids.contains(&n.node_id) {
                        (
                            experiment.supernode_uplink_mbps,
                            experiment.supernode_downlink_mbps,
                        )
                    } else {
                        (
                            experiment.network_defaults.uplink_mbps,
                            experiment.network_defaults.downlink_mbps,
                        )
                    };
                    let country = geo.as_ref().map(|g| {
                        let idx = nodes.iter().position(|x| x.node_id == n.node_id).unwrap();
                        g.node_countries[idx].clone()
                    });
                    TopoNode {
                        num: n.node_id,
                        upload_bw_mbps: up,
                        download_bw_mbps: down,
                        role: role_str(n.role).to_string(),
                        subnet: n.subnet_id,
                        country,
                    }
                })
                .collect(),
            edges: mesh_edges,
        },
        config: experiment.clone(),
        decoder_name: "leansim".to_string(),
    };

    let mut out = String::new();
    out.push_str(&serde_json::to_string(&header)?);
    out.push('\n');

    // Convert events using the peer map
    let mut event_lines: Vec<(u64, String)> = Vec::new();
    for (event, ts_us) in &raw_events {
        if let Some(line) = convert_event(event, &peer_to_node) {
            event_lines.push((*ts_us, line));
        }
    }
    event_lines.sort_by_key(|(ts, _)| *ts);

    for (_, line) in &event_lines {
        out.push_str(line);
        out.push('\n');
    }

    std::fs::write(out_path, out)?;
    let edge_count = event_lines.len();
    tracing::info!(
        "wrote {} events for {} nodes ({} mesh edges) to {:?}",
        edge_count,
        total,
        header.topology.edges.len(),
        out_path
    );
    Ok(())
}

fn role_str(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Validator => "validator",
        NodeRole::LocalAggregator => "local_aggregator",
        NodeRole::GlobalAggregator => "global_aggregator",
    }
}

fn supernode_set(
    nodes: &[crate::config::experiment::NodeConfig],
    experiment: &ExperimentConfig,
    rng: &mut StdRng,
) -> HashSet<u32> {
    let count = (nodes.len() as f64 * experiment.supernode_fraction).ceil() as usize;
    if count == 0 {
        return HashSet::new();
    }
    rand::seq::index::sample(rng, nodes.len(), count)
        .into_iter()
        .map(|i| nodes[i].node_id)
        .collect()
}

/// Read all JSONL events from shadow.data, returning (event, timestamp_us).
fn read_all_events(shadow_data: &Path) -> Result<Vec<(JsonlEvent, u64)>> {
    let mut events: Vec<(JsonlEvent, u64)> = Vec::new();
    let hosts_dir = shadow_data.join("hosts");
    if !hosts_dir.is_dir() {
        return Err(anyhow::anyhow!(
            "shadow.data/hosts/ not found at {:?}",
            shadow_data
        ));
    }

    for entry in std::fs::read_dir(&hosts_dir)? {
        let host_path = entry?.path();
        if !host_path.is_dir() {
            continue;
        }
        for file_entry in std::fs::read_dir(&host_path)? {
            let file_path = file_entry?.path();
            let file_name = file_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if !file_name.contains("stdout") {
                continue;
            }
            let content = std::fs::read_to_string(&file_path)?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<JsonlEvent>(line) {
                    let ts = event_ts_us(&event);
                    events.push((event, ts));
                }
            }
        }
    }
    Ok(events)
}

fn event_ts_us(event: &JsonlEvent) -> u64 {
    match event {
        JsonlEvent::NodePeerId { .. } => 0,
        JsonlEvent::SigSent { ts_ms, .. } => ts_ms * 1000,
        JsonlEvent::SigReceived { ts_ms, .. } => ts_ms * 1000,
        JsonlEvent::LocalProofGenerated { latency_ms, .. } => latency_ms * 1000,
        JsonlEvent::LocalProofReceived { ts_ms, .. } => ts_ms * 1000,
        JsonlEvent::GlobalProofCompleted { latency_ms, .. } => latency_ms * 1000,
        JsonlEvent::NodeStats { .. } => u64::MAX,
    }
}

/// Build a PeerId (base58 string) → node_id map from NodePeerId events.
fn build_peer_map(events: &[(JsonlEvent, u64)]) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for (event, _) in events {
        if let JsonlEvent::NodePeerId { node_id, peer_id } = event {
            map.insert(peer_id.clone(), *node_id);
        }
    }
    map
}

/// Build topology edges from actual message forwarding paths observed in the
/// simulation. For each receive event, the edge (receiver, forwarding_peer) is
/// counted. Only edges that were used at least MIN_EDGE_USES times are kept,
/// filtering out transient peers and showing the stable gossipsub mesh.
fn build_mesh_edges(
    events: &[(JsonlEvent, u64)],
    peer_to_node: &HashMap<String, u32>,
    experiment: &ExperimentConfig,
    geo: Option<&GeoContext>,
    rng: &mut StdRng,
) -> Vec<TopoEdge> {
    const MIN_EDGE_USES: u32 = 3;
    let uniform_ms = experiment.network_defaults.latency_ms as f64;
    let mut edge_counts: HashMap<(u32, u32), u32> = HashMap::new();

    for (event, _) in events {
        let (receiver, from_peer_id) = match event {
            JsonlEvent::SigReceived {
                node_id,
                from_peer_id,
                ..
            } => (*node_id, from_peer_id),
            JsonlEvent::LocalProofReceived {
                node_id,
                from_peer_id,
                ..
            } => (*node_id, from_peer_id),
            _ => continue,
        };

        if let Some(&from_node) = peer_to_node.get(from_peer_id) {
            let (lo, hi) = if receiver < from_node {
                (receiver, from_node)
            } else {
                (from_node, receiver)
            };
            *edge_counts.entry((lo, hi)).or_insert(0) += 1;
        }
    }

    let mut edges: Vec<TopoEdge> = edge_counts
        .into_iter()
        .filter(|(_, count)| *count >= MIN_EDGE_USES)
        .map(|((s, t), _)| {
            let lat = match geo {
                Some(ctx) => {
                    let from = &ctx.node_countries[s as usize];
                    let to = &ctx.node_countries[t as usize];
                    let params = ctx.model.get_latency(from, to);
                    if experiment.geo_jitter > 0.0 {
                        let spread = params.base_ms * experiment.geo_jitter;
                        (params.base_ms + rng.gen_range(-spread..spread)).max(0.5)
                    } else {
                        params.base_ms.max(0.5)
                    }
                }
                None => uniform_ms,
            };
            TopoEdge {
                source: s,
                target: t,
                latency_ms: lat,
            }
        })
        .collect();
    edges.sort_by(|a, b| a.source.cmp(&b.source).then_with(|| a.target.cmp(&b.target)));
    edges
}

/// Convert a JsonlEvent into a netviz array line. The peer_to_node map
/// resolves `from_peer_id` strings to numeric node indices for the decoder.
fn convert_event(event: &JsonlEvent, peer_to_node: &HashMap<String, u32>) -> Option<String> {
    match event {
        JsonlEvent::NodePeerId { .. } => None,
        JsonlEvent::SigSent {
            node_id,
            subnet_id,
            seq,
            ts_ms,
            byte_size,
        } => Some(format!(
            "[{}, {}, \"ss\", {}, {}, {}]",
            ts_ms * 1000,
            node_id,
            subnet_id,
            seq,
            byte_size
        )),
        JsonlEvent::SigReceived {
            node_id,
            from_id,
            from_peer_id,
            subnet_id,
            duplicate,
            ts_ms,
            byte_size,
        } => {
            let code = if *duplicate { "sd" } else { "sr" };
            let peer_idx = peer_to_node.get(from_peer_id).copied().unwrap_or(*from_id);
            Some(format!(
                "[{}, {}, \"{}\", {}, {}, {}, {}]",
                ts_ms * 1000,
                node_id,
                code,
                from_id,
                peer_idx,
                subnet_id,
                byte_size
            ))
        }
        JsonlEvent::LocalProofGenerated {
            node_id,
            subnet_id,
            sig_count,
            latency_ms,
            byte_size,
        } => Some(format!(
            "[{}, {}, \"pg\", {}, {}, {}]",
            latency_ms * 1000,
            node_id,
            subnet_id,
            sig_count,
            byte_size
        )),
        JsonlEvent::LocalProofReceived {
            node_id,
            from_id,
            from_peer_id,
            subnet_id,
            covered_sigs,
            duplicate,
            ts_ms,
            byte_size,
        } => {
            let code = if *duplicate { "pd" } else { "pr" };
            let peer_idx = peer_to_node.get(from_peer_id).copied().unwrap_or(*from_id);
            Some(format!(
                "[{}, {}, \"{}\", {}, {}, {}, {}, {}]",
                ts_ms * 1000,
                node_id,
                code,
                from_id,
                peer_idx,
                subnet_id,
                covered_sigs,
                byte_size
            ))
        }
        JsonlEvent::GlobalProofCompleted {
            node_id,
            total_sigs,
            proof_count,
            latency_ms,
        } => Some(format!(
            "[{}, {}, \"gc\", {}, {}, {}]",
            latency_ms * 1000,
            node_id,
            total_sigs,
            proof_count,
            latency_ms
        )),
        JsonlEvent::NodeStats { .. } => None,
    }
}
