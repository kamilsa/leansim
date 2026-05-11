use serde::{Deserialize, Serialize};

use crate::config::defaults;

/// Network defaults applied to all node-to-node links in Shadow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDefaults {
    #[serde(default = "defaults::default_uplink_mbps")]
    pub uplink_mbps: u64,
    #[serde(default = "defaults::default_downlink_mbps")]
    pub downlink_mbps: u64,
    #[serde(default = "defaults::default_latency_ms")]
    pub latency_ms: u64,
}

impl Default for NetworkDefaults {
    fn default() -> Self {
        Self {
            uplink_mbps: defaults::default_uplink_mbps(),
            downlink_mbps: defaults::default_downlink_mbps(),
            latency_ms: defaults::default_latency_ms(),
        }
    }
}

/// Top-level experiment configuration deserialized from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentConfig {
    pub run_id: String,

    #[serde(default = "default_run_timeout")]
    pub run_timeout_secs: u64,

    pub validator_count: usize,
    pub subnet_count: usize,

    #[serde(default = "default_local_aggregators")]
    pub local_aggregators_per_subnet: usize,

    #[serde(default = "default_global_aggregators")]
    pub global_aggregator_count: usize,

    #[serde(default = "defaults::default_local_threshold")]
    pub local_threshold: f64,

    #[serde(default = "defaults::default_global_proof_target")]
    pub global_proof_target: f64,

    #[serde(default = "defaults::default_burst_time_ms")]
    pub burst_time_ms: u64,

    #[serde(default = "defaults::default_burst_jitter_ms")]
    pub burst_jitter_ms: u64,

    #[serde(default = "defaults::default_signature_aggregation_rate")]
    pub signature_aggregation_rate: u64,

    #[serde(default = "defaults::default_global_aggregation_rate")]
    pub global_aggregation_rate: u64,

    #[serde(default = "defaults::default_signature_payload_bytes")]
    pub signature_payload_bytes: usize,

    #[serde(default = "defaults::default_proof_payload_bytes")]
    pub proof_payload_bytes: usize,

    #[serde(default = "defaults::default_mesh_n_low")]
    pub gossipsub_mesh_n_low: usize,

    #[serde(default = "defaults::default_mesh_n")]
    pub gossipsub_mesh_n: usize,

    #[serde(default = "defaults::default_mesh_n_high")]
    pub gossipsub_mesh_n_high: usize,

    #[serde(default = "defaults::default_mesh_outbound_min")]
    pub gossipsub_mesh_outbound_min: usize,

    #[serde(default = "defaults::default_heartbeat_interval_ms")]
    pub gossipsub_heartbeat_interval_ms: u64,

    #[serde(default)]
    pub network_defaults: NetworkDefaults,

    // --- Geographical latency settings ---

    /// Enable country-based per-edge latencies (uses country_latencies.json + weights.json).
    #[serde(default = "default_false")]
    pub use_geo_latency: bool,

    /// Random seed for country assignment and latency jitter (0 = use random).
    #[serde(default = "default_geo_seed")]
    pub geo_seed: u64,

    /// Jitter factor for per-edge latency. 0 = no jitter, 1 = ±100%.
    /// Overrides the built-in thresholds from the latency model when > 0.
    #[serde(default)]
    pub geo_jitter: f64,

    // --- Supernode settings ---

    /// Fraction of nodes that get supernode bandwidth (e.g. 0.05 = 5%).
    #[serde(default = "default_supernode_fraction")]
    pub supernode_fraction: f64,

    /// Upload bandwidth for supernodes in Mbps.
    #[serde(default = "default_supernode_bw")]
    pub supernode_uplink_mbps: u64,

    /// Download bandwidth for supernodes in Mbps.
    #[serde(default = "default_supernode_bw")]
    pub supernode_downlink_mbps: u64,

    /// Number of peers each node connects to in the topology graph.
    /// 0 = full mesh (complete graph, default for backward compat).
    #[serde(default)]
    pub topology_degree: usize,
}

impl ExperimentConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.run_id.is_empty() {
            return Err("run_id must not be empty".into());
        }
        if self.subnet_count == 0 {
            return Err("subnet_count must be > 0".into());
        }
        if self.validator_count == 0 {
            return Err("validator_count must be > 0".into());
        }
        if self.local_threshold <= 0.0 || self.local_threshold > 1.0 {
            return Err("local_threshold must be in (0.0, 1.0]".into());
        }
        if self.global_proof_target <= 0.0 || self.global_proof_target > 1.0 {
            return Err("global_proof_target must be in (0.0, 1.0]".into());
        }
        if self.signature_aggregation_rate == 0 {
            return Err("signature_aggregation_rate must be > 0".into());
        }
        if self.global_aggregation_rate == 0 {
            return Err("global_aggregation_rate must be > 0".into());
        }
        if self.signature_payload_bytes == 0 {
            return Err("signature_payload_bytes must be > 0".into());
        }
        if self.proof_payload_bytes == 0 {
            return Err("proof_payload_bytes must be > 0".into());
        }
        Ok(())
    }

    pub fn total_nodes(&self) -> usize {
        self.validator_count
            + self.subnet_count * self.local_aggregators_per_subnet
            + self.global_aggregator_count
    }

    pub fn validators_per_subnet(&self) -> usize {
        self.validator_count / self.subnet_count
    }
}

/// Role assigned to a single simulated node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Validator,
    LocalAggregator,
    GlobalAggregator,
}

/// Per-node configuration (generated or hand-written).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: u32,
    pub role: NodeRole,
    pub subnet_id: u32,
    pub listen_addr: String,
    pub seed_addrs: Vec<String>,
    pub experiment: ExperimentConfig,
}

fn default_run_timeout() -> u64 {
    120
}

fn default_local_aggregators() -> usize {
    1
}

fn default_global_aggregators() -> usize {
    1
}

fn default_false() -> bool {
    false
}

fn default_geo_seed() -> u64 {
    42
}

fn default_supernode_fraction() -> f64 {
    0.05
}

fn default_supernode_bw() -> u64 {
    1000
}
