use serde::{Deserialize, Serialize};

use crate::config::defaults;

/// Largest proof the proof protocol carries: its CBOR codec reads at most 10 MiB
/// per response. Mirrors MAX_PROOF_BYTES in shadow-sim.py.
pub const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;

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

    /// Validators per subnet that also act as local aggregators.
    #[serde(default = "default_local_aggregators")]
    pub local_aggregators_per_subnet: usize,

    #[serde(default = "defaults::default_local_threshold")]
    pub local_threshold: f64,

    #[serde(default = "defaults::default_burst_time_ms")]
    pub burst_time_ms: u64,

    #[serde(default = "defaults::default_burst_jitter_ms")]
    pub burst_jitter_ms: u64,

    #[serde(default = "defaults::default_signature_aggregation_rate")]
    pub signature_aggregation_rate: u64,

    #[serde(default = "defaults::default_signature_payload_bytes")]
    pub signature_payload_bytes: usize,

    /// Simulated time for one recursive proof, whatever its number of children.
    #[serde(default = "defaults::default_recursive_aggregation_time_ms")]
    pub recursive_aggregation_time_ms: u64,

    /// Announcers a recursive aggregator pulls one child proof from at once,
    /// until one copy arrives; it never downloads more copies than this.
    #[serde(default = "defaults::default_recursive_proofs_per_child")]
    pub recursive_proofs_per_child: usize,

    /// Wire size of every aggregation proof, subnet and recursive.
    #[serde(default = "defaults::default_aggregate_proof_bytes")]
    pub aggregate_proof_bytes: usize,

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

    /// Delay before the first gossipsub heartbeat; defaults to the heartbeat interval.
    /// Until it fires the mesh only holds the first `mesh_n_low` peers to subscribe and no
    /// IHAVE gossip is sent, so libp2p's 5 s default isolates regions during short warmups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gossipsub_heartbeat_initial_delay_ms: Option<u64>,

    /// Mesh warmup before signing, the same for every host so all of them vote at
    /// once. The launcher sets it from the busiest host's dial count; unset falls
    /// back to a per-host value (`network::swarm::warmup_ms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_warmup_ms: Option<u64>,

    /// Same-subnet local aggregators that every signing node keeps as explicit peers.
    #[serde(default)]
    pub gossipsub_explicit_aggregator_count: usize,

    /// Whether locally published messages are sent to every subscribed peer.
    #[serde(default)]
    pub gossipsub_flood_publish: bool,

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
        if self.validator_count < self.subnet_count {
            return Err("validator_count must be >= subnet_count".into());
        }
        if self.local_aggregators_per_subnet > self.validators_per_subnet() {
            return Err(
                "local_aggregators_per_subnet must not exceed validators_per_subnet".into(),
            );
        }
        if self.gossipsub_explicit_aggregator_count >= self.local_aggregators_per_subnet
            && self.gossipsub_explicit_aggregator_count > 0
        {
            return Err(
                "gossipsub_explicit_aggregator_count must be less than local_aggregators_per_subnet"
                    .into(),
            );
        }
        if self.local_threshold <= 0.0 || self.local_threshold > 1.0 {
            return Err("local_threshold must be in (0.0, 1.0]".into());
        }
        if self.signature_aggregation_rate == 0 {
            return Err("signature_aggregation_rate must be > 0".into());
        }
        if self.signature_payload_bytes == 0 {
            return Err("signature_payload_bytes must be > 0".into());
        }
        if self.recursive_proofs_per_child == 0 {
            return Err("recursive_proofs_per_child must be > 0".into());
        }
        if self.aggregate_proof_bytes == 0 || self.aggregate_proof_bytes > MAX_PROOF_BYTES {
            return Err(format!(
                "aggregate_proof_bytes must be in 1..={MAX_PROOF_BYTES}"
            ));
        }
        Ok(())
    }

    pub fn heartbeat_initial_delay_ms(&self) -> u64 {
        self.gossipsub_heartbeat_initial_delay_ms
            .unwrap_or(self.gossipsub_heartbeat_interval_ms)
    }

    pub fn validators_per_subnet(&self) -> usize {
        self.validator_count / self.subnet_count
    }

    /// Validator → committee → subnet. Committees are contiguous, equally sized
    /// blocks of validator ids (the launcher deals ids over randomly sampled
    /// slots, so each block is a random committee), and committee i attests on
    /// subnet i: one slot of `subnet_count` committees.
    pub fn subnet_for_validator(&self, validator_id: u32) -> u32 {
        let subnet = validator_id as usize / self.validators_per_subnet().max(1);
        subnet.min(self.subnet_count.saturating_sub(1)) as u32
    }
}

/// Role assigned to a single simulated node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Validator,
    LocalAggregator,
    /// Gossip-only node: subscribes to its assigned subnets and relays, signs nothing.
    Relay,
}

/// Per-node configuration (generated or hand-written).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: u32,
    pub role: NodeRole,
    pub subnet_id: u32,
    pub listen_addr: String,
    pub seed_addrs: Vec<String>,
    /// All peers this node keeps as explicit gossipsub peers. This includes reciprocal links.
    #[serde(default)]
    pub explicit_peer_addrs: Vec<String>,
    /// The local aggregators selected by this signing node. These must be ready before signing.
    #[serde(default)]
    pub selected_aggregator_addrs: Vec<String>,
    /// Validators run by this host. Empty means a single validator whose id is `node_id`.
    #[serde(default)]
    pub validator_ids: Vec<u32>,
    /// Subnets this host subscribes to (gossip membership), independent of the
    /// subnets its validators publish to. Local aggregators add `subnet_id`, the
    /// subnet they collect. Other roles default to the signing subnets.
    #[serde(default)]
    pub subscribed_subnets: Vec<u32>,
    /// Subnets (committees) this host aggregates. Empty on a local aggregator
    /// means just `subnet_id`, as in configs written before committee aggregators.
    #[serde(default)]
    pub aggregated_subnets: Vec<u32>,
    /// Path of the launcher's aggregation-plan.json; set only on hosts with a
    /// proof duty in a run with recursive aggregation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation_plan: Option<String>,
    pub experiment: ExperimentConfig,
}

impl NodeConfig {
    /// Validators whose signatures this host publishes. Relays sign nothing; a
    /// validator-less local aggregator (an aggregator-only host) signs nothing too.
    /// The node_id fallback exists for plain validator configs.
    pub fn signing_validator_ids(&self) -> Vec<u32> {
        match self.role {
            NodeRole::Relay => Vec::new(),
            NodeRole::Validator if self.validator_ids.is_empty() => vec![self.node_id],
            _ => self.validator_ids.clone(),
        }
    }

    /// Subnets whose signatures this host collects into local proofs.
    pub fn aggregated_subnets(&self) -> Vec<u32> {
        match self.role {
            NodeRole::LocalAggregator if self.aggregated_subnets.is_empty() => vec![self.subnet_id],
            NodeRole::LocalAggregator => {
                let mut subnets = self.aggregated_subnets.clone();
                subnets.sort_unstable();
                subnets.dedup();
                subnets
            }
            _ => Vec::new(),
        }
    }
}

fn default_run_timeout() -> u64 {
    120
}

fn default_local_aggregators() -> usize {
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
