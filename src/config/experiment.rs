use serde::{Deserialize, Serialize};

use crate::config::defaults;

/// Largest proof the proof protocol carries: its CBOR codec reads at most 10 MiB
/// per response. Mirrors MAX_PROOF_BYTES in shadow-sim.py.
pub const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;

/// How subnet signatures travel besides gossipsub's eager push.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureSync {
    /// Gossipsub only.
    #[default]
    None,
    /// Mesh neighbours exchange bitmaps; a host pulls what it lacks.
    BitmapPull,
    /// Mesh neighbours exchange bitmaps and push sparse coded repair packets.
    CodedRepair,
}

/// How subnet signatures propagate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePropagation {
    /// One gossipsub message per signature.
    #[default]
    Gossipsub,
    /// EIP-8334 (gossipsub partial messages version): signatures pushed in bundles to
    /// mesh peers every tick, and reconciled with gossip peers by validator index.
    Bundled,
}

/// The protocol that carries subnet signatures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureTransport {
    /// Gossipsub messages, or partial messages with `signature_propagation = "bundled"`.
    #[default]
    Gossipsub,
    /// Waggle: a stream per subnet topic and peer, one object per subnet. Its
    /// pieces are signature bundles and its metadata is the parts metadata.
    Waggle,
}

/// How a host picks the subscribers it pushes a subnet's signatures to over waggle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WagglePushSelection {
    /// `waggle_push_peers` subscribers, picked at random and kept, for every signature.
    #[default]
    Fixed,
    /// Per signature: a hash of the signature and the two peer ids, the same at
    /// both ends, names the end of each link that may send it. A host pushes a
    /// signature to at most `waggle_push_peers` of the subscribers it is the
    /// sender for, and never to the others.
    Hashed,
}

/// Bytes waggle's 64 KiB default message limit allows.
pub const WAGGLE_DEFAULT_MESSAGE_BYTES: usize = 65536;

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

    /// Width of a traffic-log bucket on hosts with `traffic_log = true`.
    #[serde(default = "defaults::default_traffic_log_bucket_ms")]
    pub traffic_log_bucket_ms: u64,

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

    /// Whether the heartbeat gossips to non-mesh peers. False sends no IHAVE, so no
    /// IWANT follows; with bundles it also stops the advertisements to non-mesh peers.
    #[serde(default = "default_true")]
    pub gossipsub_gossip: bool,

    /// Gossipsub v1.2 IDONTWANT for messages larger than this many bytes; 0 = off.
    #[serde(default)]
    pub gossipsub_idontwant_threshold_bytes: usize,

    /// Per-hop signature sync over each subnet's gossipsub mesh.
    #[serde(default)]
    pub signature_sync: SignatureSync,

    /// How often a host sends changed bitmaps and plans pulls or repair packets.
    #[serde(default = "defaults::default_sync_interval_ms")]
    pub sync_interval_ms: u64,

    /// Gossip's head start: a host pulls a signature only this long after a
    /// neighbour first advertised it, and codes only signatures it has held
    /// this long.
    #[serde(default = "defaults::default_sync_grace_ms")]
    pub sync_grace_ms: u64,

    /// Most signatures pulled from one neighbour per tick.
    #[serde(default = "defaults::default_sync_pull_batch")]
    pub sync_pull_batch: usize,

    /// A pull not answered after this long may be retried from another neighbour.
    #[serde(default = "defaults::default_sync_pull_timeout_ms")]
    pub sync_pull_timeout_ms: u64,

    /// Signatures combined per coded packet; 0 picks about log2(gaps) + 2, and
    /// 1 sends uncoded random repairs.
    #[serde(default)]
    pub sync_coded_degree: usize,

    /// Coded packets a peer's mesh sends it per gap: each neighbour sends
    /// ceil(redundancy * gaps / its mesh size) per bitmap it hears from the peer.
    #[serde(default = "defaults::default_sync_coded_redundancy")]
    pub sync_coded_redundancy: f64,

    /// Most coded packets to one neighbour per tick.
    #[serde(default = "defaults::default_sync_coded_per_tick")]
    pub sync_coded_per_tick: usize,

    /// Re-arm a neighbour's repair budget after this long without a new bitmap.
    #[serde(default = "defaults::default_sync_refresh_ms")]
    pub sync_refresh_ms: u64,

    /// Gossipsub messages or EIP-8334 bundles.
    #[serde(default)]
    pub signature_propagation: SignaturePropagation,

    /// Bundled: a host pushes its new signatures every this many ms; 0 pushes each
    /// arrival at once.
    #[serde(default = "defaults::default_bundle_tick_ms")]
    pub bundle_tick_ms: u64,

    /// Bundled: most signatures in one bundle.
    #[serde(default = "defaults::default_bundle_max_signatures")]
    pub bundle_max_signatures: usize,

    /// Bundled: a signature requested from a gossip peer is not requested from another
    /// until this long has passed without it arriving.
    #[serde(default = "defaults::default_bundle_request_timeout_ms")]
    pub bundle_request_timeout_ms: u64,

    /// Bundled: wait this long after an advertisement before requesting, and request
    /// only what has not arrived meanwhile; 0 requests at once, as the EIP does.
    #[serde(default = "defaults::default_bundle_request_delay_ms")]
    pub bundle_request_delay_ms: u64,

    /// Bundled: for each signature one end of a mesh link (picked by a hash) pushes
    /// at once, and the other waits this long for that copy before pushing; 0
    /// pushes from both ends at once, as the EIP does.
    #[serde(default = "defaults::default_bundle_stagger_ms")]
    pub bundle_stagger_ms: u64,

    /// Bundled, with a stagger: the end of a link that waits announces the
    /// signature to the other end at once, so that end need not push it back, and
    /// a peer announces back what it was announced once it holds it. The EIP
    /// sends no parts metadata to mesh peers.
    #[serde(default)]
    pub bundle_announce: bool,

    /// Gossipsub or waggle. Waggle ignores `signature_propagation`: `waggle_bundled`
    /// says whether its signatures travel in bundles.
    #[serde(default)]
    pub signature_transport: SignatureTransport,

    /// Waggle: signatures travel in bundles pushed every `bundle_tick_ms`, as
    /// with `signature_propagation = "bundled"` (all `bundle_*` settings apply).
    /// False sends every signature in a message of its own, forwarded on receipt.
    #[serde(default = "default_true")]
    pub waggle_bundled: bool,

    /// Waggle: subscribers of a subnet a host pushes its signatures to, picked at
    /// random and kept; 0 pushes to every subscriber. With hashed selection, the
    /// most subscribers one signature is pushed to; 0 = all the hash allows.
    #[serde(default = "defaults::default_waggle_push_peers")]
    pub waggle_push_peers: usize,

    /// Waggle: the same push peers for every signature, or picked per signature
    /// by a hash both ends of a link agree on.
    #[serde(default)]
    pub waggle_push_selection: WagglePushSelection,

    /// Waggle: other subscribers of a subnet a host advertises what it holds to
    /// every `waggle_gossip_interval_ms`, picked anew each time; 0 = none.
    #[serde(default = "defaults::default_waggle_gossip_peers")]
    pub waggle_gossip_peers: usize,

    /// Waggle: how often a host advertises; defaults to the gossipsub heartbeat interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waggle_gossip_interval_ms: Option<u64>,

    /// Waggle: messages queued for one peer on one topic. A message that finds
    /// the queue full is not sent, and its signatures are pushed again later.
    #[serde(default = "defaults::default_waggle_queue")]
    pub waggle_max_send_queue: usize,

    /// Waggle: received messages buffered per topic; reading pauses when it is full.
    #[serde(default = "defaults::default_waggle_queue")]
    pub waggle_max_receive_queue: usize,

    /// Waggle: largest message on the wire. Defaults to waggle's 64 KiB, or to
    /// what the largest bundle or parts metadata of the run needs if that is more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waggle_max_message_bytes: Option<usize>,

    /// Waggle: topics one peer may subscribe to on a connection; defaults to `subnet_count`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waggle_max_topic_subscription: Option<usize>,

    /// Churn: how often a churny host may flip between online and offline.
    #[serde(default = "defaults::default_churn_tick_ms")]
    pub churn_tick_ms: u64,

    /// Churn: share of regular hosts that churn; 0 = none. The launcher draws each
    /// churny host's offline windows; a host only follows its own.
    #[serde(default)]
    pub regular_churn_fraction: f64,

    /// Churn: chance per tick that an online churny regular host crashes.
    #[serde(default = "defaults::default_churn_leave_probability")]
    pub regular_churn_leave_probability: f64,

    /// Churn: chance per tick that an offline churny regular host rejoins.
    #[serde(default = "defaults::default_churn_rejoin_probability")]
    pub regular_churn_rejoin_probability: f64,

    /// Churn: share of supernodes that churn; 0 = none. Independent of the
    /// regular hosts' settings.
    #[serde(default)]
    pub supernode_churn_fraction: f64,

    #[serde(default = "defaults::default_churn_leave_probability")]
    pub supernode_churn_leave_probability: f64,

    #[serde(default = "defaults::default_churn_rejoin_probability")]
    pub supernode_churn_rejoin_probability: f64,

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
        if self.traffic_log_bucket_ms == 0 {
            return Err("traffic_log_bucket_ms must be > 0".into());
        }
        if self.signature_sync != SignatureSync::None {
            if self.sync_interval_ms == 0 {
                return Err("sync_interval_ms must be > 0".into());
            }
            if self.validators_per_subnet() > u16::MAX as usize + 1 {
                return Err("signature_sync supports at most 65,536 validators per subnet".into());
            }
            if self.sync_pull_batch == 0 || self.sync_pull_timeout_ms == 0 {
                return Err("sync_pull_batch and sync_pull_timeout_ms must be > 0".into());
            }
            if !(self.sync_coded_redundancy > 0.0 && self.sync_coded_redundancy.is_finite()) {
                return Err("sync_coded_redundancy must be a positive number".into());
            }
        }
        let waggle = self.signature_transport == SignatureTransport::Waggle;
        if waggle {
            if self.signature_propagation == SignaturePropagation::Bundled {
                return Err(
                    "signature_transport = \"waggle\" takes waggle_bundled, not signature_propagation = \"bundled\""
                        .into(),
                );
            }
            if self.signature_sync != SignatureSync::None {
                return Err(
                    "signature_transport = \"waggle\" requires signature_sync = \"none\"".into(),
                );
            }
            if self.gossipsub_explicit_aggregator_count > 0 {
                return Err(
                    "signature_transport = \"waggle\" does not support gossipsub_explicit_aggregator_count"
                        .into(),
                );
            }
            if self.waggle_max_send_queue == 0 || self.waggle_max_receive_queue == 0 {
                return Err(
                    "waggle_max_send_queue and waggle_max_receive_queue must be > 0".into(),
                );
            }
            if self.waggle_gossip_interval_ms == Some(0) {
                return Err("waggle_gossip_interval_ms must be > 0".into());
            }
            if self.waggle_max_topic_subscription == Some(0) {
                return Err("waggle_max_topic_subscription must be > 0".into());
            }
            if self.waggle_hashed() && self.bundle_stagger_ms > 0 {
                return Err(
                    "waggle_push_selection = \"hashed\" has no stagger: the end of a link the hash does not pick never pushes; set bundle_stagger_ms = 0"
                        .into(),
                );
            }
        }
        if self.signature_propagation == SignaturePropagation::Bundled
            && self.signature_sync != SignatureSync::None
        {
            return Err(
                "signature_propagation = \"bundled\" requires signature_sync = \"none\"".into(),
            );
        }
        if self.bundles_enabled() && self.bundle_request_timeout_ms == 0 {
            return Err("bundle_request_timeout_ms must be > 0".into());
        }
        if self.bundled() {
            if self.bundle_max_signatures == 0 {
                return Err("bundle_max_signatures must be > 0".into());
            }
            if self.bundle_announce && self.bundle_stagger_ms == 0 && !self.waggle_hashed() {
                return Err("bundle_announce requires bundle_stagger_ms > 0".into());
            }
        }
        // After the bundle checks: the size waggle needs depends on the bundle cap.
        if waggle {
            let needed = self.waggle_needed_message_bytes();
            if self
                .waggle_max_message_bytes
                .is_some_and(|max| max < needed)
            {
                return Err(format!(
                    "waggle_max_message_bytes must be at least {needed} to carry this run's bundles and parts metadata"
                ));
            }
        }
        if self.churn_tick_ms == 0 {
            return Err("churn_tick_ms must be > 0".into());
        }
        for (class, fraction, leave, rejoin) in [
            (
                "regular",
                self.regular_churn_fraction,
                self.regular_churn_leave_probability,
                self.regular_churn_rejoin_probability,
            ),
            (
                "supernode",
                self.supernode_churn_fraction,
                self.supernode_churn_leave_probability,
                self.supernode_churn_rejoin_probability,
            ),
        ] {
            for (key, value) in [
                ("fraction", fraction),
                ("leave_probability", leave),
                ("rejoin_probability", rejoin),
            ] {
                if !(0.0..=1.0).contains(&value) {
                    return Err(format!("{class}_churn_{key} must be in [0.0, 1.0]"));
                }
            }
            if fraction > 0.0 && rejoin == 0.0 {
                return Err(format!(
                    "{class}_churn_rejoin_probability must be > 0 when {class}_churn_fraction is"
                ));
            }
        }
        if self.churn_enabled() && self.gossipsub_explicit_aggregator_count > 0 {
            return Err("churn does not support gossipsub_explicit_aggregator_count".into());
        }
        Ok(())
    }

    /// Whether any host of the run churns.
    pub fn churn_enabled(&self) -> bool {
        self.regular_churn_fraction > 0.0 || self.supernode_churn_fraction > 0.0
    }

    /// Whether signatures travel as bundles and parts metadata (over gossipsub
    /// partial messages or over waggle) rather than as gossipsub messages.
    pub fn bundles_enabled(&self) -> bool {
        self.signature_transport == SignatureTransport::Waggle
            || self.signature_propagation == SignaturePropagation::Bundled
    }

    /// Whether a bundle may carry more than one signature and waits for a tick.
    /// False with gossipsub messages, and over waggle with `waggle_bundled = false`.
    pub fn bundled(&self) -> bool {
        match self.signature_transport {
            SignatureTransport::Gossipsub => {
                self.signature_propagation == SignaturePropagation::Bundled
            }
            SignatureTransport::Waggle => self.waggle_bundled,
        }
    }

    /// Whether waggle picks each signature's push peers by hash.
    pub fn waggle_hashed(&self) -> bool {
        self.signature_transport == SignatureTransport::Waggle
            && self.waggle_push_selection == WagglePushSelection::Hashed
    }

    /// Most signatures in one bundle: one without bundling.
    pub fn max_signatures_per_bundle(&self) -> usize {
        if self.bundled() {
            self.bundle_max_signatures.max(1)
        } else {
            1
        }
    }

    /// How often a host pushes its new signatures; 0, at once, without bundling.
    pub fn push_tick_ms(&self) -> u64 {
        if self.bundled() {
            self.bundle_tick_ms
        } else {
            0
        }
    }

    pub fn waggle_gossip_interval_ms(&self) -> u64 {
        self.waggle_gossip_interval_ms
            .unwrap_or(self.gossipsub_heartbeat_interval_ms)
            .max(1)
    }

    /// Bytes of the largest waggle message of the run: a full bundle, or parts
    /// metadata naming every validator of a subnet, with room for their framing.
    pub fn waggle_needed_message_bytes(&self) -> usize {
        // Bincode's fixed fields and length prefixes, the object id and protobuf framing.
        const FRAMING: usize = 128;
        // A signature, its 8-byte validator index and its 4-byte origin.
        let bundle = self.max_signatures_per_bundle() * (self.signature_payload_bytes + 12);
        let metadata = self.validators_per_subnet() * 8;
        bundle.max(metadata) + FRAMING
    }

    pub fn waggle_max_message_bytes(&self) -> usize {
        self.waggle_max_message_bytes.unwrap_or_else(|| {
            self.waggle_needed_message_bytes()
                .max(WAGGLE_DEFAULT_MESSAGE_BYTES)
        })
    }

    pub fn waggle_max_topic_subscription(&self) -> usize {
        self.waggle_max_topic_subscription
            .unwrap_or(self.subnet_count)
            .max(1)
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
    /// Whether this host logs per-bucket and per-peer traffic (the launcher sets
    /// it only for the experiment's `traffic_log_nodes`).
    #[serde(default)]
    pub traffic_log: bool,
    /// Churn: `[from_ms, until_ms)` windows since process start during which this
    /// host is offline, as the launcher drew them. Empty on a host that never churns.
    #[serde(default)]
    pub offline_windows_ms: Vec<[u64; 2]>,
    /// Churn: hosts that dial this one. With `seed_addrs` they are its peer table,
    /// all of which it dials when it comes back online.
    #[serde(default)]
    pub inbound_peer_addrs: Vec<String>,
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

    /// The `[from_ms, until_ms)` windows of a run of `run_ms` during which this
    /// host is online: what its offline windows leave. The last one ends at `run_ms`
    /// unless the host is offline then.
    pub fn online_windows(&self, run_ms: u64) -> Vec<(u64, u64)> {
        let mut offline = self.offline_windows_ms.clone();
        offline.sort_unstable();
        let mut online = Vec::new();
        let mut from = 0;
        for [start, end] in offline {
            let start = start.min(run_ms);
            if start > from {
                online.push((from, start));
            }
            from = from.max(end);
        }
        if from < run_ms {
            online.push((from, run_ms));
        }
        online
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

fn default_true() -> bool {
    true
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
