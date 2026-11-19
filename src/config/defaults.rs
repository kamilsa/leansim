// Default values as functions (usable as serde default attributes).

pub const fn default_signature_payload_bytes() -> usize {
    3072
}

pub const fn default_signature_aggregation_rate() -> u64 {
    1000
}

pub const fn default_local_threshold() -> f64 {
    0.9
}

pub const fn default_burst_time_ms() -> u64 {
    2000
}

pub const fn default_burst_jitter_ms() -> u64 {
    500
}

pub const fn default_mesh_n_low() -> usize {
    2
}

pub const fn default_mesh_n() -> usize {
    4
}

pub const fn default_mesh_n_high() -> usize {
    8
}

pub const fn default_mesh_outbound_min() -> usize {
    1
}

pub const fn default_heartbeat_interval_ms() -> u64 {
    1000
}

pub const fn default_uplink_mbps() -> u64 {
    50
}

pub const fn default_downlink_mbps() -> u64 {
    50
}

pub const fn default_latency_ms() -> u64 {
    50
}

/// leanVM's 2-to-1 recursion: 0.276 s on an M4 Max (`cargo leanvm recursion --n 2`).
pub const fn default_recursive_aggregation_time_ms() -> u64 {
    276
}

pub const fn default_recursive_proofs_per_child() -> usize {
    1
}

/// EIP-8292's propagation target for one aggregate, 256 KiB.
pub const fn default_aggregate_proof_bytes() -> usize {
    262_144
}

/// Bucket width of the per-node traffic logs, fine enough to see a slot's shape.
pub const fn default_traffic_log_bucket_ms() -> u64 {
    100
}

pub const fn default_sync_interval_ms() -> u64 {
    100
}

pub const fn default_sync_grace_ms() -> u64 {
    300
}

pub const fn default_sync_pull_batch() -> usize {
    16
}

pub const fn default_sync_pull_timeout_ms() -> u64 {
    1000
}

pub const fn default_sync_coded_redundancy() -> f64 {
    1.1
}

pub const fn default_sync_coded_per_tick() -> usize {
    8
}

pub const fn default_sync_refresh_ms() -> u64 {
    1000
}

/// EIP-8334's recommended ATTESTATION_BUNDLE_TICK_DURATION.
pub const fn default_bundle_tick_ms() -> u64 {
    20
}

/// EIP-8334's MAX_ATTESTATIONS_PER_BUNDLE.
pub const fn default_bundle_max_signatures() -> usize {
    50
}

pub const fn default_bundle_request_timeout_ms() -> u64 {
    1000
}

/// EIP-8334 pushes from both ends of a link at once.
pub const fn default_bundle_stagger_ms() -> u64 {
    0
}

/// EIP-8334 requests advertised signatures at once.
pub const fn default_bundle_request_delay_ms() -> u64 {
    0
}

/// Subscribers a host pushes a subnet's signatures to over waggle.
pub const fn default_waggle_push_peers() -> usize {
    8
}

/// Gossipsub's default `gossip_lazy`.
pub const fn default_waggle_gossip_peers() -> usize {
    6
}

/// Waggle's own default for both of its queues.
pub const fn default_waggle_queue() -> usize {
    100
}

pub const fn default_churn_tick_ms() -> u64 {
    100
}

/// Lean Gossip's churny peers: 10 s mean sessions at 100 ms ticks.
pub const fn default_churn_leave_probability() -> f64 {
    0.01
}

/// Lean Gossip's churny peers: 2 s mean gaps at 100 ms ticks.
pub const fn default_churn_rejoin_probability() -> f64 {
    0.05
}
