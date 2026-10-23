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
