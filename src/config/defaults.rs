// Default values as functions (usable as serde default attributes).

pub const fn default_signature_payload_bytes() -> usize {
    3072
}

pub const fn default_proof_payload_bytes() -> usize {
    128 * 1024
}

pub const fn default_signature_aggregation_rate() -> u64 {
    1000
}

pub const fn default_global_aggregation_rate() -> u64 {
    10
}

pub const fn default_local_threshold() -> f64 {
    0.9
}

pub const fn default_global_proof_target() -> f64 {
    0.66
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
