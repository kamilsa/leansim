use std::time::Duration;

pub const SUBNETS: usize = 4;
pub const VALIDATORS_PER_SUBNET: usize = 32;
pub const LOCAL_AGGREGATORS_PER_SUBNET: usize = 4;
pub const GLOBAL_AGGREGATORS: usize = 4;

pub const SIG_SIZE: usize = 3072; // 3KB
pub const SNARK_SIZE: usize = 128 * 1024; // 128KB

pub const SNARK1_THRESHOLD: f64 = 0.9;
pub const SNARK2_THRESHOLD: f64 = 0.66;

pub const SIG_VERIFY_TIME: Duration = Duration::from_micros(30);
pub const SNARK_VERIFY_TIME: Duration = Duration::from_millis(2);

pub const AGGREGATION_TIME_PER_SIG: Duration = Duration::from_millis(1);
pub const RECURSION_TIME_PER_SNARK: Duration = Duration::from_millis(100);

pub const MAX_BITRATE: u64 = 50 * 1024 * 1024; // 50 Mbps
