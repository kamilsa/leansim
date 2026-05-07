use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::metrics::events::JsonlEvent;

/// Final aggregated metrics written to metrics.json.
#[derive(Debug, Serialize)]
pub struct MetricsSummary {
    /// Local aggregation latency (ms) — time to first LocalProofGenerated.
    pub local_aggregation_latency_ms: Option<u64>,
    /// Per-subnet local proof latencies.
    pub local_proof_latencies: BTreeMap<u32, Vec<u64>>,
    /// Global proof latency stats (if global aggregation enabled).
    pub global_proof_latency_ms: Option<LatencyStats>,
    /// Average duplicates per unique signature (BEAMSIM metric).
    pub avg_duplicates_per_unique: f64,
    /// Total unique signatures received across all local aggregators.
    pub total_unique_sigs: u64,
    /// Total duplicate signature copies received.
    pub total_duplicate_sigs: u64,
    /// Total bytes transferred (sum of all message byte_size fields).
    pub total_bytes_transferred: u64,
    /// Total signatures sent by validators.
    pub total_sigs_sent: u64,
    /// Nodes where local threshold was never met.
    pub missed_thresholds: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LatencyStats {
    pub min: u64,
    pub max: u64,
    pub median: u64,
}

/// Walk shadow.data/hosts/*/stdout*, parse JSONL events, and aggregate into metrics.json.
pub fn summarize(shadow_data_dir: &Path, output: &Path) -> Result<()> {
    let mut global_latencies: Vec<u64> = Vec::new();
    let mut local_latencies: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    let mut total_bytes = 0u64;
    let mut sig_received_total = 0u64;
    let mut sig_duplicates = 0u64;
    let mut sigs_sent = 0u64;
    let mut first_local_proof_ms: Option<u64> = None;

    let hosts_dir = shadow_data_dir.join("hosts");
    if !hosts_dir.is_dir() {
        anyhow::bail!("shadow data hosts directory not found: {:?}", hosts_dir);
    }

    for entry in fs::read_dir(&hosts_dir)? {
        let host_dir = entry?.path();
        if !host_dir.is_dir() {
            continue;
        }
        for file_entry in fs::read_dir(&host_dir)? {
            let path = file_entry?.path();
            if !path.is_file() {
                continue;
            }
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !fname.contains("stdout") {
                continue;
            }
            let content = fs::read_to_string(&path)?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<JsonlEvent>(line) {
                    match event {
                        JsonlEvent::GlobalProofCompleted { latency_ms, .. } => {
                            global_latencies.push(latency_ms);
                        }
                        JsonlEvent::LocalProofGenerated {
                            subnet_id,
                            latency_ms,
                            byte_size,
                            ..
                        } => {
                            local_latencies.entry(subnet_id).or_default().push(latency_ms);
                            total_bytes += byte_size;
                            if first_local_proof_ms.is_none() || latency_ms < first_local_proof_ms.unwrap()
                            {
                                first_local_proof_ms = Some(latency_ms);
                            }
                        }
                        JsonlEvent::SigReceived {
                            duplicate,
                            byte_size,
                            ..
                        } => {
                            sig_received_total += 1;
                            total_bytes += byte_size;
                            if duplicate {
                                sig_duplicates += 1;
                            }
                        }
                        JsonlEvent::SigSent { byte_size, .. } => {
                            sigs_sent += 1;
                            total_bytes += byte_size;
                        }
                        JsonlEvent::LocalProofReceived { byte_size, .. } => {
                            total_bytes += byte_size;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let total_unique = sig_received_total.saturating_sub(sig_duplicates);
    let avg_dupes = if total_unique > 0 {
        sig_duplicates as f64 / total_unique as f64
    } else {
        0.0
    };

    let global_stats = if !global_latencies.is_empty() {
        let mut sorted = global_latencies.clone();
        sorted.sort();
        Some(LatencyStats {
            min: sorted[0],
            max: sorted[sorted.len() - 1],
            median: sorted[sorted.len() / 2],
        })
    } else {
        None
    };

    let summary = MetricsSummary {
        local_aggregation_latency_ms: first_local_proof_ms,
        local_proof_latencies: local_latencies,
        global_proof_latency_ms: global_stats,
        avg_duplicates_per_unique: avg_dupes,
        total_unique_sigs: total_unique,
        total_duplicate_sigs: sig_duplicates,
        total_bytes_transferred: total_bytes,
        total_sigs_sent: sigs_sent,
        missed_thresholds: Vec::new(),
    };

    let json = serde_json::to_string_pretty(&summary)?;
    fs::write(output, json)?;

    tracing::info!("metrics summary written to {:?}", output);
    Ok(())
}
