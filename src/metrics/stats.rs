use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::metrics::events::JsonlEvent;

fn median(values: &mut Vec<u64>) -> u64 {
    values.sort();
    let len = values.len();
    if len == 0 {
        return 0;
    }
    values[len / 2]
}

/// Compute and print the stats table from a Shadow data directory.
pub fn print_stats(shadow_data_dir: &Path) {
    let hosts_dir = shadow_data_dir.join("hosts");
    if !hosts_dir.is_dir() {
        eprintln!("error: shadow data hosts directory not found: {:?}", hosts_dir);
        return;
    }

    let mut sig_sent_timestamps: Vec<u64> = Vec::new();
    let mut aggregator_threshold_ts: BTreeMap<u32, u64> = BTreeMap::new();
    let mut aggregator_proof_latency: BTreeMap<u32, u64> = BTreeMap::new();
    let mut validator_count: u64 = 0;

    for entry in fs::read_dir(&hosts_dir).unwrap() {
        let host_dir = entry.unwrap().path();
        if !host_dir.is_dir() {
            continue;
        }
        for file_entry in fs::read_dir(&host_dir).unwrap() {
            let path = file_entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !fname.contains("stdout") {
                continue;
            }
            let content = fs::read_to_string(&path).unwrap();
            let mut node_sig_received: BTreeMap<u32, Vec<u64>> = BTreeMap::new();

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<JsonlEvent>(line) {
                    match event {
                        JsonlEvent::SigSent { ts_ms, .. } => {
                            sig_sent_timestamps.push(ts_ms);
                            validator_count = sig_sent_timestamps.len() as u64;
                        }
                        JsonlEvent::SigReceived {
                            node_id, duplicate, ts_ms, ..
                        } if !duplicate => {
                            node_sig_received.entry(node_id).or_default().push(ts_ms);
                        }
                        JsonlEvent::LocalProofGenerated {
                            node_id, latency_ms, ..
                        } => {
                            aggregator_proof_latency.insert(node_id, latency_ms);
                        }
                        _ => {}
                    }
                }
            }

            for (node_id, timestamps) in &node_sig_received {
                if timestamps.len() < 100 {
                    continue;
                }
                let threshold_index = ((timestamps.len() as f64) * 0.9) as usize;
                let mut sorted = timestamps.clone();
                sorted.sort();
                if threshold_index > 0 && threshold_index <= sorted.len() {
                    aggregator_threshold_ts.insert(*node_id, sorted[threshold_index - 1]);
                }
            }
        }
    }

    // Only keep aggregator nodes (those that emitted LocalProofGenerated)
    aggregator_threshold_ts.retain(|node_id, _| aggregator_proof_latency.contains_key(node_id));

    let sig_sent_median = median(&mut sig_sent_timestamps);

    let mut threshold_times: Vec<u64> = aggregator_threshold_ts.values().copied().collect();
    let threshold_median = median(&mut threshold_times);

    let mut compute_times: Vec<u64> = Vec::new();
    for (node_id, threshold_ts) in &aggregator_threshold_ts {
        if let Some(&latency) = aggregator_proof_latency.get(node_id) {
            compute_times.push(latency - threshold_ts);
        }
    }
    let compute_median = median(&mut compute_times);

    let mut proof_times: Vec<u64> = aggregator_proof_latency.values().copied().collect();
    let proof_median = median(&mut proof_times);

    let threshold_sig_count = ((validator_count as f64) * 0.9).round() as u64;

    let separator = "| ---------------------------- | ----------- |";
    println!();
    println!("| Stage                        | Median time |");
    println!("{separator}");
    println!("| Signatures sent              | {:>4} ms     |", sig_sent_median);
    println!("| Threshold reached ({} sigs) | {:>4} ms     |", threshold_sig_count, threshold_median);
    println!("| Aggregation compute          | {:>4} ms     |", compute_median);
    println!("| Local proof published        | {:>4} ms     |", proof_median);
    println!();
}
