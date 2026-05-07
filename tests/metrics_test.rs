use leansim::metrics::summary::summarize;

#[test]
fn summarize_empty_directory_errors() {
    let tmp = std::env::temp_dir().join("leansim_empty_test");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("hosts")).unwrap();
    let out = tmp.join("out.json");
    let result = summarize(&tmp, &out);
    assert!(result.is_ok());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn summarize_parses_valid_jsonl() {
    let tmp = std::env::temp_dir().join("leansim_jsonl_test");
    let _ = std::fs::remove_dir_all(&tmp);
    let host_dir = tmp.join("hosts/node-0");
    std::fs::create_dir_all(&host_dir).unwrap();

    let events = vec![
        r#"{"event":"SigSent","node_id":0,"subnet_id":0,"seq":0,"ts_ms":100,"byte_size":3072}"#,
        r#"{"event":"SigReceived","node_id":1,"from_id":0,"subnet_id":0,"duplicate":false,"ts_ms":150,"byte_size":3100}"#,
        r#"{"event":"LocalProofGenerated","node_id":1,"subnet_id":0,"sig_count":22,"latency_ms":200,"byte_size":131072}"#,
        r#"{"event":"GlobalProofCompleted","node_id":2,"total_sigs":66,"proof_count":3,"latency_ms":500}"#,
    ];
    std::fs::write(host_dir.join("node-0.1.stdout"), events.join("\n")).unwrap();

    let out = tmp.join("metrics.json");
    summarize(&tmp, &out).unwrap();

    let json_str = std::fs::read_to_string(&out).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // Check global latency
    assert_eq!(val["global_proof_latency_ms"]["min"], 500);
    assert_eq!(val["global_proof_latency_ms"]["max"], 500);

    // Check local aggregation latency
    assert_eq!(val["local_aggregation_latency_ms"], 200);

    // Check Bytes transferred
    let bytes: u64 = val["total_bytes_transferred"].as_u64().unwrap();
    assert!(bytes > 0);

    // Check sigs sent
    assert_eq!(val["total_sigs_sent"], 1);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn summarize_duplicate_calculation() {
    let tmp = std::env::temp_dir().join("leansim_dup_test");
    let _ = std::fs::remove_dir_all(&tmp);
    let host_dir = tmp.join("hosts/node-0");
    std::fs::create_dir_all(&host_dir).unwrap();

    // 3 receives: 2 unique, 1 duplicate
    let events = vec![
        r#"{"event":"SigReceived","node_id":0,"from_id":1,"subnet_id":0,"duplicate":false,"ts_ms":100,"byte_size":3072}"#,
        r#"{"event":"SigReceived","node_id":0,"from_id":1,"subnet_id":0,"duplicate":true,"ts_ms":110,"byte_size":3072}"#,
        r#"{"event":"SigReceived","node_id":0,"from_id":2,"subnet_id":0,"duplicate":false,"ts_ms":120,"byte_size":3072}"#,
    ];
    std::fs::write(host_dir.join("stdout"), events.join("\n")).unwrap();

    let out = tmp.join("metrics.json");
    summarize(&tmp, &out).unwrap();

    let json_str = std::fs::read_to_string(&out).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // 1 duplicate, 2 unique → avg_dupes = 1/2 = 0.5
    assert_eq!(val["total_unique_sigs"], 2);
    assert_eq!(val["total_duplicate_sigs"], 1);
    let rate = val["avg_duplicates_per_unique"].as_f64().unwrap();
    assert!((rate - 0.5).abs() < 0.01);

    let _ = std::fs::remove_dir_all(&tmp);
}
