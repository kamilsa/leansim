use leansim::metrics::events::JsonlEvent;

#[test]
fn events_deserialize_from_jsonl() {
    let event: JsonlEvent = serde_json::from_str(
        r#"{"event":"SigReceived","node_id":1,"from_id":0,"from_peer_id":"peer","subnet_id":0,"duplicate":false,"ts_ms":150,"byte_size":3100}"#,
    )
    .unwrap();

    assert!(matches!(
        event,
        JsonlEvent::SigReceived {
            node_id: 1,
            from_id: 0,
            duplicate: false,
            ..
        }
    ));
}
