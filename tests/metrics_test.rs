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

#[test]
fn recursive_proof_events_serialize_with_their_fields() {
    let line = serde_json::to_string(&JsonlEvent::RecursiveProofGenerated {
        node_id: 4,
        layer: 2,
        index: 0,
        inputs: 2,
        is_final: true,
        ts_ms: 6100,
    })
    .unwrap();
    assert_eq!(
        line,
        r#"{"event":"RecursiveProofGenerated","node_id":4,"layer":2,"index":0,"inputs":2,"is_final":true,"ts_ms":6100}"#
    );
}
