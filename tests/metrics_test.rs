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

#[test]
fn traffic_events_serialize_with_their_fields() {
    let bucket = JsonlEvent::TrafficBucket {
        node_id: 7,
        start_ms: 4_300,
        width_ms: 100,
        inbound: [("signature".to_string(), 1_200)].into_iter().collect(),
        outbound: Default::default(),
    };
    assert_eq!(
        serde_json::to_string(&bucket).unwrap(),
        r#"{"event":"TrafficBucket","node_id":7,"start_ms":4300,"width_ms":100,"inbound":{"signature":1200},"outbound":{}}"#
    );
    let peer = JsonlEvent::TrafficPeer {
        node_id: 7,
        peer: "node:9".into(),
        inbound_bytes: 10,
        outbound_bytes: 20,
        inbound_msgs: 1,
        outbound_msgs: 2,
    };
    assert_eq!(
        serde_json::to_string(&peer).unwrap(),
        r#"{"event":"TrafficPeer","node_id":7,"peer":"node:9","inbound_bytes":10,"outbound_bytes":20,"inbound_msgs":1,"outbound_msgs":2}"#
    );
}
