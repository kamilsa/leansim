use leansim::messages::proof::{ProofId, ProofRequest, ProofResponse};

#[test]
fn proof_messages_roundtrip() {
    let request = ProofRequest::Fetch {
        proof: ProofId { layer: 2, index: 5 },
        from: 9,
    };
    let bytes = bincode::serialize(&request).unwrap();
    assert_eq!(
        bincode::deserialize::<ProofRequest>(&bytes).unwrap(),
        request
    );
    let response = ProofResponse::Proof {
        proof: ProofId::subnet(3),
        from: 4,
        payload: vec![0; 16],
    };
    let bytes = bincode::serialize(&response).unwrap();
    assert_eq!(
        bincode::deserialize::<ProofResponse>(&bytes).unwrap(),
        response
    );
}
