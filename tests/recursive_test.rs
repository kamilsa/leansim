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

use leansim::config::plan::{AggregationPlan, NodeDuties, Seat, SubnetDuty};

/// aggregation-plan.json as shadow-sim.py writes it for the committee fixture in
/// tests/test_shadow_sim.py (RecursiveSeatTests): one group with members 0 and 1.
const PLAN: &str = r#"{"addrs": {"0": "/ip4/10.0.0.1/udp/9090/quic-v1", "1": "/ip4/10.1.0.1/udp/9090/quic-v1", "3": "/ip4/10.0.0.2/udp/9090/quic-v1", "6": "/ip4/10.0.0.4/udp/9090/quic-v1", "7": "/ip4/10.1.0.4/udp/9090/quic-v1"}, "arity": 2, "duties": {"0": {"seats": [{"announce_to": [], "children": [0, 1], "index": 0, "is_final": true, "layer": 1, "siblings": [1]}], "subnets": [{"announce_to": [1], "subnet": 0}, {"announce_to": [1], "subnet": 1}]}, "1": {"seats": [{"announce_to": [], "children": [0, 1], "index": 0, "is_final": true, "layer": 1, "siblings": [0]}], "subnets": [{"announce_to": [0], "subnet": 1}]}, "3": {"seats": [], "subnets": [{"announce_to": [0, 1], "subnet": 0}]}, "6": {"seats": [], "subnets": [{"announce_to": [0, 1], "subnet": 0}]}, "7": {"seats": [], "subnets": [{"announce_to": [0, 1], "subnet": 1}]}}, "groups": [{"children": [0, 1], "index": 0, "layer": 1, "members": [0, 1]}]}"#;

#[test]
fn launcher_plan_deserializes_into_duties() {
    let plan: AggregationPlan = serde_json::from_str(PLAN).unwrap();
    assert_eq!(
        plan.duties_of(0),
        NodeDuties {
            subnets: vec![
                SubnetDuty {
                    subnet: 0,
                    announce_to: vec![1]
                },
                SubnetDuty {
                    subnet: 1,
                    announce_to: vec![1]
                },
            ],
            seats: vec![Seat {
                layer: 1,
                index: 0,
                children: vec![0, 1],
                siblings: vec![1],
                announce_to: vec![],
                is_final: true,
            }],
        }
    );
    assert_eq!(plan.duties_of(2), NodeDuties::default());
    assert_eq!(plan.addrs[&7], "/ip4/10.1.0.4/udp/9090/quic-v1");
}

#[test]
fn proof_peers_are_every_host_a_duty_announces_to() {
    let plan: AggregationPlan = serde_json::from_str(PLAN).unwrap();
    assert_eq!(
        plan.duties_of(3).peers().into_iter().collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(
        plan.duties_of(0).peers().into_iter().collect::<Vec<_>>(),
        vec![1]
    );
}
