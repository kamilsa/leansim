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

use std::time::Duration;

use leansim::node::recursive::{Action, ProofExchange, RecursiveProof};
use tokio::time::Instant;

const PROOF_TIME: Duration = Duration::from_millis(276);
const G10: ProofId = ProofId { layer: 1, index: 0 };
const G11: ProofId = ProofId { layer: 1, index: 1 };
const ROOT: ProofId = ProofId { layer: 2, index: 0 };

const fn sub(subnet: u32) -> ProofId {
    ProofId {
        layer: 0,
        index: subnet,
    }
}

fn seat(
    layer: u32,
    index: u32,
    children: &[u32],
    siblings: &[u32],
    announce_to: &[u32],
    is_final: bool,
) -> Seat {
    Seat {
        layer,
        index,
        children: children.to_vec(),
        siblings: siblings.to_vec(),
        announce_to: announce_to.to_vec(),
        is_final,
    }
}

fn subnet(subnet: u32, announce_to: &[u32]) -> SubnetDuty {
    SubnetDuty {
        subnet,
        announce_to: announce_to.to_vec(),
    }
}

/// Duties from the 4-subnet, arity-2 plan in tests/test_shadow_sim.py
/// (AggregationPlanTests): groups 1/0 = {1, 2}, 1/1 = {3}, 2/0 = {2, 4}.
fn duties(node_id: u32) -> NodeDuties {
    match node_id {
        0 => NodeDuties {
            subnets: vec![subnet(0, &[1, 2])],
            seats: vec![],
        },
        1 => NodeDuties {
            subnets: vec![subnet(1, &[2]), subnet(2, &[3])],
            seats: vec![seat(1, 0, &[0, 1], &[2], &[2, 4], false)],
        },
        2 => NodeDuties {
            subnets: vec![subnet(3, &[3])],
            seats: vec![
                seat(1, 0, &[0, 1], &[1], &[4], false),
                seat(2, 0, &[0, 1], &[4], &[], true),
            ],
        },
        _ => unreachable!(),
    }
}

fn exchange(node_id: u32, proofs_per_child: usize) -> ProofExchange {
    ProofExchange::new(duties(node_id), proofs_per_child, PROOF_TIME)
}

#[test]
fn a_subnet_proof_is_announced_to_its_layer_one_group_once() {
    let mut node = exchange(0, 1);
    let now = Instant::now();
    assert_eq!(
        node.proof_ready(sub(0), now),
        vec![
            Action::Announce {
                to: 1,
                proof: sub(0)
            },
            Action::Announce {
                to: 2,
                proof: sub(0)
            }
        ]
    );
    assert_eq!(node.proof_ready(sub(0), now), vec![]);
    assert!(node.holds(sub(0)));
}

#[test]
fn a_member_pulls_from_the_first_announcer_and_retries_the_next_on_failure() {
    let mut node = exchange(2, 1);
    assert_eq!(
        node.announcement(sub(0), 0),
        vec![Action::Fetch {
            from: 0,
            proof: sub(0)
        }]
    );
    assert_eq!(node.announcement(sub(0), 5), vec![]);
    assert_eq!(
        node.fetch_failed(sub(0)),
        vec![Action::Fetch {
            from: 5,
            proof: sub(0)
        }]
    );
}

#[test]
fn two_proofs_per_child_pull_two_announcers_and_stop_once_one_arrives() {
    let mut node = exchange(2, 2);
    let now = Instant::now();
    assert_eq!(
        node.announcement(sub(0), 0),
        vec![Action::Fetch {
            from: 0,
            proof: sub(0)
        }]
    );
    assert_eq!(
        node.announcement(sub(0), 5),
        vec![Action::Fetch {
            from: 5,
            proof: sub(0)
        }]
    );
    assert_eq!(node.announcement(sub(0), 6), vec![]);
    // The first copy is advertised to the group's other member; the second changes nothing.
    assert_eq!(
        node.fetched(sub(0), now),
        vec![Action::Announce {
            to: 1,
            proof: sub(0)
        }]
    );
    assert_eq!(node.fetched(sub(0), now), vec![]);
    assert_eq!(node.announcement(sub(0), 7), vec![]);
}

#[test]
fn an_own_subnet_proof_counts_for_the_hosts_group_without_a_pull() {
    let mut node = exchange(1, 1);
    let now = Instant::now();
    // Subnet 1 feeds host 1's own group: announced once to its other member, host 2.
    assert_eq!(
        node.proof_ready(sub(1), now),
        vec![Action::Announce {
            to: 2,
            proof: sub(1)
        }]
    );
    assert_eq!(node.announcement(sub(1), 7), vec![]);
    // Subnet 2 feeds group 1/1, where host 1 has no seat.
    assert_eq!(
        node.proof_ready(sub(2), now),
        vec![Action::Announce {
            to: 3,
            proof: sub(2)
        }]
    );
}

#[test]
fn announcements_no_group_of_this_host_wants_are_ignored() {
    assert_eq!(exchange(0, 1).announcement(sub(1), 1), vec![]);
    assert_eq!(exchange(2, 1).announcement(sub(3), 9), vec![]);
}
