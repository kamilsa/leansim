//! The proof protocol between real swarms over QUIC.

use leansim::config::experiment::ExperimentConfig;
use leansim::network::swarm::{build_swarm, peer_id_for};

fn config() -> ExperimentConfig {
    toml::from_str("run_id = \"proofs\"\nvalidator_count = 4\nsubnet_count = 1\n").unwrap()
}

#[tokio::test]
async fn host_identities_derive_from_node_ids() {
    assert_eq!(peer_id_for(3), peer_id_for(3));
    assert_ne!(peer_id_for(3), peer_id_for(4));
    let swarm = build_swarm(3, "/ip4/127.0.0.1/udp/0/quic-v1", &config()).unwrap();
    assert_eq!(*swarm.local_peer_id(), peer_id_for(3));
}

use std::time::Duration;

use futures::StreamExt;
use leansim::messages::proof::{ProofId, ProofRequest, ProofResponse};
use leansim::network::swarm::SimBehaviourEvent;
use libp2p::{request_response, swarm::SwarmEvent};

#[tokio::test]
async fn an_announced_proof_is_pulled_with_its_full_payload() {
    let config = config();
    let mut holder = build_swarm(0, "/ip4/127.0.0.1/udp/0/quic-v1", &config).unwrap();
    let mut puller = build_swarm(1, "/ip4/127.0.0.1/udp/0/quic-v1", &config).unwrap();
    let puller_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = puller.select_next_some().await {
            break address;
        }
    };
    holder.add_peer_address(peer_id_for(1), puller_addr);
    let proof = ProofId { layer: 1, index: 2 };
    holder
        .behaviour_mut()
        .proofs
        .send_request(&peer_id_for(1), ProofRequest::Announce { proof, from: 0 });

    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            event = holder.select_next_some() => {
                if let SwarmEvent::Behaviour(SimBehaviourEvent::Proofs(request_response::Event::Message {
                    message: request_response::Message::Request {
                        request: ProofRequest::Fetch { proof: wanted, from: 1 },
                        channel,
                        ..
                    },
                    ..
                })) = event {
                    assert_eq!(wanted, proof);
                    let payload = vec![0; 262_144];
                    holder.behaviour_mut().proofs.send_response(channel, ProofResponse::Proof { proof, from: 0, payload }).unwrap();
                }
            }
            event = puller.select_next_some() => {
                if let SwarmEvent::Behaviour(SimBehaviourEvent::Proofs(request_response::Event::Message { peer, message })) = event {
                    match message {
                        request_response::Message::Request {
                            request: ProofRequest::Announce { proof: announced, from: 0 },
                            channel,
                            ..
                        } => {
                            puller.behaviour_mut().proofs.send_response(channel, ProofResponse::Ack).unwrap();
                            puller.behaviour_mut().proofs.send_request(&peer, ProofRequest::Fetch { proof: announced, from: 1 });
                        }
                        request_response::Message::Response {
                            response: ProofResponse::Proof { proof: got, payload, .. },
                            ..
                        } => {
                            assert_eq!(got, proof);
                            assert_eq!(payload.len(), 262_144);
                            return;
                        }
                        _ => {}
                    }
                }
            }
            _ = &mut deadline => panic!("the announced proof never arrived"),
        }
    }
}
