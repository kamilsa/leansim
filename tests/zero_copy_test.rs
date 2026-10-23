//! Checks that gossipsub messages sent over QUIC arrive intact while QUIC keeps references to the
//! message data instead of copying it.

use std::time::Duration;

use futures::StreamExt;
use leansim::config::experiment::ExperimentConfig;
use leansim::network::swarm::{build_swarm, SimBehaviourEvent};
use libp2p::{gossipsub, swarm::SwarmEvent};

fn config() -> ExperimentConfig {
    toml::from_str(
        r#"
run_id = "zero-copy"
validator_count = 4
subnet_count = 1
gossipsub_mesh_n_low = 1
gossipsub_mesh_n = 2
gossipsub_mesh_n_high = 3
gossipsub_mesh_outbound_min = 0
gossipsub_heartbeat_interval_ms = 100
"#,
    )
    .unwrap()
}

#[tokio::test]
async fn published_messages_arrive_intact_and_share_their_data_with_quic() {
    let config = config();
    let mut sender = build_swarm(0, "/ip4/127.0.0.1/udp/0/quic-v1", &config).unwrap();
    let mut receiver = build_swarm(1, "/ip4/127.0.0.1/udp/0/quic-v1", &config).unwrap();
    let topic = gossipsub::IdentTopic::new("zero-copy");
    sender.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    receiver
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .unwrap();

    let receiver_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = receiver.select_next_some().await {
            break address;
        }
    };
    sender.dial(receiver_addr).unwrap();
    let receiver_id = *receiver.local_peer_id();

    let messages: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 1200]).collect();
    let mut published = false;
    let mut received = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    while received.len() < messages.len() {
        tokio::select! {
            _ = sender.select_next_some() => {}
            event = receiver.select_next_some() => {
                if let SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) = event {
                    received.push(message.data);
                }
            }
            _ = tick.tick(), if !published => {
                if sender.behaviour().gossipsub.mesh_peers(&topic.hash()).any(|p| *p == receiver_id) {
                    for message in &messages {
                        sender.behaviour_mut().gossipsub.publish(topic.clone(), message.clone()).unwrap();
                    }
                    published = true;
                }
            }
            _ = &mut deadline => {
                panic!("received {} of {} messages", received.len(), messages.len())
            }
        }
    }

    // The handler sends queued messages last in, first out.
    received.sort();
    assert_eq!(received, messages);

    let stats = zero_copy_write::stats();
    println!("{stats:?}");
    let data_len = messages.iter().map(Vec::len).sum::<usize>() as u64;
    assert!(stats.shared_bytes >= data_len, "{stats:?}");
}
