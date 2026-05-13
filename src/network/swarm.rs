use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAcceptance},
    identity,
    swarm::SwarmEvent,
    Multiaddr, Swarm,
};
use std::time::Duration;

use crate::config::experiment::{ExperimentConfig, NodeRole};
use crate::messages::wire::WireMessage;
use crate::network::topics;

/// The concrete behaviour type used throughout the simulator.
pub type GossipsubBehaviour = gossipsub::Behaviour;

/// Builds a libp2p Swarm with QUIC transport and gossipsub.
pub fn build_swarm(
    _node_id: u32,
    listen_addr: &str,
    config: &ExperimentConfig,
) -> Result<Swarm<GossipsubBehaviour>> {
    let id_keys = identity::Keypair::generate_ed25519();

    let gossipsub_behaviour = build_gossipsub(&id_keys, config)?;

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_key| gossipsub_behaviour)?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(Duration::from_secs(120))
        })
        .build();

    let addr: Multiaddr = listen_addr.parse()?;
    swarm.listen_on(addr)?;

    Ok(swarm)
}

/// Builds the gossipsub behaviour with experiment-configured mesh parameters.
fn build_gossipsub(key: &identity::Keypair, config: &ExperimentConfig) -> Result<GossipsubBehaviour> {
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .mesh_n_low(config.gossipsub_mesh_n_low)
        .mesh_n(config.gossipsub_mesh_n)
        .mesh_n_high(config.gossipsub_mesh_n_high)
        .mesh_outbound_min(config.gossipsub_mesh_outbound_min)
        .heartbeat_interval(Duration::from_millis(config.gossipsub_heartbeat_interval_ms))
        .max_transmit_size(2 * 1024 * 1024) // 2 MiB for large proof messages
        .validate_messages()
        .build()
        .map_err(|e| anyhow::anyhow!("gossipsub config error: {e}"))?;

    gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
    )
    .map_err(|e| anyhow::anyhow!("gossipsub behaviour error: {e}"))
}

/// Subscribes to the topics relevant to the given role.
pub fn subscribe_to_topics(
    swarm: &mut Swarm<GossipsubBehaviour>,
    role: NodeRole,
    subnet_id: u32,
    run_id: &str,
) -> Result<()> {
    match role {
        NodeRole::Validator => {
            let topic = IdentTopic::new(topics::subnet_topic(run_id, subnet_id));
            swarm.behaviour_mut().subscribe(&topic)?;
        }
        NodeRole::LocalAggregator => {
            let subnet_topic = IdentTopic::new(topics::subnet_topic(run_id, subnet_id));
            let agg_topic = IdentTopic::new(topics::aggregation_topic(run_id));
            swarm.behaviour_mut().subscribe(&subnet_topic)?;
            swarm.behaviour_mut().subscribe(&agg_topic)?;
        }
        NodeRole::GlobalAggregator => {
            let agg_topic = IdentTopic::new(topics::aggregation_topic(run_id));
            swarm.behaviour_mut().subscribe(&agg_topic)?;
        }
    }
    Ok(())
}

/// Publishes a wire message to a gossipsub topic.
/// InsufficientPeers errors are logged but not propagated — the mesh may still be forming.
pub fn publish(
    swarm: &mut Swarm<GossipsubBehaviour>,
    topic: &IdentTopic,
    msg: &WireMessage,
) -> Result<()> {
    let data = msg.encode();
    match swarm.behaviour_mut().publish(topic.clone(), data) {
        Ok(_msg_id) => Ok(()),
        Err(gossipsub::PublishError::InsufficientPeers) => {
            tracing::warn!("publish to {topic}: insufficient peers, mesh may still be forming");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("publish error: {e}")),
    }
}

/// Result from `next_message`: the decoded WireMessage, the forwarding PeerId,
/// and whether this message is a duplicate (already seen by gossipsub).
pub struct ReceivedMessage {
    pub wire_msg: WireMessage,
    pub from_peer: libp2p::PeerId,
    pub is_duplicate: bool,
}

/// Runs the main event loop until the swarm is done or timeout.
/// Returns on gossipsub messages, forwarding deserialized WireMessages and the
/// propagation source PeerId (the immediate mesh peer that forwarded the message).
pub async fn next_message(swarm: &mut Swarm<GossipsubBehaviour>) -> Option<ReceivedMessage> {
    loop {
        let event = swarm.next().await?;
        match event {
            SwarmEvent::Behaviour(gossipsub::Event::Message {
                propagation_source: peer_id,
                message_id: _id,
                message,
            }) => {
                match WireMessage::decode(&message.data) {
                    Ok(wire_msg) => {
                        let _ = swarm.behaviour_mut().report_message_validation_result(
                            &_id,
                            &peer_id,
                            MessageAcceptance::Accept,
                        );
                        return Some(ReceivedMessage {
                            wire_msg,
                            from_peer: peer_id,
                            is_duplicate: false,
                        });
                    }
                    Err(_) => {
                        let _ = swarm.behaviour_mut().report_message_validation_result(
                            &_id,
                            &peer_id,
                            MessageAcceptance::Reject,
                        );
                    }
                }
            }
            SwarmEvent::Behaviour(gossipsub::Event::DuplicateMessage {
                propagation_source: peer_id,
                message_id: _id,
                raw_data,
                ..
            }) => {
                // Decode the raw data to count the duplicate.
                // Use `Ignore` to prevent re-forwarding — the message was already
                // forwarded when first seen. Accepting duplicates causes a storm.
                if let Ok(wire_msg) = WireMessage::decode(&raw_data) {
                    let _ = swarm.behaviour_mut().report_message_validation_result(
                        &_id,
                        &peer_id,
                        MessageAcceptance::Ignore,
                    );
                    return Some(ReceivedMessage {
                        wire_msg,
                        from_peer: peer_id,
                        is_duplicate: true,
                    });
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("listening on {address}");
            }
            _ => {}
        }
    }
}

/// Dial all seed peers (fire and forget), then wait for connections and mesh to form.
pub async fn dial_seeds(swarm: &mut Swarm<GossipsubBehaviour>, seeds: &[String]) -> Result<()> {
    for seed in seeds {
        let ma: Multiaddr = seed.parse()?;
        match swarm.dial(ma.clone()) {
            Ok(()) => tracing::info!("dialing {seed}"),
            Err(e) => tracing::warn!("dial {seed} failed: {e}"),
        }
    }

    // Poll for connection events and mesh formation.
    // Mesh needs GRAFT/PRUNE exchange across diameter of the network.
    // Base time covers connection establishment + 2 heartbeat cycles.
    let warmup_ms = if seeds.len() > 200 { 3000 } else { 1500 };
    let warmup = tokio::time::Instant::now()
        + std::time::Duration::from_millis(warmup_ms);
    loop {
        let remaining = warmup.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, swarm.next()).await {
            Ok(Some(SwarmEvent::ConnectionEstablished { peer_id, .. })) => {
                tracing::info!("connected to peer {peer_id}");
            }
            Ok(Some(SwarmEvent::OutgoingConnectionError { error, .. })) => {
                tracing::warn!("outgoing connection error: {error}");
            }
            Ok(None) => break,
            Err(_) => break, // timeout
            _ => {}
        }
    }

    tracing::info!("mesh warmup complete");
    Ok(())
}
