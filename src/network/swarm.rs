use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAcceptance},
    identity, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::config::experiment::ExperimentConfig;
use crate::messages::proof::{ProofRequest, ProofResponse};
use crate::messages::wire::WireMessage;
use crate::network::topics;

/// Gossipsub carries signatures; request-response carries proof announcements and pulls.
#[derive(NetworkBehaviour)]
pub struct SimBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub proofs: request_response::cbor::Behaviour<ProofRequest, ProofResponse>,
}

/// Protocol id of the proof announce-and-pull exchange.
pub const PROOF_PROTOCOL: &str = "/leansim/proof/1";

/// A host's libp2p identity, derived from its node id so any host can name
/// another's PeerId from the launcher's plan without a discovery round.
pub fn node_keypair(node_id: u32) -> identity::Keypair {
    let mut hasher = Sha256::new();
    hasher.update(b"leansim-node-key");
    hasher.update(node_id.to_le_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hasher.finalize());
    identity::Keypair::ed25519_from_bytes(seed)
        .expect("32 bytes are always a valid ed25519 secret key")
}

pub fn peer_id_for(node_id: u32) -> PeerId {
    node_keypair(node_id).public().to_peer_id()
}

/// Tracks address-based explicit peers because generated configs do not know PeerIds in advance.
pub struct ExplicitPeerManager {
    explicit_addrs: HashSet<Multiaddr>,
    selected_aggregator_addrs: HashSet<Multiaddr>,
    peers_by_addr: HashMap<Multiaddr, PeerId>,
    addrs_by_peer: HashMap<PeerId, Multiaddr>,
}

impl ExplicitPeerManager {
    pub fn new(
        explicit_peer_addrs: &[String],
        selected_aggregator_addrs: &[String],
    ) -> Result<Self> {
        let explicit_addrs = parse_addrs(explicit_peer_addrs)?;
        let selected_aggregator_addrs = parse_addrs(selected_aggregator_addrs)?;
        if !selected_aggregator_addrs.is_subset(&explicit_addrs) {
            anyhow::bail!("selected aggregator addresses must also be explicit peers");
        }
        Ok(Self {
            explicit_addrs,
            selected_aggregator_addrs,
            peers_by_addr: HashMap::new(),
            addrs_by_peer: HashMap::new(),
        })
    }

    pub fn all_addrs(&self) -> impl Iterator<Item = &Multiaddr> {
        self.explicit_addrs.iter()
    }

    fn dial_missing_selected_aggregators(&self, swarm: &mut Swarm<SimBehaviour>) {
        for addr in &self.selected_aggregator_addrs {
            if self.peers_by_addr.contains_key(addr) {
                continue;
            }
            match swarm.dial(addr.clone()) {
                Ok(()) => tracing::info!(address = %addr, "retrying selected explicit aggregator"),
                Err(error) => {
                    tracing::warn!(address = %addr, "retry selected explicit aggregator failed: {error}")
                }
            }
        }
    }

    fn register_connection(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        peer_id: PeerId,
        remote_addr: &Multiaddr,
    ) {
        if !self.explicit_addrs.contains(remote_addr) {
            return;
        }

        if let Some(previous_addr) = self.addrs_by_peer.insert(peer_id, remote_addr.clone()) {
            self.peers_by_addr.remove(&previous_addr);
        }
        self.peers_by_addr.insert(remote_addr.clone(), peer_id);
        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
        tracing::info!(peer = %peer_id, address = %remote_addr, "registered explicit peer");
    }

    fn handle_disconnection(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        peer_id: PeerId,
        remaining_connections: u32,
    ) {
        if remaining_connections != 0 {
            return;
        }
        let Some(addr) = self.addrs_by_peer.remove(&peer_id) else {
            return;
        };
        self.peers_by_addr.remove(&addr);
        swarm
            .behaviour_mut()
            .gossipsub
            .remove_explicit_peer(&peer_id);
        match swarm.dial(addr.clone()) {
            Ok(()) => tracing::info!(peer = %peer_id, address = %addr, "redialing explicit peer"),
            Err(error) => {
                tracing::warn!(peer = %peer_id, address = %addr, "redial explicit peer failed: {error}")
            }
        }
    }

    /// Every selected aggregator is connected and subscribed to one of this host's
    /// signing subnets (an aggregator is selected for a subnet it collects).
    fn selected_aggregators_ready(
        &self,
        gossipsub: &gossipsub::Behaviour,
        topics: &[IdentTopic],
    ) -> bool {
        let topic_hashes: Vec<_> = topics.iter().map(IdentTopic::hash).collect();
        self.selected_aggregator_addrs.iter().all(|addr| {
            self.peers_by_addr.get(addr).is_some_and(|peer_id| {
                topic_hashes
                    .iter()
                    .any(|topic_hash| gossipsub.is_peer_subscribed(peer_id, topic_hash))
            })
        })
    }
}

fn parse_addrs(addrs: &[String]) -> Result<HashSet<Multiaddr>> {
    addrs
        .iter()
        .map(|addr| addr.parse::<Multiaddr>().map_err(anyhow::Error::from))
        .collect()
}

/// Builds a libp2p Swarm with QUIC transport and gossipsub.
pub fn build_swarm(
    node_id: u32,
    listen_addr: &str,
    config: &ExperimentConfig,
) -> Result<Swarm<SimBehaviour>> {
    let id_keys = node_keypair(node_id);

    let gossipsub = build_gossipsub(&id_keys, config)?;
    let proofs = request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new(PROOF_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(10)),
    );

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_key| SimBehaviour { gossipsub, proofs })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let addr: Multiaddr = listen_addr.parse()?;
    swarm.listen_on(addr)?;

    Ok(swarm)
}

/// Builds the gossipsub behaviour with experiment-configured mesh parameters.
fn build_gossipsub(
    key: &identity::Keypair,
    config: &ExperimentConfig,
) -> Result<gossipsub::Behaviour> {
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .mesh_n_low(config.gossipsub_mesh_n_low)
        .mesh_n(config.gossipsub_mesh_n)
        .mesh_n_high(config.gossipsub_mesh_n_high)
        .mesh_outbound_min(config.gossipsub_mesh_outbound_min)
        .heartbeat_interval(Duration::from_millis(
            config.gossipsub_heartbeat_interval_ms,
        ))
        .heartbeat_initial_delay(Duration::from_millis(config.heartbeat_initial_delay_ms()))
        .flood_publish(config.gossipsub_flood_publish)
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

/// Subscribes to the host's subnet topics: every subnet in `subscribed_subnets`
/// (its gossip membership, independent of what it publishes) plus every subnet
/// it aggregates, which an aggregator must hear whether subscribed or not.
pub fn subscribe_to_topics(
    swarm: &mut Swarm<SimBehaviour>,
    aggregated_subnets: &BTreeSet<u32>,
    subscribed_subnets: &BTreeSet<u32>,
    run_id: &str,
) -> Result<()> {
    for subnet in subscribed_subnets.union(aggregated_subnets) {
        let topic = IdentTopic::new(topics::subnet_topic(run_id, *subnet));
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    }
    Ok(())
}

/// Publishes a wire message to a gossipsub topic.
/// InsufficientPeers errors are logged but not propagated — the mesh may still be forming.
pub fn publish(
    swarm: &mut Swarm<SimBehaviour>,
    topic: &IdentTopic,
    msg: &WireMessage,
) -> Result<()> {
    let data = msg.encode();
    match swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
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
pub async fn next_message(
    swarm: &mut Swarm<SimBehaviour>,
    explicit_peers: &mut ExplicitPeerManager,
) -> Option<ReceivedMessage> {
    loop {
        let event = swarm.next().await?;
        match event {
            SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source: peer_id,
                message_id: _id,
                message,
            })) => match WireMessage::decode(&message.data) {
                Ok(wire_msg) => {
                    let _ = swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
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
                    let _ = swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &_id,
                            &peer_id,
                            MessageAcceptance::Reject,
                        );
                }
            },
            SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(
                gossipsub::Event::DuplicateMessage {
                    propagation_source: peer_id,
                    message_id: _id,
                    raw_data,
                    ..
                },
            )) => {
                // Decode the raw data to count the duplicate.
                // Use `Ignore` to prevent re-forwarding — the message was already
                // forwarded when first seen. Accepting duplicates causes a storm.
                if let Ok(wire_msg) = WireMessage::decode(&raw_data) {
                    let _ = swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
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
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => explicit_peers.register_connection(swarm, peer_id, endpoint.get_remote_address()),
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => explicit_peers.handle_disconnection(swarm, peer_id, num_established),
            _ => {}
        }
    }
}

/// Dial all seed peers, then poll for connections and mesh formation.
/// Warmup before signing: the run-wide `mesh_warmup_ms` when the launcher set
/// one (it mirrors this rule with the busiest host's dial count), otherwise
/// longer for a host that dials many peers.
pub fn warmup_ms(dial_count: usize, configured: Option<u64>) -> u64 {
    configured.unwrap_or(if dial_count > 200 { 3000 } else { 1500 })
}

pub async fn dial_seeds(
    swarm: &mut Swarm<SimBehaviour>,
    seeds: &[String],
    explicit_peers: &mut ExplicitPeerManager,
    selected_aggregator_topics: &[IdentTopic],
    configured_warmup_ms: Option<u64>,
) -> Result<()> {
    let mut dial_addrs = parse_addrs(seeds)?;
    dial_addrs.extend(explicit_peers.all_addrs().cloned());
    for ma in dial_addrs.iter().cloned() {
        match swarm.dial(ma.clone()) {
            Ok(()) => tracing::info!("dialing {ma}"),
            Err(e) => tracing::warn!("dial {ma} failed: {e}"),
        }
    }

    if seeds.is_empty() && explicit_peers.explicit_addrs.is_empty() {
        tracing::info!("no seeds to dial");
        return Ok(());
    }

    // Poll for connection events and mesh formation.
    let warmup_ms = warmup_ms(dial_addrs.len(), configured_warmup_ms);
    poll_warmup(swarm, explicit_peers, warmup_ms).await;

    if !selected_aggregator_topics.is_empty() {
        let topics = selected_aggregator_topics;
        if !explicit_peers.selected_aggregators_ready(&swarm.behaviour().gossipsub, topics) {
            explicit_peers.dial_missing_selected_aggregators(swarm);
            poll_warmup(swarm, explicit_peers, warmup_ms).await;
        }
        if !explicit_peers.selected_aggregators_ready(&swarm.behaviour().gossipsub, topics) {
            anyhow::bail!(
                "selected explicit aggregators were not connected and subscribed during warmup"
            );
        }
    }

    tracing::info!("mesh warmup complete");
    Ok(())
}

async fn poll_warmup(
    swarm: &mut Swarm<SimBehaviour>,
    explicit_peers: &mut ExplicitPeerManager,
    warmup_ms: u64,
) {
    let warmup = tokio::time::Instant::now() + std::time::Duration::from_millis(warmup_ms);
    loop {
        let remaining = warmup.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, swarm.next()).await {
            Ok(Some(SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            })) => {
                tracing::info!("connected to peer {peer_id}");
                explicit_peers.register_connection(swarm, peer_id, endpoint.get_remote_address());
            }
            Ok(Some(SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            })) => {
                explicit_peers.handle_disconnection(swarm, peer_id, num_established);
            }
            Ok(Some(SwarmEvent::OutgoingConnectionError { error, .. })) => {
                tracing::warn!("outgoing connection error: {error}");
            }
            Ok(None) => break,
            Err(_) => break, // timeout
            _ => {}
        }
    }
}
