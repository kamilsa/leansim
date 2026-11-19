use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAcceptance},
    identity, request_response,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::config::experiment::{ExperimentConfig, SignatureTransport};
use crate::messages::proof::{ProofRequest, ProofResponse};
use crate::messages::sync::{SyncRequest, SyncResponse};
use crate::messages::wire::WireMessage;
use crate::network::topics;
use crate::network::waggle_net::{SigWaggle, SigWaggleEvent};

/// Gossipsub, or waggle with `signature_transport = "waggle"`, carries signatures;
/// request-response carries proof announcements and pulls, and per-hop signature
/// sync between mesh neighbours.
#[derive(NetworkBehaviour)]
pub struct SimBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub proofs: request_response::cbor::Behaviour<ProofRequest, ProofResponse>,
    pub sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    /// Off, with no protocol on the wire, unless signatures travel over waggle.
    pub waggle: Toggle<SigWaggle>,
}

/// Protocol id of the proof announce-and-pull exchange.
pub const PROOF_PROTOCOL: &str = "/leansim/proof/1";

/// Protocol id of the signature sync between mesh neighbours.
pub const SYNC_PROTOCOL: &str = "/leansim/sigsync/1";

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

/// Churn counters of one host's connections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Peers told that this host restarted.
    pub restart_notices_sent: u64,
    /// Peers dropped and redialed because they restarted.
    pub restart_reconnects: u64,
}

/// This host's connections to one peer, from the first to come up until the last closes.
struct Link {
    since_unix_us: u64,
    /// Where the peer listens: the remote address of its latest connection.
    addr: Multiaddr,
}

/// What [`ExplicitPeerManager::intercept`] made of a swarm event.
enum Intercepted {
    Handled,
    /// The last connection to this peer closed.
    PeerGone(PeerId),
    Other(SwarmEvent<SimBehaviourEvent>),
}

fn unix_us(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_micros() as u64)
}

/// Tracks address-based explicit peers because generated configs do not know PeerIds in advance,
/// and every peer's connections, to reconnect cleanly to one that crashed and came back.
///
/// A crashed host sends nothing, so its peers keep their connections to it until QUIC's
/// idle timeout. If it rejoins sooner, a peer ends up with an old and a new connection, and
/// gossipsub, which only greets the first connection to a peer, never sends the newcomer its
/// subscriptions. So a rejoined host tells every peer when it came back
/// ([`SyncRequest::Restarted`]); a peer whose connections to it started before then drops
/// them all and dials it again.
pub struct ExplicitPeerManager {
    explicit_addrs: HashSet<Multiaddr>,
    selected_aggregator_addrs: HashSet<Multiaddr>,
    peers_by_addr: HashMap<Multiaddr, PeerId>,
    addrs_by_peer: HashMap<PeerId, Multiaddr>,
    links: HashMap<PeerId, Link>,
    /// Peers dropped as restarted, to dial once their last connection has closed.
    redial: HashMap<PeerId, Multiaddr>,
    /// On a host that crashed and came back: when it came back.
    rejoined_at: Option<u64>,
    notified: HashSet<PeerId>,
    notices: HashSet<request_response::OutboundRequestId>,
    stats: LinkStats,
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
            links: HashMap::new(),
            redial: HashMap::new(),
            rejoined_at: None,
            notified: HashSet::new(),
            notices: HashSet::new(),
            stats: LinkStats::default(),
        })
    }

    pub fn all_addrs(&self) -> impl Iterator<Item = &Multiaddr> {
        self.explicit_addrs.iter()
    }

    /// Marks this host as back from a crash since `since`: it tells every peer it
    /// connects to.
    pub fn announce_restart(&mut self, since: SystemTime) {
        self.rejoined_at = Some(unix_us(since));
    }

    pub fn link_stats(&self) -> LinkStats {
        self.stats
    }

    /// Handles connection events and restart notices; hands back any other event.
    fn intercept(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        event: SwarmEvent<SimBehaviourEvent>,
    ) -> Intercepted {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.on_established(swarm, peer_id, endpoint.get_remote_address());
                Intercepted::Handled
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if self.on_closed(swarm, peer_id, num_established) {
                    Intercepted::PeerGone(peer_id)
                } else {
                    Intercepted::Handled
                }
            }
            SwarmEvent::Behaviour(SimBehaviourEvent::Sync(request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request: SyncRequest::Restarted { since_unix_us },
                        channel,
                        ..
                    },
            })) => {
                let _ = swarm
                    .behaviour_mut()
                    .sync
                    .send_response(channel, SyncResponse::Ack);
                self.on_restart_notice(swarm, peer, since_unix_us);
                Intercepted::Handled
            }
            // The answer to a restart notice, or its loss when the peer dropped this host.
            SwarmEvent::Behaviour(SimBehaviourEvent::Sync(request_response::Event::Message {
                message: request_response::Message::Response { request_id, .. },
                ..
            })) if self.notices.remove(&request_id) => Intercepted::Handled,
            SwarmEvent::Behaviour(SimBehaviourEvent::Sync(
                request_response::Event::OutboundFailure { request_id, .. },
            )) if self.notices.remove(&request_id) => Intercepted::Handled,
            other => Intercepted::Other(other),
        }
    }

    fn on_established(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        peer_id: PeerId,
        remote_addr: &Multiaddr,
    ) {
        self.register_connection(swarm, peer_id, remote_addr);
        self.links
            .entry(peer_id)
            .and_modify(|link| link.addr = remote_addr.clone())
            .or_insert_with(|| Link {
                since_unix_us: unix_us(SystemTime::now()),
                addr: remote_addr.clone(),
            });
        if let Some(since_unix_us) = self.rejoined_at {
            if self.notified.insert(peer_id) {
                let request_id = swarm
                    .behaviour_mut()
                    .sync
                    .send_request(&peer_id, SyncRequest::Restarted { since_unix_us });
                self.notices.insert(request_id);
                self.stats.restart_notices_sent += 1;
            }
        }
    }

    /// Returns whether that was the last connection to the peer.
    fn on_closed(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        peer_id: PeerId,
        num_established: u32,
    ) -> bool {
        self.handle_disconnection(swarm, peer_id, num_established);
        if num_established != 0 {
            return false;
        }
        self.links.remove(&peer_id);
        if let Some(addr) = self.redial.remove(&peer_id) {
            self.stats.restart_reconnects += 1;
            if let Err(error) = swarm.dial(addr.clone()) {
                tracing::warn!(peer = %peer_id, address = %addr, "redial restarted peer failed: {error}");
            }
        }
        true
    }

    /// `peer` came back from a crash at `since_unix_us`. Connections that started
    /// before then include one to its previous session, and gossipsub's view of
    /// the peer dates from it: drop them all, and dial again once they are closed.
    fn on_restart_notice(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        peer: PeerId,
        since_unix_us: u64,
    ) {
        let Some(link) = self.links.get(&peer) else {
            return;
        };
        if link.since_unix_us < since_unix_us && !self.redial.contains_key(&peer) {
            self.redial.insert(peer, link.addr.clone());
            let _ = swarm.disconnect_peer_id(peer);
        }
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
    let waggle = (config.signature_transport == SignatureTransport::Waggle)
        .then(|| SigWaggle::new(config, u64::from(node_id)));
    let proofs = request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new(PROOF_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(10)),
    );
    let sync = request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new(SYNC_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(Duration::from_millis(config.sync_pull_timeout_ms.max(1))),
    );

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_key| SimBehaviour {
            gossipsub,
            proofs,
            sync,
            waggle: waggle.into(),
        })?
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
    let mut builder = gossipsub::ConfigBuilder::default();
    if !config.gossipsub_gossip {
        builder.gossip_lazy(0).gossip_factor(0.0);
    }
    let gossipsub_config = builder
        .mesh_n_low(config.gossipsub_mesh_n_low)
        .mesh_n(config.gossipsub_mesh_n)
        .mesh_n_high(config.gossipsub_mesh_n_high)
        .mesh_outbound_min(config.gossipsub_mesh_outbound_min)
        .heartbeat_interval(Duration::from_millis(
            config.gossipsub_heartbeat_interval_ms,
        ))
        .heartbeat_initial_delay(Duration::from_millis(config.heartbeat_initial_delay_ms()))
        .flood_publish(config.gossipsub_flood_publish)
        .idontwant_message_size_threshold(config.gossipsub_idontwant_threshold_bytes)
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

/// Marks `subnets`' topics as partial-message topics (EIP-8334 bundles). Call it
/// before subscribing, so subscriptions request partial messages.
pub fn enable_partial_topics(
    swarm: &mut Swarm<SimBehaviour>,
    subnets: impl IntoIterator<Item = u32>,
    run_id: &str,
) {
    for subnet in subnets {
        let topic = IdentTopic::new(topics::subnet_topic(run_id, subnet));
        swarm
            .behaviour_mut()
            .gossipsub
            .set_partial_topic(topic.hash());
    }
}

/// With waggle: accepts peers' subscriptions to `subnets`, the ones whose
/// signatures this host holds. Call it before the swarm is first polled.
pub fn track_waggle_subnets(
    swarm: &mut Swarm<SimBehaviour>,
    subnets: impl IntoIterator<Item = u32>,
) {
    if let Some(waggle) = swarm.behaviour_mut().waggle.as_mut() {
        waggle.track(subnets);
    }
}

/// Subscribes to the host's subnet topics: every subnet in `subscribed_subnets`
/// (its gossip membership, independent of what it publishes) plus every subnet
/// it aggregates, which an aggregator must hear whether subscribed or not.
/// The topics are waggle's when waggle carries signatures, else gossipsub's.
pub fn subscribe_to_topics(
    swarm: &mut Swarm<SimBehaviour>,
    aggregated_subnets: &BTreeSet<u32>,
    subscribed_subnets: &BTreeSet<u32>,
    run_id: &str,
) -> Result<()> {
    for subnet in subscribed_subnets.union(aggregated_subnets) {
        match swarm.behaviour_mut().waggle.as_mut() {
            Some(waggle) => waggle.subscribe(*subnet),
            None => {
                let topic = IdentTopic::new(topics::subnet_topic(run_id, *subnet));
                swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
            }
        }
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

/// What the node's event loop handles next.
pub enum NetEvent {
    Gossip(ReceivedMessage),
    /// An announcement or a pull; answer it through `channel`.
    ProofRequest {
        request: ProofRequest,
        channel: request_response::ResponseChannel<ProofResponse>,
    },
    /// The answer to one of this host's requests.
    ProofResponse {
        request_id: request_response::OutboundRequestId,
        response: ProofResponse,
    },
    /// One of this host's requests failed (dial failure, timeout, closed connection).
    ProofFailed {
        request_id: request_response::OutboundRequestId,
    },
    /// A mesh neighbour's sync message; answer it through `channel`.
    SyncRequest {
        peer: PeerId,
        request: SyncRequest,
        channel: request_response::ResponseChannel<SyncResponse>,
    },
    /// The answer to one of this host's sync messages.
    SyncResponse {
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        response: SyncResponse,
    },
    /// One of this host's sync messages failed.
    SyncFailed {
        request_id: request_response::OutboundRequestId,
    },
    /// A partial message: an EIP-8334 bundle, parts metadata, or both.
    Partial {
        peer: PeerId,
        message: gossipsub::PartialMessage,
    },
    /// The gossipsub heartbeat chose these gossip peers for a partial topic.
    PartialGossip {
        topic: gossipsub::TopicHash,
        peers: Vec<PeerId>,
    },
    /// A waggle message on a subnet: a bundle, parts metadata, or both.
    Waggle {
        peer: PeerId,
        subnet: u32,
        pieces: waggle::handler::ObjectPieces,
    },
    /// The last connection to a peer closed. If it connects again it may be a
    /// restarted host with no state, so nothing known about it holds any more.
    PeerDisconnected {
        peer: PeerId,
    },
}

/// Runs the swarm until the next gossip message or proof-protocol event.
/// Gossip messages carry the propagation source PeerId (the immediate mesh peer
/// that forwarded the message).
pub async fn next_event(
    swarm: &mut Swarm<SimBehaviour>,
    explicit_peers: &mut ExplicitPeerManager,
) -> Option<NetEvent> {
    loop {
        let event = swarm.next().await?;
        let event = match explicit_peers.intercept(swarm, event) {
            Intercepted::Handled => continue,
            Intercepted::PeerGone(peer) => return Some(NetEvent::PeerDisconnected { peer }),
            Intercepted::Other(event) => event,
        };
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
                    return Some(NetEvent::Gossip(ReceivedMessage {
                        wire_msg,
                        from_peer: peer_id,
                        is_duplicate: false,
                    }));
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
                    return Some(NetEvent::Gossip(ReceivedMessage {
                        wire_msg,
                        from_peer: peer_id,
                        is_duplicate: true,
                    }));
                }
            }
            SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Partial {
                propagation_source,
                message,
            })) => {
                return Some(NetEvent::Partial {
                    peer: propagation_source,
                    message,
                });
            }
            SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(
                gossipsub::Event::PartialGossip { topic, peers },
            )) => return Some(NetEvent::PartialGossip { topic, peers }),
            SwarmEvent::Behaviour(SimBehaviourEvent::Waggle(SigWaggleEvent::Pieces {
                peer,
                subnet,
                pieces,
            })) => {
                return Some(NetEvent::Waggle {
                    peer,
                    subnet,
                    pieces,
                });
            }
            SwarmEvent::Behaviour(SimBehaviourEvent::Proofs(
                request_response::Event::Message { message, .. },
            )) => {
                return Some(match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => NetEvent::ProofRequest { request, channel },
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => NetEvent::ProofResponse {
                        request_id,
                        response,
                    },
                });
            }
            SwarmEvent::Behaviour(SimBehaviourEvent::Proofs(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::warn!("proof request {request_id} failed: {error:?}");
                return Some(NetEvent::ProofFailed { request_id });
            }
            SwarmEvent::Behaviour(SimBehaviourEvent::Sync(request_response::Event::Message {
                peer,
                message,
            })) => {
                return Some(match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => NetEvent::SyncRequest {
                        peer,
                        request,
                        channel,
                    },
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => NetEvent::SyncResponse {
                        peer,
                        request_id,
                        response,
                    },
                });
            }
            SwarmEvent::Behaviour(SimBehaviourEvent::Sync(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::debug!("sync request {request_id} failed: {error:?}");
                return Some(NetEvent::SyncFailed { request_id });
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("listening on {address}");
            }
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
    let dialed = dial_peers(swarm, seeds, explicit_peers)?;
    let warmup = Duration::from_millis(warmup_ms(dialed, configured_warmup_ms));
    poll_warmup(swarm, explicit_peers, tokio::time::Instant::now() + warmup).await;
    await_selected_aggregators(swarm, explicit_peers, selected_aggregator_topics, warmup).await?;
    tracing::info!("mesh warmup complete");
    Ok(())
}

/// Dials `seeds` and every explicit peer; returns how many addresses that was.
pub fn dial_peers(
    swarm: &mut Swarm<SimBehaviour>,
    seeds: &[String],
    explicit_peers: &ExplicitPeerManager,
) -> Result<usize> {
    let mut dial_addrs = parse_addrs(seeds)?;
    dial_addrs.extend(explicit_peers.all_addrs().cloned());
    for ma in dial_addrs.iter().cloned() {
        match swarm.dial(ma.clone()) {
            Ok(()) => tracing::info!("dialing {ma}"),
            Err(e) => tracing::warn!("dial {ma} failed: {e}"),
        }
    }

    // A host with nothing to dial still waits out the warmup: its peers dial it
    // (the launcher has the subnet subscriber dial the smaller host), and signing
    // before they connect and graft drops its signatures with InsufficientPeers.
    if dial_addrs.is_empty() {
        tracing::info!("no seeds to dial; waiting for inbound peers");
    }
    Ok(dial_addrs.len())
}

/// After the warmup: every selected explicit aggregator must be connected and
/// subscribed. Missing ones are dialed again and given `retry` more.
pub async fn await_selected_aggregators(
    swarm: &mut Swarm<SimBehaviour>,
    explicit_peers: &mut ExplicitPeerManager,
    topics: &[IdentTopic],
    retry: Duration,
) -> Result<()> {
    if topics.is_empty() {
        return Ok(());
    }
    if !explicit_peers.selected_aggregators_ready(&swarm.behaviour().gossipsub, topics) {
        explicit_peers.dial_missing_selected_aggregators(swarm);
        poll_warmup(swarm, explicit_peers, tokio::time::Instant::now() + retry).await;
    }
    if !explicit_peers.selected_aggregators_ready(&swarm.behaviour().gossipsub, topics) {
        anyhow::bail!(
            "selected explicit aggregators were not connected and subscribed during warmup"
        );
    }
    Ok(())
}

/// Polls for connections and mesh formation until `until`. Gossip that arrives
/// meanwhile is dropped, so every host of a run warms up over the same time.
pub async fn poll_warmup(
    swarm: &mut Swarm<SimBehaviour>,
    explicit_peers: &mut ExplicitPeerManager,
    until: tokio::time::Instant,
) {
    loop {
        let remaining = until.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, swarm.next()).await {
            Ok(Some(event)) => {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = &event {
                    tracing::info!("connected to peer {peer_id}");
                }
                if let Intercepted::Other(SwarmEvent::OutgoingConnectionError { error, .. }) =
                    explicit_peers.intercept(swarm, event)
                {
                    tracing::warn!("outgoing connection error: {error}");
                }
            }
            Ok(None) => break,
            Err(_) => break, // timeout
        }
    }
}
