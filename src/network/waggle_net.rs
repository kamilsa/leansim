//! Waggle in the swarm: the vendored waggle behaviour, which opens a stream per
//! subscribed topic and peer and leaves the rest to the application, plus what
//! leansim needs around it. The topic of a subnet is its gossipsub topic string.
//!
//! - Subscribing to a subnet opens a stream to every connected peer; the peers
//!   that hold the subnet's signatures write to it. What they send comes out of
//!   the swarm as [`SigWaggleEvent::Pieces`].
//! - A peer that subscribes to a subnet this host tracks is kept with the sender
//!   of its stream, also while the host warms up and drops other swarm events.
//!   A subscription to any other topic is refused by dropping its sender.
//! - Waggle has no mesh, so this host picks whom it pushes to: `push_peers`
//!   subscribers per subnet, at random, kept until they leave ([`PeerSet`]).
//!   Other subscribers are gossip peers, a few of them picked anew each round.
//! - With hashed push selection every subscriber is a push target, and
//!   [`crate::node::bundles::BundleSync`] picks among them per signature. Any
//!   subscriber can then be a gossip peer.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::NonZeroUsize;
use std::task::{Context, Poll};

use futures::stream::{BoxStream, SelectAll};
use futures::StreamExt;
use libp2p::core::{transport::PortUse, Endpoint};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use rand::rngs::StdRng;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use waggle::behaviour::{Behaviour, Event};
use waggle::handler::{Handler, ObjectPieces, PieceSender, TopicEvent};

use crate::config::experiment::ExperimentConfig;
use crate::network::topics;

/// What waggle tells the node.
#[derive(Debug)]
pub enum SigWaggleEvent {
    /// A peer sent a message on a subnet this host subscribes to.
    Pieces {
        peer: PeerId,
        subnet: u32,
        pieces: ObjectPieces,
    },
}

/// The subscribers of one subnet and the ones this host pushes to.
#[derive(Debug, Clone)]
pub struct PeerSet<P> {
    subscribers: BTreeSet<P>,
    push: BTreeSet<P>,
}

impl<P> Default for PeerSet<P> {
    fn default() -> Self {
        Self {
            subscribers: BTreeSet::new(),
            push: BTreeSet::new(),
        }
    }
}

impl<P: Copy + Ord> PeerSet<P> {
    pub fn insert(&mut self, peer: P) {
        self.subscribers.insert(peer);
    }

    pub fn remove(&mut self, peer: &P) {
        self.subscribers.remove(peer);
        self.push.remove(peer);
    }

    pub fn len(&self) -> usize {
        self.subscribers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.subscribers.is_empty()
    }

    pub fn contains(&self, peer: &P) -> bool {
        self.subscribers.contains(peer)
    }

    /// The push targets: up to `limit` subscribers, every one of them with a
    /// limit of 0. Targets stay until they unsubscribe; free places go to
    /// subscribers picked at random.
    pub fn push_targets(&mut self, limit: usize, rng: &mut StdRng) -> Vec<P> {
        if limit == 0 {
            self.push.clone_from(&self.subscribers);
        } else if self.push.len() < limit {
            let free = limit - self.push.len();
            let picked = self
                .subscribers
                .difference(&self.push)
                .copied()
                .choose_multiple(rng, free);
            self.push.extend(picked);
        }
        self.push.iter().copied().collect()
    }

    /// Up to `count` subscribers that are not push targets, picked at random.
    pub fn gossip_peers(&mut self, limit: usize, count: usize, rng: &mut StdRng) -> Vec<P> {
        self.push_targets(limit, rng);
        let mut peers = self
            .subscribers
            .difference(&self.push)
            .copied()
            .choose_multiple(rng, count);
        peers.sort_unstable();
        peers
    }

    /// Up to `count` subscribers, picked at random.
    pub fn sample(&self, count: usize, rng: &mut StdRng) -> Vec<P> {
        let mut peers = self.subscribers.iter().copied().choose_multiple(rng, count);
        peers.sort_unstable();
        peers
    }
}

/// A peer's subscription to one of this host's subnets.
struct Subscription {
    /// The connection it subscribed on.
    connection_id: ConnectionId,
    /// Queues messages on the peer's subscription stream.
    sender: PieceSender,
}

/// Subnet signatures over waggle.
pub struct SigWaggle {
    waggle: Behaviour,
    run_id: String,
    push_peers: usize,
    gossip_peers: usize,
    /// Push peers are picked per signature, among every subscriber.
    hashed: bool,
    /// The subnet of each tracked subnet's topic.
    subnets: HashMap<Vec<u8>, u32>,
    peers: BTreeMap<u32, PeerSet<PeerId>>,
    subscriptions: HashMap<(u32, PeerId), Subscription>,
    /// The events of every subscribed subnet topic, with the subnet.
    inbox: SelectAll<BoxStream<'static, (u32, TopicEvent)>>,
    rng: StdRng,
}

impl SigWaggle {
    /// `seed` picks this host's push and gossip peers.
    pub fn new(config: &ExperimentConfig, seed: u64) -> Self {
        let queue = |len: usize| NonZeroUsize::new(len.max(1)).expect("at least 1");
        let waggle_config = waggle::config::Config::default()
            .set_max_send_queue_limit(queue(config.waggle_max_send_queue))
            .set_max_receive_queue_len(queue(config.waggle_max_receive_queue))
            .set_max_topic_subscription(config.waggle_max_topic_subscription())
            .set_max_protobuf_size(config.waggle_max_message_bytes());
        Self {
            waggle: Behaviour::new(waggle_config),
            run_id: config.run_id.clone(),
            // Hashed selection caps the push peers of each signature, not of the subnet.
            push_peers: if config.waggle_hashed() {
                0
            } else {
                config.waggle_push_peers
            },
            hashed: config.waggle_hashed(),
            gossip_peers: config.waggle_gossip_peers,
            subnets: HashMap::new(),
            peers: BTreeMap::new(),
            subscriptions: HashMap::new(),
            inbox: SelectAll::new(),
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Accepts peers' subscriptions to `subnets`: the ones whose signatures this
    /// host holds, whether it subscribes to them or only signs in them.
    pub fn track(&mut self, subnets: impl IntoIterator<Item = u32>) {
        for subnet in subnets {
            let topic = self.topic(subnet);
            self.subnets.insert(topic, subnet);
            self.peers.entry(subnet).or_default();
        }
    }

    /// Subscribes to `subnet`: every connected peer that tracks it sends this
    /// host its signatures.
    pub fn subscribe(&mut self, subnet: u32) {
        let topic = self.topic(subnet);
        if let Some(receiver) = self.waggle.subscribe(topic) {
            self.inbox
                .push(receiver.map(move |event| (subnet, event)).boxed());
        }
    }

    /// The subscribers of `subnet` this host pushes to; with hashed selection,
    /// the ones it may push to, all of them.
    pub fn push_targets(&mut self, subnet: u32) -> Vec<PeerId> {
        match self.peers.get_mut(&subnet) {
            Some(peers) => peers.push_targets(self.push_peers, &mut self.rng),
            None => Vec::new(),
        }
    }

    /// This round's gossip peers of `subnet`: subscribers this host does not
    /// push to, or any subscribers with hashed selection.
    pub fn gossip_peers(&mut self, subnet: u32) -> Vec<PeerId> {
        match self.peers.get_mut(&subnet) {
            Some(peers) if self.hashed => peers.sample(self.gossip_peers, &mut self.rng),
            Some(peers) => peers.gossip_peers(self.push_peers, self.gossip_peers, &mut self.rng),
            None => Vec::new(),
        }
    }

    pub fn subscriber_count(&self, subnet: u32) -> usize {
        self.peers.get(&subnet).map_or(0, PeerSet::len)
    }

    pub fn is_subscribed(&self, peer: &PeerId, subnet: u32) -> bool {
        self.peers
            .get(&subnet)
            .is_some_and(|peers| peers.contains(peer))
    }

    /// Whether a message for `peer` on `subnet` would be queued now: the peer
    /// subscribes and its send queue has room.
    pub fn can_send(&self, peer: &PeerId, subnet: u32) -> bool {
        self.subscriptions
            .get(&(subnet, *peer))
            .is_some_and(|subscription| !subscription.sender.is_full())
    }

    /// Queues `pieces` for `peer` on `subnet`'s stream. Returns the bytes of the
    /// frame that carries it, or 0 if it was not queued: the peer does not
    /// subscribe, or its send queue is full.
    pub fn send(&mut self, peer: &PeerId, subnet: u32, pieces: ObjectPieces) -> usize {
        let Some(subscription) = self.subscriptions.get(&(subnet, *peer)) else {
            return 0;
        };
        let bytes = frame_len(&pieces);
        match subscription.sender.try_send(pieces) {
            Ok(()) => bytes,
            Err(_) => 0,
        }
    }

    fn topic(&self, subnet: u32) -> Vec<u8> {
        topics::subnet_topic(&self.run_id, subnet).into_bytes()
    }

    fn on_waggle_event(&mut self, event: Event) {
        match event {
            Event::Subscribed {
                peer_id,
                connection_id,
                topic_id,
                sender,
            } => {
                // Dropping the sender refuses a subscription to an untracked topic.
                let Some(&subnet) = self.subnets.get(&topic_id) else {
                    return;
                };
                // A subscription on a newer connection replaces the peer's previous one.
                self.subscriptions.insert(
                    (subnet, peer_id),
                    Subscription {
                        connection_id,
                        sender,
                    },
                );
                self.peers.entry(subnet).or_default().insert(peer_id);
            }
            Event::Unsubscribed {
                peer_id,
                connection_id,
                topic_id,
            } => {
                let Some(&subnet) = self.subnets.get(&topic_id) else {
                    return;
                };
                let current = self
                    .subscriptions
                    .get(&(subnet, peer_id))
                    .is_some_and(|subscription| subscription.connection_id == connection_id);
                if current {
                    self.subscriptions.remove(&(subnet, peer_id));
                    if let Some(peers) = self.peers.get_mut(&subnet) {
                        peers.remove(&peer_id);
                    }
                }
            }
        }
    }
}

/// Bytes of the frame that carries `pieces`: the protobuf message and the
/// varint length before it.
pub fn frame_len(pieces: &ObjectPieces) -> usize {
    let field = |len: usize| 1 + varint_len(len) + len;
    let message = field(pieces.object_id.len())
        + pieces.metadata.as_ref().map_or(0, |m| field(m.len()))
        + pieces.pieces.as_ref().map_or(0, |p| field(p.len()));
    varint_len(message) + message
}

fn varint_len(value: usize) -> usize {
    let bits = (usize::BITS - value.leading_zeros()).max(1) as usize;
    bits.div_ceil(7)
}

impl NetworkBehaviour for SigWaggle {
    type ConnectionHandler = Handler;
    type ToSwarm = SigWaggleEvent;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.waggle.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.waggle.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.waggle.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.waggle
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<SigWaggleEvent, THandlerInEvent<Self>>> {
        // Subscriptions first, so a peer can be answered as soon as it sends.
        while let Poll::Ready(event) = self.waggle.poll(cx) {
            match event {
                ToSwarm::GenerateEvent(event) => self.on_waggle_event(event),
                other => {
                    return Poll::Ready(other.map_out(|_| unreachable!("matched above")));
                }
            }
        }
        while let Poll::Ready(Some((subnet, event))) = self.inbox.poll_next_unpin(cx) {
            // Streams opening and closing need nothing: subscriptions do.
            if let TopicEvent::Pieces {
                peer_id, pieces, ..
            } = event
            {
                return Poll::Ready(ToSwarm::GenerateEvent(SigWaggleEvent::Pieces {
                    peer: peer_id,
                    subnet,
                    pieces,
                }));
            }
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(peers: impl IntoIterator<Item = u8>) -> PeerSet<u8> {
        let mut set = PeerSet::default();
        for peer in peers {
            set.insert(peer);
        }
        set
    }

    #[test]
    fn push_targets_are_capped_and_kept() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut peers = set(0..20);
        let targets = peers.push_targets(8, &mut rng);
        assert_eq!(targets.len(), 8);
        for _ in 0..10 {
            assert_eq!(peers.push_targets(8, &mut rng), targets, "kept once picked");
        }
        // Later subscribers do not displace them.
        peers.insert(99);
        assert_eq!(peers.push_targets(8, &mut rng), targets);
    }

    #[test]
    fn a_target_that_leaves_is_replaced() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut peers = set(0..20);
        let targets = peers.push_targets(8, &mut rng);
        let gone = targets[3];
        peers.remove(&gone);
        let after = peers.push_targets(8, &mut rng);
        assert_eq!(after.len(), 8);
        assert!(!after.contains(&gone));
        assert_eq!(
            after.iter().filter(|peer| targets.contains(peer)).count(),
            7,
            "the others stay"
        );
    }

    #[test]
    fn fewer_subscribers_than_the_cap_are_all_targets() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut peers = set(0..3);
        assert_eq!(peers.push_targets(8, &mut rng), vec![0, 1, 2]);
        assert!(peers.gossip_peers(8, 6, &mut rng).is_empty());
        // New subscribers fill the free places.
        peers.insert(3);
        assert_eq!(peers.push_targets(8, &mut rng), vec![0, 1, 2, 3]);
    }

    #[test]
    fn a_cap_of_zero_pushes_to_every_subscriber() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut peers = set(0..20);
        assert_eq!(peers.push_targets(0, &mut rng).len(), 20);
        assert!(peers.gossip_peers(0, 6, &mut rng).is_empty());
        peers.insert(20);
        assert_eq!(peers.push_targets(0, &mut rng).len(), 21);
    }

    #[test]
    fn gossip_peers_are_other_subscribers() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut peers = set(0..20);
        let targets = peers.push_targets(8, &mut rng);
        let mut seen = BTreeSet::new();
        for _ in 0..50 {
            let gossip = peers.gossip_peers(8, 6, &mut rng);
            assert_eq!(gossip.len(), 6);
            assert!(gossip.iter().all(|peer| !targets.contains(peer)));
            seen.extend(gossip);
        }
        assert_eq!(seen.len(), 12, "picked anew each round");
        assert!(peers.gossip_peers(8, 0, &mut rng).is_empty());
    }

    #[test]
    fn a_sample_takes_any_subscribers() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut peers = set(0..20);
        peers.push_targets(0, &mut rng);
        let mut seen = BTreeSet::new();
        for _ in 0..50 {
            let sample = peers.sample(6, &mut rng);
            assert_eq!(sample.len(), 6);
            seen.extend(sample);
        }
        assert_eq!(seen.len(), 20, "push targets included");
        assert_eq!(set(0..3).sample(6, &mut rng), vec![0, 1, 2]);
    }

    #[test]
    fn frames_count_their_fields_and_length_prefix() {
        let pieces = ObjectPieces {
            object_id: vec![0; 8],
            metadata: None,
            pieces: Some(vec![0; 300]),
        };
        // Object id: tag, length, 8 bytes. Pieces: tag, two-byte length, 300
        // bytes. Then the two-byte length of the 313-byte message.
        assert_eq!(frame_len(&pieces), 2 + (1 + 1 + 8) + (1 + 2 + 300));
        let metadata = ObjectPieces {
            object_id: vec![0; 8],
            metadata: Some(vec![0; 20]),
            pieces: None,
        };
        assert_eq!(frame_len(&metadata), 1 + (1 + 1 + 8) + (1 + 1 + 20));
        assert_eq!(
            [0, 1, 127, 128, 16383, 16384].map(varint_len),
            [1, 1, 1, 2, 2, 3]
        );
    }
}
