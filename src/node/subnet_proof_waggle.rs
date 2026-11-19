//! Proof-specific policy on top of Waggle's per-topic subscription streams.
//!
//! Like ec-sim's Lighthouse payload port, mutually subscribed peers exchange
//! inventories, eagerly push to a small set of peers, and pull missing chunks.
//! The proof runner supplies the producer's signed commitment instead of a block.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use bincode::Options;
use libp2p::{swarm::ConnectionId, PeerId};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use tokio::time::Instant;
use waggle::{
    behaviour::Event,
    handler::{ObjectPieces, PieceSender, TopicEvent},
};

use super::subnet_proof_run::codec;
use super::subnet_proofs::{Piece, ProofKey, Root};

const FANOUT: u8 = 2;
const PUSH_WINDOW: Duration = Duration::from_millis(250);
const REQUEST_DELAY: Duration = Duration::from_millis(100);
const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(50);
const QUEUE_RETRY: Duration = Duration::from_millis(100);
pub(super) const DRIVE_INTERVAL: Duration = Duration::from_millis(25);

/// The wire uses only ceil(chunk_count / 8) bytes of each bitmap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Bitmap([u8; 32]);

impl Bitmap {
    fn get(self, index: usize) -> bool {
        self.0[index / 8] & (1 << (index % 8)) != 0
    }

    fn set(&mut self, index: usize) {
        self.0[index / 8] |= 1 << (index % 8);
    }

    fn includes(self, other: Self) -> bool {
        self.0.iter().zip(other.0).all(|(a, b)| a & b == b)
    }

    fn decode(bytes: &[u8], count: usize) -> Option<Self> {
        if bytes.len() != count.div_ceil(8) {
            return None;
        }
        let mut bits = Self::default();
        bits.0[..bytes.len()].copy_from_slice(bytes);
        if count % 8 != 0 && bits.0[bytes.len() - 1] >> (count % 8) != 0 {
            return None;
        }
        Some(bits)
    }
}

#[derive(Clone, Copy)]
struct Request {
    peer: PeerId,
    until: Instant,
}

#[derive(Default)]
struct PeerProof {
    has: Option<Bitmap>,
    announced: Option<Bitmap>,
    sent: Bitmap,
    pushes: usize,
}

struct Slot {
    /// Encoded authenticated chunk, reused for pushes and request replies.
    piece: Option<Vec<u8>>,
    requested: Option<Request>,
    pushes: u8,
}

struct Proof {
    key: ProofKey,
    object_id: Vec<u8>,
    root: Root,
    registered: Instant,
    first_chunk: Option<Instant>,
    producer: bool,
    have: Bitmap,
    received: usize,
    slots: Vec<Slot>,
    peers: BTreeMap<PeerId, PeerProof>,
    announce_at: Option<Instant>,
    pull_at: Option<Instant>,
}

type Senders = BTreeMap<PeerId, PieceSender>;

impl Proof {
    fn new(key: ProofKey, root: Root, count: usize, now: Instant, producer: bool) -> Self {
        Self {
            key,
            object_id: codec().serialize(&key).expect("proof key encodes"),
            root,
            registered: now,
            first_chunk: None,
            producer,
            have: Bitmap::default(),
            received: 0,
            slots: (0..count)
                .map(|_| Slot {
                    piece: None,
                    requested: None,
                    pushes: 0,
                })
                .collect(),
            peers: BTreeMap::new(),
            announce_at: Some(now),
            pull_at: None,
        }
    }

    fn insert(&mut self, index: usize, piece: Vec<u8>, now: Instant) -> bool {
        debug_assert!(!self.have.get(index));
        self.slots[index].piece = Some(piece);
        self.slots[index].requested = None;
        self.have.set(index);
        self.received += 1;
        self.first_chunk.get_or_insert(now);
        self.announce_at.get_or_insert(now + ANNOUNCE_INTERVAL);
        self.received == self.slots.len()
    }

    fn send(
        &mut self,
        peer: PeerId,
        sender: &PieceSender,
        chunk: Option<usize>,
        request: Option<usize>,
    ) -> bool {
        let state = self.peers.entry(peer).or_default();
        let announce = state.announced != Some(self.have) || request.is_some();
        if !announce && chunk.is_none() {
            return true;
        }
        let metadata = announce.then(|| {
            let n = self.slots.len().div_ceil(8);
            let mut metadata = Vec::with_capacity(n * 2);
            let mut requests = Bitmap::default();
            if let Some(index) = request {
                requests.set(index);
            }
            metadata.extend_from_slice(&self.have.0[..n]);
            metadata.extend_from_slice(&requests.0[..n]);
            metadata
        });
        let pieces = chunk.map(|i| self.slots[i].piece.as_ref().expect("held piece").clone());
        if sender
            .try_send(ObjectPieces {
                object_id: self.object_id.clone(),
                metadata,
                pieces,
            })
            .is_err()
        {
            return false;
        }
        if let Some(index) = chunk {
            state.sent.set(index);
        }
        if announce {
            state.announced = Some(self.have);
        }
        true
    }

    fn announce(&mut self, senders: &Senders, now: Instant) {
        self.announce_at = None;
        for (&peer, sender) in senders {
            if !self.send(peer, sender, None, None) {
                self.announce_at = Some(now + QUEUE_RETRY);
            }
        }
    }

    fn push(&mut self, senders: &Senders, mut indices: Vec<usize>, now: Instant, rng: &mut StdRng) {
        if self.first_chunk.is_none()
            || (!self.producer && self.first_chunk.is_some_and(|at| now >= at + PUSH_WINDOW))
        {
            return;
        }
        indices.retain(|&i| self.have.get(i) && self.slots[i].pushes < FANOUT);
        if indices.is_empty() {
            return;
        }
        let per_peer = (self.slots.len() * usize::from(FANOUT) * 2).div_ceil(senders.len().max(1));
        let mut candidates = senders
            .iter()
            .filter(|(peer, sender)| {
                !sender.is_full()
                    && self
                        .peers
                        .get(peer)
                        .is_some_and(|p| p.has.is_some() && p.pushes < per_peer)
            })
            .map(|(&peer, sender)| (peer, sender, sender.len()))
            .collect::<Vec<_>>();
        candidates.shuffle(rng);
        for _ in 0..FANOUT {
            indices.shuffle(rng);
            indices.sort_by_key(|&i| self.slots[i].pushes);
            for &i in &indices {
                if self.slots[i].pushes >= FANOUT {
                    continue;
                }
                if let Some((peer, sender, queued)) = candidates
                    .iter_mut()
                    .filter(|(p, s, _)| {
                        let state = &self.peers[p];
                        state.pushes < per_peer
                            && !state.sent.get(i)
                            && !state.has.expect("tracking").get(i)
                            && !s.is_full()
                            && !s.is_closed()
                    })
                    .min_by_key(|(_, _, queued)| *queued)
                {
                    if self.send(*peer, sender, Some(i), None) {
                        *queued += 1;
                        self.peers.get_mut(peer).expect("candidate").pushes += 1;
                        self.slots[i].pushes += 1;
                    }
                }
            }
        }
    }

    fn nudge_pull(&mut self, now: Instant) {
        if self.received < self.slots.len() {
            let earliest = now.max(self.registered + REQUEST_DELAY);
            self.pull_at = Some(self.pull_at.map_or(earliest, |at| at.min(earliest)));
        }
    }

    fn pull(&mut self, senders: &Senders, now: Instant, timeout: Duration, rng: &mut StdRng) {
        self.pull_at = None;
        if self.received == self.slots.len() {
            return;
        }
        let mut busy = BTreeSet::new();
        for req in self.slots.iter().filter_map(|slot| slot.requested) {
            if req.until > now && senders.contains_key(&req.peer) {
                busy.insert(req.peer);
                self.pull_at = Some(self.pull_at.map_or(req.until, |at| at.min(req.until)));
            }
        }
        let mut providers = senders
            .iter()
            .filter_map(|(&peer, sender)| Some((peer, sender, self.peers.get(&peer)?.has?)))
            .collect::<Vec<_>>();
        providers.shuffle(rng);
        let mut missing = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| {
                if slot.piece.is_some()
                    || slot
                        .requested
                        .is_some_and(|req| req.until > now && senders.contains_key(&req.peer))
                {
                    return None;
                }
                let count = providers
                    .iter()
                    .filter(|(p, _, have)| !busy.contains(p) && have.get(i))
                    .count();
                (count != 0).then_some((i, count))
            })
            .collect::<Vec<_>>();
        missing.shuffle(rng);
        missing.sort_by_key(|&(_, count)| count);
        for (i, _) in missing {
            let failed = self.slots[i].requested.map(|req| req.peer);
            if let Some(&(peer, sender, _)) = providers
                .iter()
                .filter(|(p, _, has)| !busy.contains(p) && has.get(i))
                .min_by_key(|(p, _, _)| Some(*p) == failed)
            {
                let at = if self.send(peer, sender, None, Some(i)) {
                    busy.insert(peer);
                    let until = now + timeout;
                    self.slots[i].requested = Some(Request { peer, until });
                    until
                } else {
                    now + QUEUE_RETRY
                };
                self.pull_at = Some(self.pull_at.map_or(at, |due| due.min(at)));
            }
        }
    }

    fn receive(
        &mut self,
        peer: PeerId,
        msg: ObjectPieces,
        senders: &Senders,
        bytes: usize,
        now: Instant,
        rng: &mut StdRng,
    ) -> bool {
        let count = self.slots.len();
        let mut complete = false;
        let mut added = None;
        if let Some(encoded) = msg.pieces {
            let Ok(piece) = codec().deserialize::<Piece>(&encoded) else {
                return false;
            };
            if piece.key != self.key || piece.index >= count {
                return false;
            }
            let index = piece.index;
            if let Some(held) = &self.slots[index].piece {
                if held != &encoded {
                    return false;
                }
            } else {
                if !piece.verify(self.root, count, bytes) {
                    return false;
                }
                complete = self.insert(index, encoded, now);
                added = Some(index);
                self.nudge_pull(now);
            }
        }
        let mut first_inventory = false;
        if let Some(metadata) = msg.metadata {
            let n = count.div_ceil(8);
            if metadata.len() == 2 * n {
                if let (Some(has), Some(requests)) = (
                    Bitmap::decode(&metadata[..n], count),
                    Bitmap::decode(&metadata[n..], count),
                ) {
                    let state = self.peers.entry(peer).or_default();
                    if state.has.is_none_or(|old| has.includes(old)) {
                        first_inventory = state.has.is_none();
                        if first_inventory {
                            // The remote may not have known the commitment when
                            // we sent our initial inventory.
                            state.announced = None;
                            self.announce_at = Some(now);
                        }
                        if state.has != Some(has) {
                            state.has = Some(has);
                            self.nudge_pull(now);
                        }
                        if let Some(sender) = senders.get(&peer) {
                            for i in 0..count {
                                if requests.get(i)
                                    && !has.get(i)
                                    && self.have.get(i)
                                    && !self.peers[&peer].sent.get(i)
                                {
                                    if !self.send(peer, sender, Some(i), None) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if first_inventory {
            // Reconsider chunks not previously pushed to enough tracking peers.
            self.push(senders, (0..count).collect(), now, rng);
        } else if let Some(i) = added {
            self.push(senders, vec![i], now, rng);
        }
        complete
    }
}

struct Link {
    id: ConnectionId,
    receiving: bool,
    sender: Option<PieceSender>,
}

pub(super) struct ProofWaggle {
    node_id: u32,
    count: usize,
    bytes: usize,
    topic: Vec<u8>,
    rng: StdRng,
    links: BTreeMap<PeerId, Link>,
    /// Only links with both subscription streams open participate.
    senders: Senders,
    proofs: BTreeMap<ProofKey, Proof>,
}

impl ProofWaggle {
    pub(super) fn new(node_id: u32, seed: u64, count: usize, bytes: usize, topic: Vec<u8>) -> Self {
        Self {
            node_id,
            count,
            bytes,
            topic,
            rng: StdRng::seed_from_u64(seed ^ u64::from(node_id)),
            links: BTreeMap::new(),
            senders: BTreeMap::new(),
            proofs: BTreeMap::new(),
        }
    }

    pub(super) fn register(&mut self, key: ProofKey, root: Root) {
        self.proofs.entry(key).or_insert_with(|| {
            Proof::new(
                key,
                root,
                self.count,
                Instant::now(),
                self.node_id == key.producer,
            )
        });
    }

    pub(super) fn release(&mut self, key: ProofKey, chunks: Vec<Piece>) -> anyhow::Result<()> {
        let proof = self
            .proofs
            .get_mut(&key)
            .expect("registered producer commitment");
        let now = Instant::now();
        for chunk in chunks {
            proof.insert(chunk.index, codec().serialize(&chunk)?, now);
        }
        proof.push(&self.senders, (0..self.count).collect(), now, &mut self.rng);
        Ok(())
    }

    fn link(&mut self, peer: PeerId, id: ConnectionId) -> Option<&mut Link> {
        let link = self.links.entry(peer).or_insert(Link {
            id,
            receiving: false,
            sender: None,
        });
        (link.id == id).then_some(link)
    }

    fn ready(&mut self, peer: PeerId) {
        let Some(sender) = self
            .links
            .get(&peer)
            .filter(|l| l.receiving)
            .and_then(|l| l.sender.clone())
        else {
            return;
        };
        if self.senders.insert(peer, sender).is_none() {
            let now = Instant::now();
            for proof in self.proofs.values_mut() {
                proof.announce_at = Some(now);
                proof.nudge_pull(now);
            }
        }
    }

    fn not_ready(&mut self, peer: PeerId) {
        if self.senders.remove(&peer).is_some() {
            let now = Instant::now();
            for proof in self.proofs.values_mut() {
                proof.peers.remove(&peer);
                for slot in &mut proof.slots {
                    if slot.requested.is_some_and(|r| r.peer == peer) {
                        slot.requested = None;
                    }
                }
                proof.nudge_pull(now);
            }
        }
    }

    pub(super) fn disconnected(&mut self, peer: PeerId, id: ConnectionId) {
        if self.links.get(&peer).is_some_and(|l| l.id == id) {
            self.links.remove(&peer);
            self.not_ready(peer);
        }
    }

    pub(super) fn on_behaviour(&mut self, event: Event) {
        match event {
            Event::Subscribed {
                peer_id,
                connection_id,
                topic_id,
                sender,
            } if topic_id == self.topic => {
                if let Some(link) = self.link(peer_id, connection_id) {
                    link.sender = Some(sender);
                    self.ready(peer_id);
                }
            }
            Event::Unsubscribed {
                peer_id,
                connection_id,
                topic_id,
            } if topic_id == self.topic => {
                if let Some(link) = self
                    .links
                    .get_mut(&peer_id)
                    .filter(|l| l.id == connection_id)
                {
                    link.sender = None;
                    self.not_ready(peer_id);
                }
            }
            _ => {}
        }
    }

    pub(super) fn on_topic(&mut self, event: TopicEvent) -> Option<ProofKey> {
        match event {
            TopicEvent::Opened {
                peer_id,
                connection_id,
            } => {
                if let Some(link) = self.link(peer_id, connection_id) {
                    link.receiving = true;
                    self.ready(peer_id);
                }
            }
            TopicEvent::Closed {
                peer_id,
                connection_id,
            } => {
                if let Some(link) = self
                    .links
                    .get_mut(&peer_id)
                    .filter(|l| l.id == connection_id)
                {
                    link.receiving = false;
                    self.not_ready(peer_id);
                }
            }
            TopicEvent::Pieces {
                peer_id,
                connection_id,
                pieces,
            } => {
                // An inventory can arrive while the reverse subscription is still opening.
                if !self
                    .links
                    .get(&peer_id)
                    .is_some_and(|l| l.id == connection_id && l.receiving)
                {
                    return None;
                }
                let key = codec().deserialize::<ProofKey>(&pieces.object_id).ok()?;
                let proof = self.proofs.get_mut(&key)?;
                if proof.receive(
                    peer_id,
                    pieces,
                    &self.senders,
                    self.bytes,
                    Instant::now(),
                    &mut self.rng,
                ) {
                    return Some(key);
                }
            }
        }
        None
    }

    pub(super) fn drive(&mut self) {
        let now = Instant::now();
        let timeout = Duration::from_millis(500)
            + Duration::from_micros(16 * self.bytes.div_ceil(self.count) as u64);
        for proof in self.proofs.values_mut() {
            if proof.announce_at.is_some_and(|at| now >= at) {
                proof.announce(&self.senders, now);
            }
            if proof.pull_at.is_some_and(|at| now >= at) {
                proof.pull(&self.senders, now, timeout, &mut self.rng);
            }
        }
    }

    pub(super) fn pending(&self) -> usize {
        self.proofs
            .values()
            .flat_map(|proof| &proof.slots)
            .filter(|slot| slot.requested.is_some())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::subnet_proofs::pieces;

    #[test]
    fn only_distinct_authenticated_pieces_complete_a_proof() {
        let key = ProofKey {
            subnet: 1,
            producer: 2,
        };
        let (root, chunks) = pieces(key, b"abcd", 2);
        let now = Instant::now();
        let mut proof = Proof::new(key, root, 2, now, false);
        let peer = PeerId::random();
        let mut rng = StdRng::seed_from_u64(9);
        let senders = BTreeMap::new();
        let mut receive = |piece: &Piece| {
            let msg = ObjectPieces {
                object_id: proof.object_id.clone(),
                metadata: None,
                pieces: Some(codec().serialize(piece).unwrap()),
            };
            proof.receive(peer, msg, &senders, 4, now, &mut rng)
        };
        let mut wrong = chunks[0].clone();
        wrong.data[0] ^= 1;
        assert!(!receive(&wrong));
        assert!(!receive(&chunks[1]));
        assert!(!receive(&chunks[1]));
        assert!(receive(&chunks[0]));
        assert!(!receive(&chunks[0]));
    }

    #[test]
    fn inventories_reject_values_outside_the_chunk_roster() {
        assert!(Bitmap::decode(&[4], 2).is_none());
        assert!(Bitmap::decode(&[0, 1], 2).is_none());
        assert!(Bitmap::decode(&[3], 2)
            .unwrap()
            .includes(Bitmap::decode(&[1], 2).unwrap()));
    }
}
