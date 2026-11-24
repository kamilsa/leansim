//! Proof-specific policy on top of Waggle's per-topic subscription streams.
//!
//! Like ec-sim's Lighthouse payload port, mutually subscribed peers exchange
//! inventories, eagerly push to a small set of peers, and pull missing chunks.
//! The producer builds a Merkle tree over the chunks and signs only its root. Every
//! chunk message carries the chunk's Merkle path, which leads to that root. The root
//! signature goes along only while the peer may lack it: once a peer has received or
//! advertised a chunk, or we have queued it a signed one, the path alone is enough.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::Context;
use bincode::Options;
use libp2p::{
    identity::{Keypair, PublicKey},
    swarm::ConnectionId,
    PeerId,
};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use tokio::time::Instant;
use waggle::{
    behaviour::Event,
    handler::{ObjectPieces, PieceSender, TopicEvent},
};

use super::subnet_proof_run::codec;
use super::subnet_proofs::{
    sign_commitment, Commitment, Piece, ProofKey, Root, COMMITMENT_SIGNATURE_BYTES,
};
use crate::network::swarm::node_keypair;

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
    /// The peer sent us a valid chunk, so it holds the signed root.
    received_from: bool,
    /// A chunk with the signature is queued to the peer on its current stream.
    signature_sent: bool,
}

impl PeerProof {
    /// A peer that holds, sent or was sent a valid chunk has verified the root signature
    /// and keeps it for the life of the proof.
    fn needs_signature(&self) -> bool {
        !self.signature_sent
            && !self.received_from
            && self.has.unwrap_or_default() == Bitmap::default()
    }
}

/// The chunk with its Merkle path, followed by the root signature if the peer needs it.
fn encode_chunk(piece: &[u8], signature: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(piece.len() + signature.map_or(0, <[u8]>::len));
    bytes.extend_from_slice(piece);
    bytes.extend_from_slice(signature.unwrap_or_default());
    bytes
}

/// Splits a chunk message into the piece, its encoding and the signature, which is
/// either absent or of the full size.
fn decode_chunk(encoded: &[u8]) -> Option<(Piece, &[u8], &[u8])> {
    let mut signature = encoded;
    let piece = codec()
        .allow_trailing_bytes()
        .deserialize_from(&mut signature)
        .ok()?;
    (signature.is_empty() || signature.len() == COMMITMENT_SIGNATURE_BYTES).then(|| {
        (
            piece,
            &encoded[..encoded.len() - signature.len()],
            signature,
        )
    })
}

struct Slot {
    /// Encoded chunk with its Merkle path, reused for pushes and request replies.
    piece: Option<Vec<u8>>,
    requested: Option<Request>,
    pushes: u8,
}

struct Proof {
    key: ProofKey,
    object_id: Vec<u8>,
    producer_key: PublicKey,
    /// The signed root of the first valid chunk; later chunks must lead to it.
    commitment: Commitment,
    /// Chunks sent without and with the signature.
    signatures: [u64; 2],
    /// When this host first heard of the proof.
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
    fn new(
        key: ProofKey,
        producer_key: PublicKey,
        count: usize,
        now: Instant,
        producer: bool,
    ) -> Self {
        Self {
            key,
            object_id: codec().serialize(&key).expect("proof key encodes"),
            producer_key,
            commitment: Commitment::default(),
            signatures: [0; 2],
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
        // An empty inventory says nothing: every peer on the topic is assumed to want the proof.
        let announce = state.announced.unwrap_or_default() != self.have || request.is_some();
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
        let sign = chunk.is_some() && state.needs_signature();
        let pieces = chunk.map(|i| {
            encode_chunk(
                self.slots[i].piece.as_ref().expect("held piece"),
                sign.then(|| self.commitment.signature().expect("held chunks are signed")),
            )
        });
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
            state.signature_sent |= sign;
            self.signatures[usize::from(sign)] += 1;
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
        // A peer need not have advertised anything to be pushed to.
        for &peer in senders.keys() {
            self.peers.entry(peer).or_default();
        }
        let mut candidates = senders
            .iter()
            .filter(|(peer, sender)| !sender.is_full() && self.peers[peer].pushes < per_peer)
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
                            && !state.has.unwrap_or_default().get(i)
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
            let Some((piece, body, signature)) = decode_chunk(&encoded) else {
                return false;
            };
            if piece.key != self.key || piece.index >= count {
                return false;
            }
            let index = piece.index;
            if let Some(held) = &self.slots[index].piece {
                if held != body {
                    return false;
                }
            } else {
                // The Merkle path leads to a root. The first chunk must bring the producer's
                // signature over it; once that root is held the path alone is enough.
                let Some(root) = piece.root(count, bytes) else {
                    return false;
                };
                if self
                    .commitment
                    .admit(&self.producer_key, self.key, root, signature, true)
                    .is_err()
                {
                    return false;
                }
                let body = body.to_vec();
                complete = self.insert(index, body, now);
                added = Some(index);
                self.nudge_pull(now);
            }
            // A peer that sends a valid chunk holds the signed root.
            self.peers.entry(peer).or_default().received_from = true;
        }
        if let Some(metadata) = msg.metadata {
            let n = count.div_ceil(8);
            if metadata.len() == 2 * n {
                if let (Some(has), Some(requests)) = (
                    Bitmap::decode(&metadata[..n], count),
                    Bitmap::decode(&metadata[n..], count),
                ) {
                    let state = self.peers.entry(peer).or_default();
                    if state.has.is_none_or(|old| has.includes(old)) {
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
        if let Some(i) = added {
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

pub(crate) struct ProofWaggle {
    node_id: u32,
    count: usize,
    bytes: usize,
    topic: Vec<u8>,
    rng: StdRng,
    keypair: Keypair,
    /// Proofs this host accepts, with the key that must sign each commitment.
    roster: BTreeMap<ProofKey, PublicKey>,
    links: BTreeMap<PeerId, Link>,
    /// Only links with both subscription streams open participate.
    senders: Senders,
    proofs: BTreeMap<ProofKey, Proof>,
}

impl ProofWaggle {
    pub(crate) fn new(
        node_id: u32,
        seed: u64,
        count: usize,
        bytes: usize,
        topic: Vec<u8>,
        roster: impl IntoIterator<Item = ProofKey>,
    ) -> Self {
        Self {
            node_id,
            count,
            bytes,
            topic,
            rng: StdRng::seed_from_u64(seed ^ u64::from(node_id)),
            keypair: node_keypair(node_id),
            roster: roster
                .into_iter()
                .map(|key| (key, node_keypair(key.producer).public()))
                .collect(),
            links: BTreeMap::new(),
            senders: BTreeMap::new(),
            proofs: BTreeMap::new(),
        }
    }

    /// The proof for `key`, created when this host first hears of it.
    fn proof(&mut self, key: ProofKey) -> Option<&mut Proof> {
        let producer_key = self.roster.get(&key)?;
        let (count, producer) = (self.count, self.node_id == key.producer);
        Some(self.proofs.entry(key).or_insert_with(|| {
            Proof::new(key, producer_key.clone(), count, Instant::now(), producer)
        }))
    }

    /// Signs the Merkle root and starts pushing the chunks.
    pub(crate) fn release(
        &mut self,
        key: ProofKey,
        root: Root,
        chunks: Vec<Piece>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            key.producer == self.node_id,
            "only its producer releases a proof"
        );
        let signature = sign_commitment(&self.keypair, key, root)?;
        let proof = self.proof(key).context("proof is not on the roster")?;
        proof.commitment = Commitment::signed(root, signature);
        let now = Instant::now();
        for piece in chunks {
            proof.insert(piece.index, codec().serialize(&piece)?, now);
        }
        let proof = self.proofs.get_mut(&key).expect("just created");
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
        } else {
            // A signature queued on the replaced stream may never have arrived.
            for proof in self.proofs.values_mut() {
                if let Some(state) = proof.peers.get_mut(&peer) {
                    state.signature_sent = false;
                }
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

    pub(crate) fn disconnected(&mut self, peer: PeerId, id: ConnectionId) {
        if self.links.get(&peer).is_some_and(|l| l.id == id) {
            self.links.remove(&peer);
            self.not_ready(peer);
        }
    }

    pub(crate) fn on_behaviour(&mut self, event: Event) {
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

    pub(crate) fn on_topic(&mut self, event: TopicEvent) -> Option<ProofKey> {
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
                self.proof(key)?;
                let proof = self.proofs.get_mut(&key).expect("just created");
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

    pub(crate) fn drive(&mut self) {
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

    /// Chunk messages sent without and with the root signature.
    pub(super) fn signatures(&self) -> [u64; 2] {
        self.proofs.values().fold([0; 2], |sum, proof| {
            [sum[0] + proof.signatures[0], sum[1] + proof.signatures[1]]
        })
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
    use crate::network::swarm::node_keypair;
    use crate::node::subnet_proofs::{pieces, sign_commitment};

    /// A chunk message as a relay would send it: the chunk with its Merkle path, and
    /// the producer's root signature only if `signer` is given.
    fn chunk(signer: Option<u32>, root: Root, piece: &Piece) -> ObjectPieces {
        let signature =
            signer.map(|id| sign_commitment(&node_keypair(id), piece.key, root).unwrap());
        ObjectPieces {
            object_id: codec().serialize(&piece.key).unwrap(),
            metadata: None,
            pieces: Some(encode_chunk(
                &codec().serialize(piece).unwrap(),
                signature.as_deref(),
            )),
        }
    }

    #[test]
    fn only_distinct_authenticated_pieces_complete_a_proof() {
        let key = ProofKey {
            subnet: 1,
            producer: 2,
        };
        let (root, chunks) = pieces(key, b"abcd", 2);
        let now = Instant::now();
        let mut proof = Proof::new(key, node_keypair(2).public(), 2, now, false);
        let peer = PeerId::random();
        let mut rng = StdRng::seed_from_u64(9);
        let senders = BTreeMap::new();
        let mut receive = |piece: &Piece| {
            proof.receive(
                peer,
                chunk(Some(2), root, piece),
                &senders,
                4,
                now,
                &mut rng,
            )
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
    fn a_chunk_without_the_signature_is_accepted_only_after_a_signed_one() {
        let key = ProofKey {
            subnet: 1,
            producer: 2,
        };
        let (root, chunks) = pieces(key, b"abcd", 2);
        let (other_root, other) = pieces(key, b"wxyz", 2);
        let now = Instant::now();
        let mut proof = Proof::new(key, node_keypair(2).public(), 2, now, false);
        let peer = PeerId::random();
        let mut rng = StdRng::seed_from_u64(9);
        let senders = BTreeMap::new();
        let mut receive = |msg: ObjectPieces| proof.receive(peer, msg, &senders, 4, now, &mut rng);
        // Nothing holds this proof to a root yet, so a bare Merkle path proves nothing.
        assert!(!receive(chunk(None, root, &chunks[1])));
        // Signed by a host that is not the producer, or over another root.
        assert!(!receive(chunk(Some(3), root, &chunks[0])));
        assert!(!receive(chunk(Some(2), other_root, &chunks[0])));
        assert!(!receive(chunk(Some(2), root, &chunks[0])));
        // The signed root is known now: the Merkle path alone authenticates the next chunk,
        // and a chunk of another tree fails with or without a signature.
        assert!(!receive(chunk(None, other_root, &other[1])));
        assert!(!receive(chunk(Some(2), other_root, &other[1])));
        let unsigned = chunk(None, root, &chunks[1]);
        let signed = chunk(Some(2), root, &chunks[1]);
        assert_eq!(
            signed.pieces.as_ref().unwrap().len(),
            unsigned.pieces.as_ref().unwrap().len() + 2400
        );
        assert!(receive(unsigned));
        assert!(proof.peers[&peer].received_from);
    }

    #[test]
    fn the_signature_goes_only_to_a_peer_that_may_lack_it() {
        let mut peer = PeerProof::default();
        assert!(peer.needs_signature());
        // An empty inventory does not show that the peer has verified anything.
        peer.has = Some(Bitmap::default());
        assert!(peer.needs_signature());
        let mut holding = Bitmap::default();
        holding.set(3);
        peer.has = Some(holding);
        assert!(!peer.needs_signature());
        let sent = PeerProof {
            signature_sent: true,
            ..PeerProof::default()
        };
        assert!(!sent.needs_signature());
        let received = PeerProof {
            received_from: true,
            ..PeerProof::default()
        };
        assert!(!received.needs_signature());
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
