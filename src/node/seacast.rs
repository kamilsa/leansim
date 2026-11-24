//! SEACAST for committee proofs, on SEACAST's Waggle binding.
//!
//! Follows cskiraly/seacast-spec v0.12.0 (2026-11-22) in its tier 4 setting
//! (`seacast.md` §6.1, §6.2): one object type, interest `ALL`, duty `FORWARD`, one
//! colour (`M = 1`) and a symmetric push relation kept like a gossipsub mesh
//! (`F_LO` 6, `D_OUT` 8, `F_HI` 12), heartbeat gossip to a sample of the other
//! links. A proof is a group: the producer cuts it into `k` data chunks, adds `k`
//! Reed–Solomon parity chunks, builds a Merkle tree over the `n = 2k` chunks and
//! signs the root (the "header"; there is no block here to commit it).
//!
//! Mechanisms (the spec's cards): HAVE bitmaps as holdings and offers [c7], announce
//! instead of push with a budget of `R_NODE` less the known holders [c3, c4, c11,
//! c17], furthest-behind-first push targets [c16], one ask per chunk at a time with a
//! promise and a park [c5], the decode claim at `K` with stop-pull and repair [c6,
//! c10], cancel [c8], rarest at pop [c9], projection [c12], striped publishing above
//! 1 Gbit/s [c13], the byte window [c14], paced heartbeat gossip [c15], the source's
//! acknowledged offers and paced HAVE [c3, P4].
//!
//! Simplifications, each stated where it bites: the per-peer queue is unbounded (no
//! refusal, so nothing is owed); the signed root rides with a chunk while the peer
//! may lack it (as leanSim's Waggle proof arm), since there is no block to carry the
//! header; chunks are not snappy-compressed (the proof bytes are random); the guard of
//! card 16, peer scoring, group expiry and deferral are left out.
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::Duration;

use libp2p::identity::{Keypair, PublicKey};
use libp2p::PeerId;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use waggle::handler::ObjectPieces;

use super::rs_code::Code;
use super::subnet_proofs::{
    sign_commitment, verify_commitment, ProofKey, Root, COMMITMENT_SIGNATURE_BYTES,
};
use crate::network::swarm::node_keypair;

// seacast-lite.md §8.3 and seacast.md §6.3, reference values.
const R: usize = 2;
const R_FAST: usize = 6;
const FAST_UPLINK_MBPS: u64 = 500;
const STRIPE_UPLINK_MBPS: u64 = 1000;
const D_OUT: usize = 8;
const F_LO: usize = 6;
const F_HI: usize = 12;
const HEARTBEAT: Duration = Duration::from_millis(700);
const PACE_TICK: Duration = Duration::from_micros(43_750);
const D_LAZY: usize = 6;
const GOSSIP_FACTOR: f64 = 0.25;
const GOSSIP_HISTORY: usize = 3;
const IWANT_WINDOW: Duration = Duration::from_millis(200);
const RETRY_SLACK: Duration = Duration::from_millis(5);
const PROMISE: Duration = Duration::from_millis(400);
const PARK_TTL: Duration = Duration::from_secs(30);
const WINDOW_TIMEOUT: Duration = Duration::from_millis(500);
const RTT_REF_TARGET: Duration = Duration::from_millis(112 + 20);
const ASK_UPLINK_MBPS: u64 = 50;
const FAN_IN: u32 = 2;
const PRUNE_BACKOFF: Duration = Duration::from_secs(60);
const GOSSIP_RETRANSMISSION: u8 = 3;
const OFFER_LIST: usize = 16;

// seacast-bindings.md §1.1: an encoded message's kind byte.
const JOIN: u8 = 0x01;
const GRAFT: u8 = 0x02;
const PRUNE: u8 = 0x03;
const HAVE: u8 = 0x04;
const WANT: u8 = 0x05;
const CHUNK: u8 = 0x06;
const GROUP_ID_BYTES: usize = 35;
const BRANCH: usize = 32;

type Bits = u128;

fn bit(i: usize) -> Bits {
    1u128 << i
}

fn all(n: usize) -> Bits {
    if n == 128 {
        u128::MAX
    } else {
        bit(n) - 1
    }
}

fn indices(bits: Bits) -> impl Iterator<Item = usize> {
    (0..128).filter(move |&i| bits & bit(i) != 0)
}

/// seacast-bindings.md §1.2: least significant bit first, trailing zero bytes dropped.
fn encode_bits(bits: Bits) -> Vec<u8> {
    let bytes = bits.to_le_bytes();
    let len = 16 - (bits.leading_zeros() as usize / 8);
    bytes[..len].to_vec()
}

fn decode_bits(bytes: &[u8], n: usize) -> Option<Bits> {
    if bytes.len() > 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    buf[..bytes.len()].copy_from_slice(bytes);
    let bits = u128::from_le_bytes(buf);
    (bits & !all(n) == 0).then_some(bits)
}

/// The 35-byte `GroupId` of a proof: type 0, a key naming the proof, index 0.
pub fn group_id(key: ProofKey) -> Vec<u8> {
    let mut id = Vec::with_capacity(GROUP_ID_BYTES);
    id.push(0);
    id.extend_from_slice(&key.subnet.to_le_bytes());
    id.extend_from_slice(&key.producer.to_le_bytes());
    let tail = Sha256::new()
        .chain_update(b"leansim-seacast-group")
        .chain_update(key.subnet.to_le_bytes())
        .chain_update(key.producer.to_le_bytes())
        .finalize();
    id.extend_from_slice(&tail[..24]);
    id.extend_from_slice(&0u16.to_le_bytes());
    id
}

fn key_of(id: &[u8]) -> Option<ProofKey> {
    if id.len() != GROUP_ID_BYTES {
        return None;
    }
    let key = ProofKey {
        subnet: u32::from_le_bytes(id[1..5].try_into().ok()?),
        producer: u32::from_le_bytes(id[5..9].try_into().ok()?),
    };
    (group_id(key) == id).then_some(key)
}

/// seacast-lite.md §1: leaves `sha256(0x00 ‖ chunk)`, nodes `sha256(0x01 ‖ l ‖ r)`.
fn leaf(data: &[u8]) -> Root {
    Sha256::new()
        .chain_update([0u8])
        .chain_update(data)
        .finalize()
        .into()
}

fn node(left: &Root, right: &Root) -> Root {
    Sha256::new()
        .chain_update([1u8])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// The root and every leaf's branch, for a power-of-two number of chunks.
pub fn merkle(chunks: &[Vec<u8>]) -> (Root, Vec<Vec<Root>>) {
    assert!(chunks.len().is_power_of_two());
    let mut layer: Vec<Root> = chunks.iter().map(|c| leaf(c)).collect();
    let mut branches = vec![Vec::new(); chunks.len()];
    let mut width = 1;
    while layer.len() > 1 {
        for (i, branch) in branches.iter_mut().enumerate() {
            branch.push(layer[(i / width) ^ 1]);
        }
        layer = layer.chunks(2).map(|p| node(&p[0], &p[1])).collect();
        width *= 2;
    }
    (layer[0], branches)
}

fn root_of(index: usize, data: &[u8], branch: &[Root]) -> Root {
    let mut acc = leaf(data);
    for (level, sibling) in branch.iter().enumerate() {
        acc = if (index >> level) & 1 == 0 {
            node(&acc, sibling)
        } else {
            node(sibling, &acc)
        };
    }
    acc
}

/// A message of seacast.md §2, as this arm uses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Join,
    Graft {
        answer: bool,
    },
    Prune,
    Have {
        key: ProofKey,
        bits: Bits,
        offer: bool,
        claim_all: bool,
    },
    Want {
        key: ProofKey,
        bits: Bits,
    },
    Chunk {
        key: ProofKey,
        index: usize,
        branch: Vec<Root>,
        header: Option<Vec<u8>>,
        data: Vec<u8>,
    },
}

/// seacast-bindings.md §3: one `ObjectPieces` per message. `objectID` is the group id
/// (or `0x00` for JOIN, GRAFT and PRUNE), `piecesMetadata` the encoded message (a
/// chunk's kind byte alone), `pieces` a chunk's body.
pub fn encode(msg: &Msg) -> ObjectPieces {
    let control = |body: Vec<u8>| ObjectPieces {
        object_id: vec![0],
        metadata: Some(body),
        pieces: None,
    };
    match msg {
        // JoinMsg: type, fork digest, interest ALL, custody 0, duty FORWARD, colours 1.
        Msg::Join => {
            let mut b = vec![JOIN, 0, 0, 0, 0, 0, 0];
            b.extend_from_slice(&0u64.to_le_bytes());
            b.extend_from_slice(&[1, 1, 0]);
            control(b)
        }
        // GraftMsg: type, family, colour, direction BOTH, answer.
        Msg::Graft { answer } => control(vec![GRAFT, 0, 0, 0, 0, 0, 2, u8::from(*answer)]),
        Msg::Prune => control(vec![PRUNE, 0, 0, 0, 0, 0, 2]),
        // HaveMsg: group, flags (bit 0 offer, bit 1 claim_all, bit 2 complete), offset, bits.
        Msg::Have {
            key,
            bits,
            offer,
            claim_all,
        } => {
            let id = group_id(*key);
            let mut b = vec![HAVE];
            b.extend_from_slice(&id);
            b.push(u8::from(*offer) | (u8::from(*claim_all) * 0b110));
            b.extend_from_slice(&40u32.to_le_bytes());
            b.extend_from_slice(&encode_bits(*bits));
            ObjectPieces {
                object_id: id,
                metadata: Some(b),
                pieces: None,
            }
        }
        // WantMsg: group, flags, hops 0, offset, bits.
        Msg::Want { key, bits } => {
            let id = group_id(*key);
            let mut b = vec![WANT];
            b.extend_from_slice(&id);
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&41u32.to_le_bytes());
            b.extend_from_slice(&encode_bits(*bits));
            ObjectPieces {
                object_id: id,
                metadata: Some(b),
                pieces: None,
            }
        }
        Msg::Chunk {
            key,
            index,
            branch,
            header,
            data,
        } => {
            let mut b = Vec::with_capacity(
                6 + branch.len() * BRANCH + data.len() + COMMITMENT_SIGNATURE_BYTES,
            );
            b.extend_from_slice(&(*index as u32).to_le_bytes());
            b.push(u8::from(header.is_some()));
            b.push(branch.len() as u8);
            for r in branch {
                b.extend_from_slice(r);
            }
            if let Some(h) = header {
                b.extend_from_slice(h);
            }
            b.extend_from_slice(data);
            ObjectPieces {
                object_id: group_id(*key),
                metadata: Some(vec![CHUNK]),
                pieces: Some(b),
            }
        }
    }
}

pub fn decode(m: &ObjectPieces, n: usize) -> Option<Msg> {
    let meta = m.metadata.as_deref()?;
    match *meta.first()? {
        JOIN => Some(Msg::Join),
        GRAFT if meta.len() == 8 => Some(Msg::Graft {
            answer: meta[7] == 1,
        }),
        PRUNE if meta.len() == 7 => Some(Msg::Prune),
        HAVE if meta.len() >= 41 => {
            let key = key_of(&meta[1..36])?;
            (m.object_id == meta[1..36]).then_some(())?;
            let flags = meta[36];
            Some(Msg::Have {
                key,
                bits: decode_bits(&meta[41..], n)?,
                offer: flags & 1 != 0,
                claim_all: flags & 2 != 0,
            })
        }
        WANT if meta.len() >= 42 => {
            let key = key_of(&meta[1..36])?;
            (m.object_id == meta[1..36]).then_some(())?;
            Some(Msg::Want {
                key,
                bits: decode_bits(&meta[42..], n)?,
            })
        }
        CHUNK => {
            let key = key_of(&m.object_id)?;
            let b = m.pieces.as_deref()?;
            if b.len() < 6 {
                return None;
            }
            let index = u32::from_le_bytes(b[..4].try_into().ok()?) as usize;
            let has_header = b[4] == 1;
            let depth = usize::from(b[5]);
            let mut at = 6;
            let mut branch = Vec::with_capacity(depth);
            for _ in 0..depth {
                branch.push(b.get(at..at + BRANCH)?.try_into().ok()?);
                at += BRANCH;
            }
            let header = if has_header {
                let h = b.get(at..at + COMMITMENT_SIGNATURE_BYTES)?.to_vec();
                at += COMMITMENT_SIGNATURE_BYTES;
                Some(h)
            } else {
                None
            };
            Some(Msg::Chunk {
                key,
                index,
                branch,
                header,
                data: b[at..].to_vec(),
            })
        }
        _ => None,
    }
}

fn wire_len(m: &ObjectPieces) -> usize {
    m.object_id.len()
        + m.metadata.as_ref().map_or(0, Vec::len)
        + m.pieces.as_ref().map_or(0, Vec::len)
        + 8
}

/// What one host knows of one peer for one group.
#[derive(Default)]
struct PeerGroup {
    /// Holdings: what the peer said it holds, verified (§1.5).
    has: Bits,
    claim_all: bool,
    /// Chunks we chose to push it, queued or sent (cards 4, 16).
    pushed: Bits,
    /// Chunks that left for it, for projection (card 12).
    sent_to: Bits,
    served: BTreeMap<usize, u8>,
    /// The peer has verified the signed root: it sent us a chunk, or we queued it one
    /// that carried the root's signature.
    header_sent: bool,
    received_from: bool,
    /// The peer offered us chunks, so it holds some and has verified the root.
    offered: bool,
    parked_until: Option<Instant>,
}

impl PeerGroup {
    fn needs_header(&self) -> bool {
        !self.header_sent
            && !self.received_from
            && !self.offered
            && self.has == 0
            && !self.claim_all
    }
}

struct Group {
    key: ProofKey,
    producer_key: PublicKey,
    root: Option<Root>,
    header: Option<Vec<u8>>,
    chunks: Vec<Option<(Vec<Root>, Vec<u8>)>>,
    received: Bits,
    mine: Bits,
    claimed: bool,
    invalid: bool,
    stop_pull: bool,
    /// For a group we publish: what is acknowledged so far (P4), and each chunk's targets.
    origin: Option<Bits>,
    planned: Vec<Vec<PeerId>>,
    holders: Vec<u16>,
    peers: BTreeMap<PeerId, PeerGroup>,
    offers: Vec<Vec<PeerId>>,
    asked_at: Vec<Option<Instant>>,
    tried: Vec<BTreeMap<PeerId, Instant>>,
    asked_parked: Vec<BTreeSet<PeerId>>,
    last_resort_armed: Vec<bool>,
    promises: BTreeMap<(usize, PeerId), Instant>,
}

impl Group {
    fn new(key: ProofKey, producer_key: PublicKey, n: usize) -> Self {
        Self {
            key,
            producer_key,
            root: None,
            header: None,
            chunks: vec![None; n],
            received: 0,
            mine: 0,
            claimed: false,
            invalid: false,
            stop_pull: false,
            origin: None,
            planned: vec![Vec::new(); n],
            holders: vec![0; n],
            peers: BTreeMap::new(),
            offers: vec![Vec::new(); n],
            asked_at: vec![None; n],
            tried: vec![BTreeMap::new(); n],
            asked_parked: vec![BTreeSet::new(); n],
            last_resort_armed: vec![false; n],
            promises: BTreeMap::new(),
        }
    }

    fn pg(&mut self, p: PeerId) -> &mut PeerGroup {
        self.peers.entry(p).or_default()
    }

    fn has(&self, p: &PeerId) -> Bits {
        self.peers.get(p).map_or(0, |s| s.has)
    }

    fn pushed(&self, p: &PeerId) -> Bits {
        self.peers.get(p).map_or(0, |s| s.pushed)
    }

    fn parked(&self, p: &PeerId, now: Instant) -> bool {
        self.peers
            .get(p)
            .and_then(|s| s.parked_until)
            .is_some_and(|t| now < t)
    }

    fn have_bits(&self) -> Bits {
        self.origin.unwrap_or(self.mine)
    }

    fn close_promises(&mut self, i: usize) {
        self.promises.retain(|(j, _), _| *j != i);
        self.offers[i].clear();
        self.tried[i].clear();
        self.asked_at[i] = None;
        self.asked_parked[i].clear();
    }
}

#[derive(Debug, Clone)]
enum Entry {
    Ctrl(Msg),
    /// A holding: the whole bitmap as it is when written (merged: one per group).
    Holding(ProofKey),
    /// The source's HAVE just ahead of a peer's first chunk (P4).
    SourceHave(ProofKey, Bits),
    Offer(ProofKey, Bits),
    Want(ProofKey, Bits),
    Chunk {
        key: ProofKey,
        index: usize,
        solicited: bool,
        own: bool,
    },
}

#[derive(Default)]
struct Peer {
    in_mesh: bool,
    graft_pending: bool,
    backoff_until: Option<Instant>,
    urgent: VecDeque<Entry>,
    normal: VecDeque<Entry>,
    writing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Timer {
    Heartbeat,
    Pace,
    WindowTimeout(PeerId, ProofKey, usize),
    Retry(ProofKey, usize),
    Promise(ProofKey, usize, PeerId),
    LastResort(ProofKey, usize),
}

/// Counters logged at the end of a run.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Stats {
    pub chunks_received: u64,
    pub chunks_duplicate: u64,
    pub chunks_invalid: u64,
    pub chunks_unverifiable: u64,
    pub pushes: u64,
    pub answers: u64,
    pub repairs: u64,
    pub cancelled: u64,
    pub projected: u64,
    pub headers_sent: u64,
    pub holdings_sent: u64,
    pub offers_sent: u64,
    pub wants_sent: u64,
    pub asks: u64,
    pub parks: u64,
    pub decodes: u64,
    pub decode_failures: u64,
    pub completed_at_k: u64,
    pub max_mesh: usize,
    pub min_mesh_at_release: Option<usize>,
}

pub struct Seacast {
    node_id: u32,
    k: usize,
    n: usize,
    stride: usize,
    proof_bytes: usize,
    uplink_mbps: u64,
    code: Code,
    keypair: Keypair,
    rng: StdRng,
    roster: BTreeMap<ProofKey, PublicKey>,
    groups: BTreeMap<ProofKey, Group>,
    peers: BTreeMap<PeerId, Peer>,
    // The window, in bytes (seacast.md §4.11).
    window: usize,
    in_flight: usize,
    waiters: VecDeque<PeerId>,
    sent: HashMap<(PeerId, ProofKey, usize), (Instant, usize)>,
    timers: BinaryHeap<Reverse<(Instant, Timer)>>,
    to_pump: BTreeSet<PeerId>,
    writes: Vec<(PeerId, ObjectPieces)>,
    history: VecDeque<BTreeMap<ProofKey, Bits>>,
    pace: VecDeque<(PeerId, BTreeMap<ProofKey, Bits>, Instant)>,
    heartbeat_armed: bool,
    pub stats: Stats,
}

impl Seacast {
    pub fn new(
        node_id: u32,
        seed: u64,
        k: usize,
        proof_bytes: usize,
        uplink_mbps: u64,
        roster: impl IntoIterator<Item = ProofKey>,
    ) -> Self {
        let n = 2 * k;
        assert!(
            n <= 128 && n.is_power_of_two(),
            "SEACAST arm needs 2k a power of two up to 128"
        );
        let window = (uplink_mbps as f64 * 1e6 / 8.0 * RTT_REF_TARGET.as_secs_f64()) as usize;
        Self {
            node_id,
            k,
            n,
            stride: proof_bytes.div_ceil(k),
            proof_bytes,
            uplink_mbps,
            code: Code::new(k, n),
            keypair: node_keypair(node_id),
            rng: StdRng::seed_from_u64(seed ^ (u64::from(node_id) << 1) ^ 0x5eac),
            roster: roster
                .into_iter()
                .map(|key| (key, node_keypair(key.producer).public()))
                .collect(),
            groups: BTreeMap::new(),
            peers: BTreeMap::new(),
            window,
            in_flight: 0,
            waiters: VecDeque::new(),
            sent: HashMap::new(),
            timers: BinaryHeap::new(),
            to_pump: BTreeSet::new(),
            writes: Vec::new(),
            history: VecDeque::from([BTreeMap::new()]),
            pace: VecDeque::new(),
            heartbeat_armed: false,
            stats: Stats::default(),
        }
    }

    pub fn max_message_bytes(&self) -> usize {
        self.stride + 8 * BRANCH + COMMITMENT_SIGNATURE_BYTES + 1024
    }

    fn r_node(&self) -> usize {
        if self.uplink_mbps >= FAST_UPLINK_MBPS {
            R_FAST
        } else {
            R
        }
    }

    fn iwant_window(&self) -> Duration {
        let scale = (ASK_UPLINK_MBPS as f64 / self.uplink_mbps.max(1) as f64).max(1.0);
        IWANT_WINDOW.mul_f64(scale)
    }

    fn at(&mut self, when: Instant, timer: Timer) {
        self.timers.push(Reverse((when, timer)));
    }

    pub fn next_due(&self) -> Option<Instant> {
        self.timers.peek().map(|Reverse((t, _))| *t)
    }

    pub fn take_writes(&mut self) -> Vec<(PeerId, ObjectPieces)> {
        std::mem::take(&mut self.writes)
    }

    pub fn mesh_size(&self) -> usize {
        self.peers.values().filter(|p| p.in_mesh).count()
    }

    fn mesh(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, p)| p.in_mesh)
            .map(|(q, _)| *q)
            .collect()
    }

    /// Outstanding asks, for the end-of-run report.
    pub fn pending(&self) -> usize {
        self.groups.values().map(|g| g.promises.len()).sum()
    }

    fn group(&mut self, key: ProofKey) -> Option<&mut Group> {
        let producer = self.roster.get(&key)?.clone();
        let n = self.n;
        Some(
            self.groups
                .entry(key)
                .or_insert_with(|| Group::new(key, producer, n)),
        )
    }

    // ---- the per-peer queue and the writer (seacast-lite.md §7, seacast.md §4.11, §4.12)

    fn push_urgent(&mut self, p: PeerId, e: Entry) {
        let Some(peer) = self.peers.get_mut(&p) else {
            return;
        };
        if let Entry::Holding(key) = e {
            if peer
                .urgent
                .iter()
                .any(|x| matches!(x, Entry::Holding(k) if *k == key))
            {
                return; // merged: the holding is written whole when it leaves
            }
        }
        peer.urgent.push_back(e);
        self.to_pump.insert(p);
    }

    fn push_normal(&mut self, p: PeerId, e: Entry) {
        let Some(peer) = self.peers.get_mut(&p) else {
            return;
        };
        if let Entry::Offer(key, bits) = e {
            for x in peer.normal.iter_mut() {
                if let Entry::Offer(k, b) = x {
                    if *k == key {
                        *b |= bits; // offers of one group merged while they wait
                        return;
                    }
                }
            }
        }
        peer.normal.push_back(e);
        self.to_pump.insert(p);
    }

    fn send_have(&mut self, p: PeerId, key: ProofKey) {
        self.push_urgent(p, Entry::Holding(key));
    }

    fn announce(&mut self, p: PeerId, key: ProofKey, bits: Bits) {
        let Some(g) = self.groups.get(&key) else {
            return;
        };
        let b = bits & !g.pushed(&p) & !g.has(&p);
        if b != 0 && !g.peers.get(&p).is_some_and(|s| s.claim_all) {
            self.push_normal(p, Entry::Offer(key, b));
        }
    }

    fn note_push(&mut self, p: PeerId, key: ProofKey, i: usize) {
        if let Some(g) = self.groups.get_mut(&key) {
            g.pg(p).pushed |= bit(i);
        }
    }

    fn front(&self) -> Option<PeerId> {
        self.waiters
            .iter()
            .find(|q| self.peers.get(q).is_some_and(|p| !p.writing))
            .copied()
    }

    fn wake_front(&mut self) {
        if self.in_flight >= self.window {
            return;
        }
        if let Some(q) = self.front() {
            self.to_pump.insert(q);
        }
    }

    fn acquire_room(&mut self, p: PeerId, need: usize) -> bool {
        let fits = self.in_flight + need <= self.window || self.in_flight == 0;
        let front = self.front();
        if fits && (front.is_none() || front == Some(p)) {
            self.waiters.retain(|q| *q != p);
            self.in_flight += need;
            self.wake_front();
            return true;
        }
        if !self.waiters.contains(&p) {
            self.waiters.push_back(p);
        }
        false
    }

    fn free_room(&mut self, need: usize) {
        self.in_flight = self.in_flight.saturating_sub(need);
        self.wake_front();
    }

    fn leave_line(&mut self, p: PeerId) {
        if self.waiters.contains(&p) {
            self.waiters.retain(|q| *q != p);
            self.wake_front();
        }
    }

    fn holders(&self, key: &ProofKey, i: usize) -> u16 {
        self.groups.get(key).map_or(0, |g| g.holders[i])
    }

    /// seacast.md §4.12: control at the head first, then the source's own chunks, then
    /// the rarest chunk before the first control-only entry.
    fn choose(&self, q: &VecDeque<Entry>) -> usize {
        let rarity = |k: usize| match &q[k] {
            Entry::Chunk { key, index, .. } => (self.holders(key, *index), k),
            _ => (u16::MAX, k),
        };
        if !matches!(q[0], Entry::Chunk { .. }) {
            return 0;
        }
        let own: Vec<usize> = (0..q.len())
            .filter(|&k| matches!(q[k], Entry::Chunk { own: true, .. }))
            .collect();
        if !own.is_empty() {
            return own
                .into_iter()
                .min_by_key(|&k| rarity(k))
                .expect("own chunk");
        }
        (0..q.len())
            .take_while(|&k| matches!(q[k], Entry::Chunk { .. }))
            .min_by_key(|&k| rarity(k))
            .unwrap_or(0)
    }

    fn chunk_msg(&self, p: &PeerId, key: ProofKey, i: usize) -> Option<(Msg, bool)> {
        let g = self.groups.get(&key)?;
        let (branch, data) = g.chunks[i].clone()?;
        let header = g
            .peers
            .get(p)
            .map_or(true, PeerGroup::needs_header)
            .then(|| g.header.clone())
            .flatten();
        let with_header = header.is_some();
        Some((
            Msg::Chunk {
                key,
                index: i,
                branch,
                header,
                data,
            },
            with_header,
        ))
    }

    fn next_to_send(&mut self, p: PeerId, now: Instant) -> Option<ObjectPieces> {
        loop {
            let peer = self.peers.get_mut(&p)?;
            if let Some(e) = peer.urgent.pop_front() {
                if let Some(m) = self.render(p, e, now) {
                    return Some(m);
                }
                continue;
            }
            if peer.normal.is_empty() {
                self.leave_line(p);
                return None;
            }
            let k = self.choose(&self.peers[&p].normal);
            let entry = self.peers[&p].normal[k].clone();
            if let Entry::Chunk {
                key,
                index,
                solicited,
                ..
            } = entry
            {
                let Some(g) = self.groups.get(&key) else {
                    self.peers.get_mut(&p)?.normal.remove(k);
                    continue;
                };
                let st = g.peers.get(&p);
                // Card 8: cancel a chunk the peer now holds.
                if st.is_some_and(|s| s.claim_all || s.has & bit(index) != 0) {
                    self.peers.get_mut(&p)?.normal.remove(k);
                    self.stats.cancelled += 1;
                    continue;
                }
                // Card 12: skip a push to a peer that will reach K without it; offer it instead.
                let (has, sent_to) = st.map_or((0, 0), |s| (s.has, s.sent_to));
                if !solicited
                    && has.count_ones() + FAN_IN * (sent_to & !has).count_ones() >= self.k as u32
                {
                    self.peers.get_mut(&p)?.normal.remove(k);
                    self.stats.projected += 1;
                    let in_mesh = self.peers[&p].in_mesh;
                    if let Some(g) = self.groups.get_mut(&key) {
                        g.pg(p).pushed &= !bit(index);
                    }
                    if in_mesh {
                        self.announce(p, key, bit(index));
                    }
                    continue;
                }
                let Some((msg, with_header)) = self.chunk_msg(&p, key, index) else {
                    self.peers.get_mut(&p)?.normal.remove(k);
                    continue;
                };
                let out = encode(&msg);
                let need = wire_len(&out);
                if !self.acquire_room(p, need) {
                    return None; // in line for room; woken when room frees
                }
                self.peers.get_mut(&p)?.normal.remove(k);
                let g = self.groups.get_mut(&key).expect("group");
                let st = g.pg(p);
                st.sent_to |= bit(index);
                if with_header {
                    st.header_sent = true;
                    self.stats.headers_sent += 1;
                }
                if solicited {
                    self.stats.answers += 1;
                } else {
                    self.stats.pushes += 1;
                }
                if let Some(prev) = self.sent.insert((p, key, index), (now, need)) {
                    self.free_room(prev.1); // a second copy in flight: its room back at once
                }
                self.at(now + WINDOW_TIMEOUT, Timer::WindowTimeout(p, key, index));
                return Some(out);
            }
            let entry = self.peers.get_mut(&p)?.normal.remove(k).expect("entry");
            if let Some(m) = self.render(p, entry, now) {
                return Some(m);
            }
        }
    }

    /// A control entry as it leaves, or nothing if nothing is left of it.
    fn render(&mut self, p: PeerId, e: Entry, now: Instant) -> Option<ObjectPieces> {
        let msg = match e {
            Entry::Ctrl(m) => m,
            Entry::Holding(key) => {
                let g = self.groups.get(&key)?;
                self.stats.holdings_sent += 1;
                Msg::Have {
                    key,
                    bits: g.have_bits(),
                    offer: false,
                    claim_all: g.claimed,
                }
            }
            Entry::SourceHave(key, bits) => {
                self.stats.holdings_sent += 1;
                Msg::Have {
                    key,
                    bits,
                    offer: false,
                    claim_all: false,
                }
            }
            Entry::Offer(key, bits) => {
                let g = self.groups.get(&key)?;
                let b = bits & !g.pushed(&p) & !g.has(&p) & g.mine;
                if b == 0 || g.peers.get(&p).is_some_and(|s| s.claim_all) {
                    return None;
                }
                self.stats.offers_sent += 1;
                Msg::Have {
                    key,
                    bits: b,
                    offer: true,
                    claim_all: false,
                }
            }
            Entry::Want(key, bits) => {
                let g = self.groups.get_mut(&key)?;
                if g.stop_pull {
                    return None;
                }
                let b = bits & !g.mine;
                if b == 0 {
                    return None;
                }
                for i in indices(b) {
                    // Card 5: the promise starts at the write.
                    g.promises.insert((i, p), now);
                    self.timers
                        .push(Reverse((now + PROMISE, Timer::Promise(key, i, p))));
                }
                self.stats.wants_sent += 1;
                Msg::Want { key, bits: b }
            }
            Entry::Chunk { .. } => unreachable!("chunks leave through next_to_send"),
        };
        Some(encode(&msg))
    }

    /// Runs the writers that have something to do. Call after every event.
    pub fn flush(&mut self, now: Instant) {
        while let Some(p) = self.to_pump.pop_first() {
            if self.peers.get(&p).is_some_and(|x| !x.writing) {
                if let Some(m) = self.next_to_send(p, now) {
                    self.peers.get_mut(&p).expect("peer").writing = true;
                    if self.waiters.contains(&p) {
                        self.wake_front(); // the line skips a writer whose write is pending
                    }
                    self.writes.push((p, m));
                }
            }
        }
    }

    /// The previous write to `p` was taken by the transport.
    pub fn write_done(&mut self, p: PeerId, now: Instant) {
        if let Some(peer) = self.peers.get_mut(&p) {
            peer.writing = false;
            self.to_pump.insert(p);
            self.wake_front();
        }
        self.flush(now);
    }

    // ---- links and the push relation (seacast.md §4.1, tier 4: one symmetric relation)

    pub fn link_up(&mut self, p: PeerId, now: Instant) {
        if self.peers.contains_key(&p) {
            return;
        }
        self.peers.insert(p, Peer::default());
        self.push_urgent(p, Entry::Ctrl(Msg::Join));
        if !self.heartbeat_armed {
            self.heartbeat_armed = true;
            self.at(now + HEARTBEAT, Timer::Heartbeat);
        }
        let grafted = self
            .peers
            .values()
            .filter(|x| x.in_mesh || x.graft_pending)
            .count();
        if grafted < D_OUT {
            self.graft(p);
        }
        self.flush(now);
    }

    pub fn link_down(&mut self, p: PeerId, now: Instant) {
        if self.peers.remove(&p).is_none() {
            return;
        }
        self.waiters.retain(|q| *q != p);
        let gone: Vec<_> = self
            .sent
            .keys()
            .filter(|(q, _, _)| *q == p)
            .copied()
            .collect();
        for key in gone {
            let (_, need) = self.sent.remove(&key).expect("sent");
            self.free_room(need);
        }
        for g in self.groups.values_mut() {
            if let Some(st) = g.peers.remove(&p) {
                for i in indices(st.has) {
                    g.holders[i] = g.holders[i].saturating_sub(1);
                }
            }
            g.promises.retain(|(_, q), _| *q != p);
            for list in &mut g.offers {
                list.retain(|q| *q != p);
            }
        }
        self.flush(now);
    }

    fn graft(&mut self, p: PeerId) {
        if let Some(peer) = self.peers.get_mut(&p) {
            peer.graft_pending = true;
        }
        self.push_urgent(p, Entry::Ctrl(Msg::Graft { answer: false }));
    }

    fn join_push(&mut self, p: PeerId) {
        // seacast-lite.md §5.4: a peer that joins the relation is offered what we hold.
        let held: Vec<(ProofKey, Bits)> = self
            .groups
            .values()
            .filter(|g| !g.invalid && g.mine != 0)
            .map(|g| {
                (
                    g.key,
                    indices(g.mine)
                        .filter(|&i| g.chunks[i].is_some())
                        .fold(0, |b, i| b | bit(i)),
                )
            })
            .collect();
        for (key, bits) in held {
            self.announce(p, key, bits);
        }
    }

    fn on_graft(&mut self, p: PeerId, answer: bool, now: Instant) {
        let Some(peer) = self.peers.get_mut(&p) else {
            return;
        };
        if peer.backoff_until.is_some_and(|t| now < t) {
            peer.graft_pending = false;
            self.push_urgent(p, Entry::Ctrl(Msg::Prune));
            return;
        }
        let was = peer.in_mesh;
        peer.in_mesh = true;
        peer.graft_pending = false;
        if !answer && !was {
            self.push_urgent(p, Entry::Ctrl(Msg::Graft { answer: true }));
        }
        if !was {
            self.join_push(p);
        }
    }

    fn on_prune(&mut self, p: PeerId, now: Instant) {
        if let Some(peer) = self.peers.get_mut(&p) {
            peer.in_mesh = false;
            peer.graft_pending = false;
            peer.backoff_until = Some(now + PRUNE_BACKOFF);
        }
    }

    fn heartbeat(&mut self, now: Instant) {
        self.at(now + HEARTBEAT, Timer::Heartbeat);
        // Relation upkeep: below F_LO graft up to D_OUT; above F_HI prune to D_OUT.
        let mesh = self.mesh();
        let pending = self.peers.values().filter(|x| x.graft_pending).count();
        if mesh.len() + pending < F_LO {
            let mut cands: Vec<PeerId> = self
                .peers
                .iter()
                .filter(|(_, x)| {
                    !x.in_mesh && !x.graft_pending && !x.backoff_until.is_some_and(|t| now < t)
                })
                .map(|(q, _)| *q)
                .collect();
            cands.shuffle(&mut self.rng);
            for q in cands.into_iter().take(D_OUT - mesh.len() - pending) {
                self.graft(q);
            }
        } else if mesh.len() > F_HI {
            let mut drop = mesh.clone();
            drop.shuffle(&mut self.rng);
            for q in drop.into_iter().take(mesh.len() - D_OUT) {
                self.on_prune(q, now);
                self.push_urgent(q, Entry::Ctrl(Msg::Prune));
            }
        }
        self.stats.max_mesh = self.stats.max_mesh.max(self.mesh_size());
        // Heartbeat gossip (seacast-lite.md §6.4), paced (card 15): the last three
        // heartbeats' chunks, to a sample of the links outside the relation.
        let mut ids: BTreeMap<ProofKey, Bits> = BTreeMap::new();
        for h in &self.history {
            for (k, b) in h {
                *ids.entry(*k).or_default() |= *b;
            }
        }
        self.history.push_front(BTreeMap::new());
        self.history.truncate(GOSSIP_HISTORY);
        if !ids.is_empty() {
            let mut eligible: Vec<PeerId> = self
                .peers
                .iter()
                .filter(|(_, x)| !x.in_mesh)
                .map(|(q, _)| *q)
                .collect();
            let count = eligible
                .len()
                .min(D_LAZY.max((GOSSIP_FACTOR * eligible.len() as f64) as usize));
            eligible.shuffle(&mut self.rng);
            let was_empty = self.pace.is_empty();
            for q in eligible.into_iter().take(count) {
                self.pace.push_back((q, ids.clone(), now));
            }
            if was_empty && !self.pace.is_empty() {
                self.at(now, Timer::Pace);
            }
        }
    }

    fn pace_tick(&mut self, now: Instant) {
        while let Some((q, ids, at)) = self.pace.pop_front() {
            if now.duration_since(at) >= HEARTBEAT || !self.peers.contains_key(&q) {
                continue;
            }
            for (key, bits) in ids {
                self.announce(q, key, bits);
            }
            break;
        }
        if !self.pace.is_empty() {
            self.at(now + PACE_TICK, Timer::Pace);
        }
    }

    fn history_put(&mut self, key: ProofKey, bits: Bits) {
        *self
            .history
            .front_mut()
            .expect("history")
            .entry(key)
            .or_default() |= bits;
    }

    // ---- choosing push targets (seacast-lite.md §5.3, card 16 without the guard)

    fn tiebreak(key: ProofKey, i: usize, p: &PeerId) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (key, i, p.to_bytes()).hash(&mut h);
        h.finish()
    }

    fn choose_push(
        &mut self,
        key: ProofKey,
        i: usize,
        cands: Vec<PeerId>,
        budget: usize,
        at_source: bool,
    ) -> Vec<PeerId> {
        if budget >= cands.len() {
            return cands;
        }
        let g = &self.groups[&key];
        let known = |p: &PeerId| (g.has(p) | g.pushed(p)).count_ones();
        let mut order = cands;
        order.sort_by_key(|p| Reverse((Self::tiebreak(key, i, p), p.to_bytes())));
        order.sort_by_key(known);
        if !at_source && !order.is_empty() {
            let median = known(&order[(order.len() - 1) / 2]);
            let mut pool: Vec<PeerId> = order
                .iter()
                .filter(|p| known(p) <= median)
                .copied()
                .collect();
            pool.shuffle(&mut self.rng);
            pool.truncate(budget);
            let rest: Vec<PeerId> = order.into_iter().filter(|p| !pool.contains(p)).collect();
            order = pool;
            order.extend(rest);
        }
        order.truncate(budget);
        order
    }

    // ---- the source (seacast-lite.md §5.1, seacast.md §4.7)

    /// Codes the proof, signs the Merkle root and publishes the group.
    pub fn release(&mut self, key: ProofKey, data: &[u8], now: Instant) -> anyhow::Result<()> {
        anyhow::ensure!(
            key.producer == self.node_id,
            "only its producer releases a proof"
        );
        let mut shards: Vec<Vec<u8>> = (0..self.k)
            .map(|i| {
                let mut s = data
                    [(i * self.stride).min(data.len())..((i + 1) * self.stride).min(data.len())]
                    .to_vec();
                s.resize(self.stride, 0);
                s
            })
            .collect();
        shards.extend(self.code.encode(&shards));
        let (root, branches) = merkle(&shards);
        let header = sign_commitment(&self.keypair, key, root)?;
        let n = self.n;
        let g = self
            .group(key)
            .ok_or_else(|| anyhow::anyhow!("proof is not on the roster"))?;
        g.root = Some(root);
        g.header = Some(header);
        g.chunks = branches.into_iter().zip(shards).map(Some).collect();
        g.mine = all(n);
        g.received = all(n);
        g.claimed = true;
        g.stop_pull = true;
        g.origin = Some(0);
        // Card 13: a source on a fast uplink stripes over every link, a slower one pushes
        // to the relation.
        let pool: Vec<PeerId> = if self.uplink_mbps >= STRIPE_UPLINK_MBPS {
            self.peers.keys().copied().collect()
        } else {
            self.mesh()
        };
        let mut plan = Vec::with_capacity(n);
        for i in 0..n {
            let cands: Vec<PeerId> = pool
                .iter()
                .filter(|p| self.groups[&key].has(p) & bit(i) == 0)
                .copied()
                .collect();
            let targets = self.choose_push(key, i, cands, R, true);
            for p in &targets {
                self.note_push(*p, key, i);
            }
            plan.push(targets);
        }
        let mut led = BTreeSet::new();
        for copy in 0..R {
            for (i, targets) in plan.iter().enumerate() {
                if let Some(&p) = targets.get(copy) {
                    if led.insert(p) {
                        // P4: a peer's first chunk from us follows our HAVE naming it.
                        let origin = self.groups[&key].origin.unwrap_or(0);
                        self.push_urgent(p, Entry::SourceHave(key, origin | bit(i)));
                    }
                    self.push_normal(
                        p,
                        Entry::Chunk {
                            key,
                            index: i,
                            solicited: false,
                            own: true,
                        },
                    );
                }
            }
        }
        self.groups.get_mut(&key).expect("group").planned = plan;
        self.history_put(key, all(n));
        self.flush(now);
        Ok(())
    }

    /// A chunk of a group we publish is acknowledged (SOURCE_OFFERS = ACK): it joins our
    /// HAVE, and the relation's peers not chosen to be pushed it are offered it.
    fn origin_acked(&mut self, key: ProofKey, i: usize) {
        let Some(g) = self.groups.get_mut(&key) else {
            return;
        };
        let Some(origin) = g.origin.as_mut() else {
            return;
        };
        if *origin & bit(i) != 0 {
            return;
        }
        *origin |= bit(i);
        let planned = g.planned[i].clone();
        for q in self.mesh() {
            self.send_have(q, key);
            if !planned.contains(&q) {
                self.announce(q, key, bit(i));
            }
        }
    }

    // ---- receiving (seacast-lite.md §4, seacast.md §4.2 to §4.6)

    /// Handles one message; returns the proof this host just completed, if any.
    pub fn receive(&mut self, p: PeerId, m: &ObjectPieces, now: Instant) -> Option<ProofKey> {
        if !self.peers.contains_key(&p) {
            return None;
        }
        let done = match decode(m, self.n) {
            Some(Msg::Join) => None,
            Some(Msg::Graft { answer }) => {
                self.on_graft(p, answer, now);
                None
            }
            Some(Msg::Prune) => {
                self.on_prune(p, now);
                None
            }
            Some(Msg::Have {
                key,
                bits,
                offer: false,
                claim_all,
            }) => {
                self.on_holding(p, key, bits, claim_all);
                None
            }
            Some(Msg::Have {
                key,
                bits,
                offer: true,
                ..
            }) => {
                self.on_offer(p, key, bits, now);
                None
            }
            Some(Msg::Want { key, bits }) => {
                self.on_want(p, key, bits);
                None
            }
            Some(Msg::Chunk {
                key,
                index,
                branch,
                header,
                data,
            }) => self.on_chunk(p, key, index, branch, header, data, now),
            None => None,
        };
        self.flush(now);
        done
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chunk(
        &mut self,
        p: PeerId,
        key: ProofKey,
        i: usize,
        branch: Vec<Root>,
        header: Option<Vec<u8>>,
        data: Vec<u8>,
        _now: Instant,
    ) -> Option<ProofKey> {
        let (n, stride) = (self.n, self.stride);
        self.stats.chunks_received += 1;
        let g = self.group(key)?;
        if g.invalid {
            return None;
        }
        // Level 1: the Merkle path leads to the root the producer signed.
        if i >= n || data.len() != stride || branch.len() != n.trailing_zeros() as usize {
            self.stats.chunks_invalid += 1;
            return None;
        }
        let root = root_of(i, &data, &branch);
        match (&g.root, &header) {
            (Some(held), _) if *held != root => {
                self.stats.chunks_invalid += 1;
                return None;
            }
            (Some(_), _) => {}
            (None, Some(h)) if verify_commitment(&g.producer_key, key, root, h) => {
                g.root = Some(root);
                g.header = Some(h.clone());
            }
            (None, Some(_)) => {
                self.stats.chunks_invalid += 1;
                return None;
            }
            (None, None) => {
                self.stats.chunks_unverifiable += 1;
                return None;
            }
        }
        g.pg(p).received_from = true;
        if g.chunks[i].is_some() {
            // A copy of a chunk we hold: acknowledged, nothing more (card 14).
            self.stats.chunks_duplicate += 1;
            self.send_have(p, key);
            return None;
        }
        g.chunks[i] = Some((branch, data));
        g.received |= bit(i);
        g.close_promises(i);
        let claim = g.mine & bit(i) == 0;
        g.mine |= bit(i);
        if claim {
            for q in self.mesh() {
                self.send_have(q, key);
            }
        }
        self.send_have(p, key);
        self.forward(key, i, Some(p));
        let g = &self.groups[&key];
        if !g.claimed && g.received.count_ones() as usize >= self.k {
            self.claim_group(key);
            self.decode_group(key);
            if self.groups[&key].invalid {
                return None;
            }
            self.stats.completed_at_k += 1;
            return Some(key);
        }
        None
    }

    fn forward(&mut self, key: ProofKey, i: usize, from: Option<PeerId>) {
        let mesh = self.mesh();
        let g = &self.groups[&key];
        let holding = mesh.iter().filter(|q| g.has(q) & bit(i) != 0).count();
        let cands: Vec<PeerId> = mesh
            .iter()
            .filter(|q| {
                g.has(q) & bit(i) == 0
                    && Some(**q) != from
                    && !g.peers.get(q).is_some_and(|s| s.claim_all)
            })
            .copied()
            .collect();
        let budget = self.r_node().saturating_sub(holding);
        let targets = self.choose_push(key, i, cands.clone(), budget, false);
        for q in &targets {
            self.push_normal(
                *q,
                Entry::Chunk {
                    key,
                    index: i,
                    solicited: false,
                    own: false,
                },
            );
            self.note_push(*q, key, i);
        }
        for q in cands {
            if !targets.contains(&q) {
                self.announce(q, key, bit(i));
            }
        }
        self.history_put(key, bit(i));
    }

    fn on_holding(&mut self, p: PeerId, key: ProofKey, bits: Bits, claim_all: bool) {
        let n = self.n;
        let Some(g) = self.group(key) else { return };
        let st = g.pg(p);
        let bits = if claim_all { all(n) } else { bits };
        let newly = bits & !st.has;
        st.has |= bits;
        st.claim_all |= claim_all;
        for i in indices(newly) {
            g.holders[i] += 1;
        }
        let source = g.origin.is_some();
        for i in indices(newly) {
            if let Some((_, need)) = self.sent.remove(&(p, key, i)) {
                self.free_room(need);
            }
            if source {
                self.origin_acked(key, i);
            }
        }
    }

    fn on_offer(&mut self, p: PeerId, key: ProofKey, bits: Bits, now: Instant) {
        let window = self.iwant_window();
        let Some(g) = self.group(key) else { return };
        g.pg(p).offered = true;
        if g.stop_pull || g.invalid {
            return;
        }
        let mut asks = Vec::new();
        let mut resort = Vec::new();
        for i in indices(bits & !g.mine) {
            if g.offers[i].len() < OFFER_LIST && !g.offers[i].contains(&p) {
                g.offers[i].push(p);
            }
            if g.parked(&p, now) {
                resort.push(i);
                continue;
            }
            if g.promises.contains_key(&(i, p)) {
                continue;
            }
            asks.push(i);
        }
        asks.shuffle(&mut self.rng);
        let mut want = 0;
        for i in asks {
            if self.may_ask(key, i, p, now, window) {
                want |= bit(i);
            }
        }
        if want != 0 {
            self.push_normal(p, Entry::Want(key, want));
        }
        for i in resort {
            self.last_resort(key, i, now);
        }
    }

    /// Card 5: one ask per chunk at a time; the retry moves on after the window.
    fn may_ask(
        &mut self,
        key: ProofKey,
        i: usize,
        p: PeerId,
        now: Instant,
        window: Duration,
    ) -> bool {
        let g = self.groups.get_mut(&key).expect("group");
        if g.asked_at[i].is_some_and(|at| now.duration_since(at) < window) {
            return false;
        }
        g.asked_at[i] = Some(now);
        g.tried[i].insert(p, now);
        self.stats.asks += 1;
        self.at(now + window + RETRY_SLACK, Timer::Retry(key, i));
        true
    }

    fn queued_want(&self, p: &PeerId, key: ProofKey, i: usize) -> bool {
        self.peers.get(p).is_some_and(|x| {
            x.normal
                .iter()
                .any(|e| matches!(e, Entry::Want(k, b) if *k == key && b & bit(i) != 0))
        })
    }

    fn retry_offer(&mut self, key: ProofKey, i: usize, now: Instant) {
        let window = self.iwant_window();
        let Some(g) = self.groups.get(&key) else {
            return;
        };
        if g.mine & bit(i) != 0
            || g.stop_pull
            || g.asked_at[i].is_some_and(|at| now.duration_since(at) < window)
        {
            return;
        }
        let cands: Vec<PeerId> = g.offers[i]
            .iter()
            .filter(|q| !g.parked(q, now))
            .copied()
            .collect();
        if cands.is_empty() {
            return self.last_resort(key, i, now);
        }
        let free: Vec<PeerId> = cands
            .into_iter()
            .filter(|q| !g.promises.contains_key(&(i, *q)) && !self.queued_want(q, key, i))
            .collect();
        if free.is_empty() {
            return self.at(now + window + RETRY_SLACK, Timer::Retry(key, i));
        }
        let pick = free
            .iter()
            .find(|q| !g.tried[i].contains_key(q))
            .or_else(|| free.iter().min_by_key(|q| g.tried[i][q]))
            .copied()
            .expect("candidate");
        if self.may_ask(key, i, pick, now, window) {
            self.push_normal(pick, Entry::Want(key, bit(i)));
        }
    }

    fn last_resort(&mut self, key: ProofKey, i: usize, now: Instant) {
        let g = &self.groups[&key];
        if g.last_resort_armed[i] || g.offers[i].iter().any(|q| !g.parked(q, now)) {
            return;
        }
        if g.offers[i].iter().all(|q| g.asked_parked[i].contains(q)) {
            return;
        }
        let wait = PROMISE * 2u32.pow(g.asked_parked[i].len().min(6) as u32);
        self.groups.get_mut(&key).expect("group").last_resort_armed[i] = true;
        self.at(now + wait, Timer::LastResort(key, i));
    }

    fn ask_parked(&mut self, key: ProofKey, i: usize, now: Instant) {
        let window = self.iwant_window();
        let g = self.groups.get_mut(&key).expect("group");
        g.last_resort_armed[i] = false;
        if g.mine & bit(i) != 0
            || g.stop_pull
            || g.asked_at[i].is_some_and(|at| now.duration_since(at) < window)
        {
            return;
        }
        let mut cands: Vec<PeerId> = g.offers[i]
            .iter()
            .filter(|q| !g.parked(q, now))
            .copied()
            .collect();
        if cands.is_empty() {
            cands = g.offers[i]
                .iter()
                .filter(|q| !g.asked_parked[i].contains(q))
                .copied()
                .collect();
        }
        let Some(pick) = cands
            .into_iter()
            .find(|q| !g.promises.contains_key(&(i, *q)))
        else {
            return;
        };
        if g.parked(&pick, now) {
            g.asked_parked[i].insert(pick);
        }
        if self.may_ask(key, i, pick, now, window) {
            self.push_normal(pick, Entry::Want(key, bit(i)));
        }
    }

    fn on_want(&mut self, p: PeerId, key: ProofKey, bits: Bits) {
        let Some(g) = self.groups.get_mut(&key) else {
            return;
        };
        if g.invalid {
            return;
        }
        let st_has = g.has(&p);
        let mut answers = Vec::new();
        for i in indices(bits) {
            if st_has & bit(i) != 0 || g.chunks[i].is_none() {
                continue;
            }
            let count = g.pg(p).served.entry(i).or_default();
            if *count >= GOSSIP_RETRANSMISSION {
                continue;
            }
            *count += 1;
            answers.push(i);
        }
        for i in answers {
            self.push_normal(
                p,
                Entry::Chunk {
                    key,
                    index: i,
                    solicited: true,
                    own: false,
                },
            );
        }
    }

    /// The decode claim at K (card 10): stop pulling, claim every chunk, close promises.
    fn claim_group(&mut self, key: ProofKey) {
        let n = self.n;
        let g = self.groups.get_mut(&key).expect("group");
        g.stop_pull = true;
        g.claimed = true;
        g.mine = all(n);
        g.promises.clear();
        for q in self.mesh() {
            self.send_have(q, key);
        }
    }

    /// Level 2: rebuild every chunk from any K and check the root, then repair.
    fn decode_group(&mut self, key: ProofKey) {
        self.stats.decodes += 1;
        let (k, n) = (self.k, self.n);
        let g = &self.groups[&key];
        let have: Vec<(usize, &[u8])> = (0..n)
            .filter_map(|i| g.chunks[i].as_ref().map(|(_, d)| (i, d.as_slice())))
            .collect();
        let Some(data) = self.code.reconstruct(&have) else {
            self.stats.decode_failures += 1;
            self.groups.get_mut(&key).expect("group").invalid = true;
            return;
        };
        let mut shards = data;
        shards.extend(self.code.encode(&shards));
        let (root, branches) = merkle(&shards);
        if Some(root) != g.root {
            self.stats.decode_failures += 1;
            self.groups.get_mut(&key).expect("group").invalid = true;
            return;
        }
        let g = self.groups.get_mut(&key).expect("group");
        let mut rebuilt = 0;
        for (i, (branch, shard)) in branches.into_iter().zip(shards).enumerate() {
            if g.chunks[i].is_none() {
                g.chunks[i] = Some((branch, shard));
                rebuilt |= bit(i);
            }
        }
        let _ = k;
        self.push_rebuilt(key, rebuilt);
    }

    /// Repair: rebuilt chunks to the relation's peers still short of K.
    fn push_rebuilt(&mut self, key: ProofKey, rebuilt: Bits) {
        let mut mesh = self.mesh();
        mesh.shuffle(&mut self.rng);
        for q in mesh {
            let g = &self.groups[&key];
            if g.peers.get(&q).is_some_and(|s| s.claim_all) {
                continue;
            }
            let known = g.has(&q) | g.pushed(&q);
            let short = self.k.saturating_sub(known.count_ones() as usize);
            if short == 0 {
                continue;
            }
            let mut lacks: Vec<usize> = indices(rebuilt & !known).collect();
            lacks.shuffle(&mut self.rng);
            for i in lacks.into_iter().take(short) {
                self.push_normal(
                    q,
                    Entry::Chunk {
                        key,
                        index: i,
                        solicited: false,
                        own: false,
                    },
                );
                self.note_push(q, key, i);
                self.stats.repairs += 1;
            }
        }
    }

    // ---- timers

    pub fn on_timer(&mut self, now: Instant) {
        while let Some(Reverse((at, timer))) = self.timers.peek().copied() {
            if at > now {
                break;
            }
            self.timers.pop();
            match timer {
                Timer::Heartbeat => self.heartbeat(now),
                Timer::Pace => self.pace_tick(now),
                Timer::WindowTimeout(p, key, i) => {
                    if self
                        .sent
                        .get(&(p, key, i))
                        .is_some_and(|(t, _)| *t + WINDOW_TIMEOUT <= now)
                    {
                        let (_, need) = self.sent.remove(&(p, key, i)).expect("sent");
                        self.free_room(need);
                        self.origin_acked(key, i);
                    }
                }
                Timer::Retry(key, i) => self.retry_offer(key, i, now),
                Timer::Promise(key, i, p) => {
                    let g = self.groups.get_mut(&key).expect("group");
                    if g.promises.get(&(i, p)).is_some_and(|t| *t + PROMISE <= now) {
                        g.promises.remove(&(i, p));
                        g.pg(p).parked_until = Some(now + PARK_TTL);
                        self.stats.parks += 1;
                    }
                }
                Timer::LastResort(key, i) => self.ask_parked(key, i, now),
            }
        }
        self.flush(now);
    }

    pub fn note_release_mesh(&mut self) {
        let m = self.mesh_size();
        self.stats.min_mesh_at_release =
            Some(self.stats.min_mesh_at_release.map_or(m, |x| x.min(m)));
    }

    pub fn proof_bytes(&self) -> usize {
        self.proof_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(subnet: u32, producer: u32) -> ProofKey {
        ProofKey { subnet, producer }
    }

    #[test]
    fn messages_round_trip_through_the_waggle_binding() {
        let k = key(3, 9);
        let msgs = [
            Msg::Join,
            Msg::Graft { answer: true },
            Msg::Prune,
            Msg::Have {
                key: k,
                bits: 0b1011 | bit(127),
                offer: false,
                claim_all: true,
            },
            Msg::Have {
                key: k,
                bits: 0b100,
                offer: true,
                claim_all: false,
            },
            Msg::Want {
                key: k,
                bits: bit(64),
            },
            Msg::Chunk {
                key: k,
                index: 5,
                branch: vec![[7; 32]; 7],
                header: Some(vec![1; 2400]),
                data: vec![2; 100],
            },
            Msg::Chunk {
                key: k,
                index: 6,
                branch: vec![[8; 32]; 7],
                header: None,
                data: vec![3; 100],
            },
        ];
        for m in msgs {
            assert_eq!(decode(&encode(&m), 128), Some(m));
        }
        // A bitmap with a bit beyond the group's count, or a forged group id, is refused.
        let wide = encode(&Msg::Have {
            key: k,
            bits: bit(70),
            offer: false,
            claim_all: false,
        });
        assert!(decode(&wide, 64).is_none());
        let mut forged = encode(&Msg::Want { key: k, bits: 1 });
        forged.object_id[20] ^= 1;
        assert!(decode(&forged, 128).is_none());
    }

    #[test]
    fn the_signature_goes_only_to_a_peer_that_may_lack_it() {
        let fresh = PeerGroup::default();
        assert!(fresh.needs_header());
        for st in [
            PeerGroup {
                header_sent: true,
                ..PeerGroup::default()
            },
            PeerGroup {
                received_from: true,
                ..PeerGroup::default()
            },
            PeerGroup {
                offered: true,
                ..PeerGroup::default()
            },
            PeerGroup {
                has: 0b1000,
                ..PeerGroup::default()
            },
            PeerGroup {
                claim_all: true,
                ..PeerGroup::default()
            },
        ] {
            assert!(!st.needs_header());
        }
    }

    #[test]
    fn the_merkle_branch_leads_to_the_root() {
        let chunks: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 10]).collect();
        let (root, branches) = merkle(&chunks);
        for (i, b) in branches.iter().enumerate() {
            assert_eq!(root_of(i, &chunks[i], b), root);
            assert_ne!(root_of(i ^ 1, &chunks[i], b), root);
        }
    }

    /// A small network on a lossless instantaneous transport: every host completes
    /// every proof at K, decodes it, and the producers' traffic stays bounded.
    #[test]
    fn every_host_completes_every_proof_on_a_small_network() {
        let hosts = 12u32;
        let k = 8;
        let roster = vec![key(0, 0), key(1, 5), key(1, 7)];
        let peer = |i: u32| node_keypair(i).public().to_peer_id();
        let by_peer: BTreeMap<PeerId, u32> = (0..hosts).map(|i| (peer(i), i)).collect();
        let mut nodes: Vec<Seacast> = (0..hosts)
            .map(|i| {
                Seacast::new(
                    i,
                    1,
                    k,
                    1000,
                    if i == 5 { 1000 } else { 50 },
                    roster.clone(),
                )
            })
            .collect();
        let t0 = Instant::now();
        // A ring plus chords, each host linked to 6 others.
        for i in 0..hosts {
            for d in [1, 2, 5] {
                let j = (i + d) % hosts;
                nodes[i as usize].link_up(peer(j), t0);
                nodes[j as usize].link_up(peer(i), t0);
            }
        }
        let mut now = t0;
        let mut complete: BTreeSet<(u32, ProofKey)> = BTreeSet::new();
        let data = vec![42u8; 1000];
        for step in 0..4000 {
            if step == 50 {
                for &rk in &roster {
                    nodes[rk.producer as usize].release(rk, &data, now).unwrap();
                    complete.insert((rk.producer, rk));
                }
            }
            // Deliver every pending write, then let each writer continue.
            let mut moved = false;
            for i in 0..hosts as usize {
                for (to, msg) in nodes[i].take_writes() {
                    moved = true;
                    let j = by_peer[&to] as usize;
                    if let Some(key) = nodes[j].receive(peer(i as u32), &msg, now) {
                        complete.insert((j as u32, key));
                    }
                    nodes[i].write_done(to, now);
                }
            }
            if !moved {
                now += Duration::from_millis(5);
                for n in nodes.iter_mut() {
                    n.on_timer(now);
                }
            }
        }
        assert_eq!(complete.len(), hosts as usize * roster.len());
        // The root signature goes to a peer at most once per proof: 12 hosts with 6
        // links each, 3 proofs.
        let headers: u64 = nodes.iter().map(|n| n.stats.headers_sent).sum();
        assert!(headers <= 12 * 6 * 3, "{headers} signatures sent");
        assert!(nodes.iter().all(|n| n.stats.chunks_unverifiable == 0));
        for n in &nodes {
            assert_eq!(n.stats.decode_failures, 0);
            assert_eq!(n.stats.chunks_invalid, 0);
            assert!(n.mesh_size() >= 3, "relation formed");
        }
        // Every host but the producer decodes each proof once.
        let decodes: u64 = nodes.iter().map(|n| n.stats.decodes).sum();
        assert_eq!(decodes, (hosts as u64 - 1) * roster.len() as u64);
    }
}
