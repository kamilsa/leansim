//! Per-hop signature sync over each subnet's gossipsub mesh: bitmap pull and
//! sparse coded repair, on top of gossipsub's eager push.
//!
//! A pure state machine like [`crate::node::recursive::ProofExchange`]: the
//! caller reports signatures, bitmaps and packets as they arrive, calls
//! [`SigSync::tick`] every `sync_interval_ms`, and sends the returned
//! [`Action`]s to the named mesh peers. Times are passed in.
//!
//! Every host tracks which signatures of its subscribed subnets it holds, in
//! all modes, so a signature that arrives twice (gossip after a pull, say)
//! counts as a duplicate however it came.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::time::Duration;

use rand::seq::{IteratorRandom, SliceRandom};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::time::Instant;

use crate::config::experiment::{ExperimentConfig, SignatureSync};
use crate::messages::sync::CodedPacket;
use crate::node::decoder::{Column, Decoder};
use crate::node::gf256::mul;

/// Origin of a signature whose publishing host is unknown.
pub const UNKNOWN_ORIGIN: u32 = u32::MAX;

/// The one-byte stand-in for a validator's signature that coded packets carry.
pub fn symbol_of(validator_id: u32) -> u8 {
    (validator_id.wrapping_mul(2_654_435_761) >> 24) as u8
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SyncSettings {
    pub mode: SignatureSync,
    pub validators_per_subnet: usize,
    pub grace: Duration,
    pub pull_batch: usize,
    pub pull_timeout: Duration,
    /// Signatures per coded packet; 0 picks log2(gaps) + 2 (at most 16).
    pub coded_degree: usize,
    /// Packets the mesh sends a peer per gap: each neighbour sends
    /// ceil(redundancy * gaps / its mesh size).
    pub coded_redundancy: f64,
    pub coded_per_tick: usize,
    pub refresh: Duration,
    pub payload_bytes: usize,
}

impl SyncSettings {
    pub fn from_config(config: &ExperimentConfig) -> Self {
        Self {
            mode: config.signature_sync,
            validators_per_subnet: config.validators_per_subnet(),
            grace: Duration::from_millis(config.sync_grace_ms),
            pull_batch: config.sync_pull_batch,
            pull_timeout: Duration::from_millis(config.sync_pull_timeout_ms),
            coded_degree: config.sync_coded_degree,
            coded_redundancy: config.sync_coded_redundancy,
            coded_per_tick: config.sync_coded_per_tick,
            refresh: Duration::from_millis(config.sync_refresh_ms),
            payload_bytes: config.signature_payload_bytes,
        }
    }
}

/// Network work the caller must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action<P> {
    Have {
        peer: P,
        subnet: u32,
        bitmap: Vec<u8>,
    },
    Want {
        peer: P,
        subnet: u32,
        validators: Vec<u32>,
    },
    Coded {
        peer: P,
        subnet: u32,
        packet: CodedPacket,
    },
}

/// A signature this host now holds for the first time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Held {
    pub validator_id: u32,
    pub origin: u32,
}

/// What a coded packet did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodedOutcome {
    /// It raised the rank of this host's pending equations.
    pub innovative: bool,
    /// Signatures it completed.
    pub decoded: Vec<Held>,
    /// Decoded symbols that did not match the signer's (must stay 0).
    pub mismatches: u32,
}

/// A fixed-size bitmap of a subnet's validators.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Bits(Vec<u64>);

impl Bits {
    fn new(len: usize) -> Self {
        Self(vec![0; len.div_ceil(64)])
    }

    fn get(&self, i: usize) -> bool {
        self.0
            .get(i / 64)
            .is_some_and(|word| word >> (i % 64) & 1 == 1)
    }

    fn set(&mut self, i: usize) {
        if let Some(word) = self.0.get_mut(i / 64) {
            *word |= 1 << (i % 64);
        }
    }

    fn to_bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.0.iter().flat_map(|word| word.to_le_bytes()).collect();
        bytes.truncate(len.div_ceil(8));
        bytes
    }

    fn from_bytes(bytes: &[u8], len: usize) -> Self {
        let mut bits = Self::new(len);
        for (i, chunk) in bytes.chunks(8).enumerate().take(bits.0.len()) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            bits.0[i] = u64::from_le_bytes(word);
        }
        // Ignore bits past the subnet's size.
        if !len.is_multiple_of(64) {
            if let Some(last) = bits.0.last_mut() {
                *last &= (1u64 << (len % 64)) - 1;
            }
        }
        bits
    }
}

/// What this host knows about one mesh neighbour in one subnet.
#[derive(Debug, Clone)]
struct PeerView {
    /// The neighbour's last bitmap; `None` until one arrives.
    have: Option<Bits>,
    /// When that bitmap arrived.
    have_at: Option<Instant>,
    /// This host's held-set version last advertised to the neighbour, and when.
    advertised_version: u64,
    advertised_at: Option<Instant>,
    /// Coded packets sent since the budget was last armed.
    coded_sent: usize,
    budget_armed_at: Option<Instant>,
}

impl PeerView {
    fn new() -> Self {
        Self {
            have: None,
            have_at: None,
            advertised_version: 0,
            advertised_at: None,
            coded_sent: 0,
            budget_armed_at: None,
        }
    }
}

struct SubnetSync<P> {
    /// Validator id of column 0.
    base: u32,
    held: Bits,
    held_at: Vec<Option<Instant>>,
    origin: Vec<u32>,
    /// Bumped whenever a signature is added, so bitmaps go out only on change.
    version: u64,
    /// Pull: when a neighbour first advertised a signature this host lacked.
    advertised_at: Vec<Option<Instant>>,
    /// Pull: columns requested and when.
    in_flight: HashMap<Column, Instant>,
    /// Coded repair: pending equations.
    decoder: Option<Decoder>,
    peers: HashMap<P, PeerView>,
}

impl<P: Copy + Eq + Hash + Ord> SubnetSync<P> {
    fn new(base: u32, size: usize, coded: bool) -> Self {
        Self {
            base,
            held: Bits::new(size),
            held_at: vec![None; size],
            origin: vec![UNKNOWN_ORIGIN; size],
            version: 0,
            advertised_at: vec![None; size],
            in_flight: HashMap::new(),
            decoder: coded.then(|| Decoder::new(size)),
            peers: HashMap::new(),
        }
    }

    fn column(&self, validator_id: u32) -> Option<Column> {
        let col = validator_id.checked_sub(self.base)? as usize;
        (col < self.held_at.len()).then_some(col as Column)
    }

    /// Marks a column held; false if it already was.
    fn mark(&mut self, col: Column, origin: u32, now: Instant) -> bool {
        let i = col as usize;
        if self.held.get(i) {
            return false;
        }
        self.held.set(i);
        self.held_at[i] = Some(now);
        if origin != UNKNOWN_ORIGIN {
            self.origin[i] = origin;
        }
        self.in_flight.remove(&col);
        self.version += 1;
        true
    }

    fn held_record(&self, col: Column) -> Held {
        Held {
            validator_id: self.base + col as u32,
            origin: self.origin[col as usize],
        }
    }
}

pub struct SigSync<P> {
    settings: SyncSettings,
    subnets: BTreeMap<u32, SubnetSync<P>>,
    rng: StdRng,
}

impl<P: Copy + Eq + Hash + Ord> SigSync<P> {
    /// Tracks `subnets` (the host's gossip subscriptions); the k-th subnet's
    /// validators are `k * validators_per_subnet ..`.
    pub fn new(settings: SyncSettings, subnets: impl IntoIterator<Item = u32>, seed: u64) -> Self {
        let size = settings.validators_per_subnet;
        let coded = settings.mode == SignatureSync::CodedRepair;
        Self {
            settings,
            subnets: subnets
                .into_iter()
                .map(|subnet| (subnet, SubnetSync::new(subnet * size as u32, size, coded)))
                .collect(),
            rng: StdRng::seed_from_u64(seed),
        }
    }

    pub fn mode(&self) -> SignatureSync {
        self.settings.mode
    }

    pub fn subnets(&self) -> impl Iterator<Item = u32> + '_ {
        self.subnets.keys().copied()
    }

    /// Whether this host tracks `subnet` (subscribes to it).
    pub fn tracks(&self, subnet: u32) -> bool {
        self.subnets.contains_key(&subnet)
    }

    pub fn holds(&self, subnet: u32, validator_id: u32) -> bool {
        self.subnets.get(&subnet).is_some_and(|sync| {
            sync.column(validator_id)
                .is_some_and(|col| sync.held.get(col as usize))
        })
    }

    pub fn held_count(&self, subnet: u32) -> usize {
        self.subnets.get(&subnet).map_or(0, |sync| {
            sync.held
                .0
                .iter()
                .map(|word| word.count_ones() as usize)
                .sum()
        })
    }

    /// Pending coded equations across subnets.
    pub fn pending_rows(&self) -> usize {
        self.subnets
            .values()
            .filter_map(|sync| sync.decoder.as_ref())
            .map(Decoder::pending_rows)
            .sum()
    }

    /// A signature arrived uncoded (published here, gossip, or a pull). Returns
    /// every signature newly held: this one first, unless it was already held,
    /// then any it let the decoder finish.
    pub fn deliver(
        &mut self,
        subnet: u32,
        validator_id: u32,
        origin: u32,
        now: Instant,
    ) -> Vec<Held> {
        let Some(sync) = self.subnets.get_mut(&subnet) else {
            return Vec::new();
        };
        let Some(col) = sync.column(validator_id) else {
            return Vec::new();
        };
        if !sync.mark(col, origin, now) {
            return Vec::new();
        }
        let mut held = vec![sync.held_record(col)];
        let decoded = match sync.decoder.as_mut() {
            Some(decoder) => decoder.learn(col, symbol_of(validator_id)),
            None => Vec::new(),
        };
        for (col, _) in decoded {
            if sync.mark(col, UNKNOWN_ORIGIN, now) {
                held.push(sync.held_record(col));
            }
        }
        held
    }

    /// A neighbour's bitmap arrived.
    pub fn on_have(&mut self, peer: P, subnet: u32, bitmap: &[u8], now: Instant) {
        let Some(sync) = self.subnets.get_mut(&subnet) else {
            return;
        };
        let size = sync.held_at.len();
        let have = Bits::from_bytes(bitmap, size);
        for i in 0..size {
            if have.get(i) && !sync.held.get(i) && sync.advertised_at[i].is_none() {
                sync.advertised_at[i] = Some(now);
            }
        }
        let view = sync.peers.entry(peer).or_insert_with(PeerView::new);
        if view.have.as_ref() != Some(&have) {
            // News from the peer: its deficit is fresh, so re-arm its repair budget.
            view.coded_sent = 0;
            view.budget_armed_at = Some(now);
        }
        view.have = Some(have);
        view.have_at = Some(now);
    }

    /// A coded packet arrived.
    pub fn on_coded(&mut self, subnet: u32, packet: &CodedPacket, now: Instant) -> CodedOutcome {
        let Some(sync) = self.subnets.get_mut(&subnet) else {
            return CodedOutcome::default();
        };
        let mut entries = Vec::with_capacity(packet.validators.len());
        for (k, &validator_id) in packet.validators.iter().enumerate() {
            let (Some(col), Some(&coeff)) = (sync.column(validator_id), packet.coeffs.get(k))
            else {
                continue;
            };
            let origin = packet.origins.get(k).copied().unwrap_or(UNKNOWN_ORIGIN);
            if sync.origin[col as usize] == UNKNOWN_ORIGIN {
                sync.origin[col as usize] = origin;
            }
            entries.push((col, coeff));
        }
        let Some(decoder) = sync.decoder.as_mut() else {
            return CodedOutcome::default();
        };
        let insert = decoder.insert(&entries, packet.symbol);
        let mut outcome = CodedOutcome {
            innovative: insert.innovative,
            ..CodedOutcome::default()
        };
        for (col, symbol) in insert.decoded {
            if symbol != symbol_of(sync.base + col as u32) {
                outcome.mismatches += 1;
            }
            if sync.mark(col, UNKNOWN_ORIGIN, now) {
                outcome.decoded.push(sync.held_record(col));
            }
        }
        outcome
    }

    /// The requested signatures this host holds, to answer a pull.
    pub fn serve(&self, subnet: u32, validators: &[u32]) -> Vec<Held> {
        let Some(sync) = self.subnets.get(&subnet) else {
            return Vec::new();
        };
        validators
            .iter()
            .filter_map(|&validator_id| sync.column(validator_id))
            .filter(|&col| sync.held.get(col as usize))
            .map(|col| sync.held_record(col))
            .collect()
    }

    /// A pull finished (answered or failed): its unanswered columns may be retried.
    pub fn pull_done(&mut self, subnet: u32, validators: &[u32]) {
        if let Some(sync) = self.subnets.get_mut(&subnet) {
            for &validator_id in validators {
                if let Some(col) = sync.column(validator_id) {
                    sync.in_flight.remove(&col);
                }
            }
        }
    }

    /// Plans this tick's messages. `mesh` names each subnet's current mesh peers.
    pub fn tick(&mut self, now: Instant, mut mesh: impl FnMut(u32) -> Vec<P>) -> Vec<Action<P>> {
        let mut actions = Vec::new();
        if self.settings.mode == SignatureSync::None {
            return actions;
        }
        let settings = self.settings;
        let subnet_ids: Vec<u32> = self.subnets.keys().copied().collect();
        for subnet in subnet_ids {
            let mut peers = mesh(subnet);
            peers.sort_unstable();
            peers.dedup();
            peers.shuffle(&mut self.rng);
            let sync = self.subnets.get_mut(&subnet).expect("listed above");
            let size = sync.held_at.len();

            // Bitmaps, to every mesh peer that has not heard the current one. An
            // incomplete host also repeats an unchanged bitmap every `refresh`, so
            // neighbours that got signatures after its last one learn it lacks them.
            let held: usize = sync.held.0.iter().map(|w| w.count_ones() as usize).sum();
            let incomplete = held < size;
            if sync.version > 0 {
                let bitmap = sync.held.to_bytes(size);
                for &peer in &peers {
                    let view = sync.peers.entry(peer).or_insert_with(PeerView::new);
                    let due = incomplete
                        && view.advertised_at.is_some_and(|at| {
                            now.saturating_duration_since(at) >= settings.refresh
                        });
                    if view.advertised_version != sync.version || due {
                        view.advertised_version = sync.version;
                        view.advertised_at = Some(now);
                        actions.push(Action::Have {
                            peer,
                            subnet,
                            bitmap: bitmap.clone(),
                        });
                    }
                }
            }

            match settings.mode {
                SignatureSync::None => {}
                SignatureSync::BitmapPull => {
                    plan_pulls(sync, &peers, &settings, now, subnet, &mut actions)
                }
                SignatureSync::CodedRepair => plan_repairs(
                    sync,
                    &peers,
                    &settings,
                    now,
                    subnet,
                    &mut self.rng,
                    &mut actions,
                ),
            }
        }
        actions
    }
}

/// Pull every signature a neighbour advertised at least `grace` ago, from the
/// advertising neighbours with the fewest requests so far, `pull_batch` each.
fn plan_pulls<P: Copy + Eq + Hash + Ord>(
    sync: &mut SubnetSync<P>,
    peers: &[P],
    settings: &SyncSettings,
    now: Instant,
    subnet: u32,
    actions: &mut Vec<Action<P>>,
) {
    sync.in_flight
        .retain(|_, at| now.saturating_duration_since(*at) < settings.pull_timeout);
    let size = sync.held_at.len();
    let mut wanted: Vec<(Instant, Column)> = (0..size)
        .filter(|&i| !sync.held.get(i))
        .filter_map(|i| sync.advertised_at[i].map(|at| (at, i as Column)))
        .filter(|(at, col)| {
            now.saturating_duration_since(*at) >= settings.grace
                && !sync.in_flight.contains_key(col)
        })
        .collect();
    if wanted.is_empty() {
        return;
    }
    wanted.sort_unstable();
    let mut batches: Vec<Vec<u32>> = vec![Vec::new(); peers.len()];
    for (_, col) in wanted {
        let holder = peers
            .iter()
            .enumerate()
            .filter(|(k, peer)| {
                batches[*k].len() < settings.pull_batch
                    && sync
                        .peers
                        .get(*peer)
                        .and_then(|view| view.have.as_ref())
                        .is_some_and(|have| have.get(col as usize))
            })
            .min_by_key(|(k, _)| batches[*k].len())
            .map(|(k, _)| k);
        if let Some(k) = holder {
            batches[k].push(sync.base + col as u32);
            sync.in_flight.insert(col, now);
        }
    }
    for (k, validators) in batches.into_iter().enumerate() {
        if !validators.is_empty() {
            actions.push(Action::Want {
                peer: peers[k],
                subnet,
                validators,
            });
        }
    }
}

/// Signatures per packet for `gaps` gaps: `configured`, or with 0 about
/// log2(gaps) + 2, which uncoordinated senders need for the receiver's
/// equations to reach full rank (lower degrees leave gaps uncovered).
pub fn coded_degree(configured: usize, gaps: usize) -> usize {
    let degree = if configured == 0 {
        (usize::BITS - gaps.leading_zeros()) as usize + 2
    } else {
        configured
    };
    degree.clamp(1, MAX_AUTO_DEGREE.max(configured)).min(gaps)
}

/// Cap of the automatic degree; past it, elimination fill-in costs more than it gains.
pub const MAX_AUTO_DEGREE: usize = 16;

/// Push each neighbour random sparse combinations of the signatures it lacks:
/// those missing from its last bitmap although that bitmap came at least
/// `grace` after this host got them (so gossip had its chance): up to
/// ceil(redundancy * gaps / mesh size) packets per bitmap heard, `coded_per_tick` a tick.
fn plan_repairs<P: Copy + Eq + Hash + Ord>(
    sync: &mut SubnetSync<P>,
    peers: &[P],
    settings: &SyncSettings,
    now: Instant,
    subnet: u32,
    rng: &mut StdRng,
    actions: &mut Vec<Action<P>>,
) {
    let size = sync.held_at.len();
    for &peer in peers {
        let Some(view) = sync.peers.get_mut(&peer) else {
            continue;
        };
        let (Some(have), Some(have_at)) = (view.have.as_ref(), view.have_at) else {
            continue;
        };
        let lacking: Vec<Column> = (0..size)
            .filter(|&i| {
                !have.get(i)
                    && sync.held_at[i]
                        .is_some_and(|at| have_at.saturating_duration_since(at) >= settings.grace)
            })
            .map(|i| i as Column)
            .collect();
        if lacking.is_empty() {
            continue;
        }
        let stale = view
            .budget_armed_at
            .is_none_or(|at| now.saturating_duration_since(at) >= settings.refresh);
        if stale {
            view.coded_sent = 0;
            view.budget_armed_at = Some(now);
        }
        let share = settings.coded_redundancy / peers.len().max(1) as f64;
        let budget = (lacking.len() as f64 * share).ceil() as usize;
        let count = budget
            .saturating_sub(view.coded_sent)
            .min(settings.coded_per_tick);
        view.coded_sent += count;
        let degree = coded_degree(settings.coded_degree, lacking.len());
        for _ in 0..count {
            let mut validators = Vec::with_capacity(degree);
            let mut coeffs = Vec::with_capacity(degree);
            let mut origins = Vec::with_capacity(degree);
            let mut symbol = 0u8;
            for col in lacking.iter().copied().choose_multiple(rng, degree) {
                let validator_id = sync.base + col as u32;
                let coeff: u8 = if degree == 1 {
                    1
                } else {
                    rng.gen_range(1..=255)
                };
                symbol ^= mul(coeff, symbol_of(validator_id));
                validators.push(validator_id);
                coeffs.push(coeff);
                origins.push(sync.origin[col as usize]);
            }
            actions.push(Action::Coded {
                peer,
                subnet,
                packet: CodedPacket {
                    validators,
                    coeffs,
                    origins,
                    symbol,
                    payload: vec![0; settings.payload_bytes],
                },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(mode: SignatureSync) -> SyncSettings {
        SyncSettings {
            mode,
            validators_per_subnet: 16,
            grace: Duration::from_millis(100),
            pull_batch: 4,
            pull_timeout: Duration::from_millis(500),
            coded_degree: 3,
            coded_redundancy: 1.0,
            coded_per_tick: 100,
            refresh: Duration::from_millis(1000),
            payload_bytes: 8,
        }
    }

    fn bitmap(cols: &[usize]) -> Vec<u8> {
        let mut bits = Bits::new(16);
        for &col in cols {
            bits.set(col);
        }
        bits.to_bytes(16)
    }

    #[test]
    fn bits_roundtrip_through_bytes() {
        let bytes = bitmap(&[0, 3, 15]);
        assert_eq!(bytes.len(), 2);
        let bits = Bits::from_bytes(&bytes, 16);
        assert!(bits.get(0) && bits.get(3) && bits.get(15) && !bits.get(1));
    }

    #[test]
    fn duplicate_delivery_holds_nothing_new() {
        let now = Instant::now();
        let mut sync: SigSync<u8> = SigSync::new(settings(SignatureSync::None), [1], 0);
        // Subnet 1 holds validators 16..32.
        assert_eq!(sync.deliver(1, 17, 5, now).len(), 1);
        assert!(sync.deliver(1, 17, 5, now).is_empty());
        assert!(
            sync.deliver(1, 3, 5, now).is_empty(),
            "validator of another subnet"
        );
        assert!(sync.holds(1, 17));
        assert!(
            sync.tick(now, |_| vec![1]).is_empty(),
            "mode none sends nothing"
        );
    }

    #[test]
    fn bitmaps_go_out_only_when_the_held_set_changes() {
        let now = Instant::now();
        let mut sync: SigSync<u8> = SigSync::new(settings(SignatureSync::BitmapPull), [0], 0);
        assert!(
            sync.tick(now, |_| vec![1, 2]).is_empty(),
            "nothing held yet"
        );
        sync.deliver(0, 2, 0, now);
        let haves = sync
            .tick(now, |_| vec![1, 2])
            .into_iter()
            .filter(|a| matches!(a, Action::Have { .. }))
            .count();
        assert_eq!(haves, 2);
        assert!(sync.tick(now, |_| vec![1, 2]).is_empty());
    }

    #[test]
    fn pulls_wait_out_the_grace_and_spread_over_holders() {
        let t0 = Instant::now();
        let mut sync: SigSync<u8> = SigSync::new(settings(SignatureSync::BitmapPull), [0], 0);
        sync.on_have(1, 0, &bitmap(&[0, 1, 2, 3, 4, 5]), t0);
        sync.on_have(2, 0, &bitmap(&[0, 1, 2, 3, 4, 5]), t0);
        assert!(sync.tick(t0, |_| vec![1, 2]).is_empty(), "inside the grace");
        let later = t0 + Duration::from_millis(100);
        let wants: Vec<_> = sync
            .tick(later, |_| vec![1, 2])
            .into_iter()
            .filter_map(|a| match a {
                Action::Want {
                    peer, validators, ..
                } => Some((peer, validators)),
                _ => None,
            })
            .collect();
        assert_eq!(wants.len(), 2, "both holders asked");
        let total: usize = wants.iter().map(|(_, v)| v.len()).sum();
        assert_eq!(total, 6);
        assert!(
            wants.iter().all(|(_, v)| v.len() <= 4),
            "pull_batch respected"
        );
        // In flight: not asked again until answered or timed out.
        assert!(sync.tick(later, |_| vec![1, 2]).is_empty());
        sync.pull_done(0, &[0, 1]);
        let retried: usize = sync
            .tick(later, |_| vec![1, 2])
            .into_iter()
            .map(|a| match a {
                Action::Want { validators, .. } => validators.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(retried, 2);
    }

    #[test]
    fn coded_repair_fills_a_peer_without_coordination() {
        // Two senders hold everything; a receiver holds half. Each sender pushes
        // combinations of what the receiver lacks; together they decode it all.
        let t0 = Instant::now();
        let later = t0 + Duration::from_millis(200);
        let mut senders: Vec<SigSync<u8>> = (0..2)
            .map(|seed| SigSync::new(settings(SignatureSync::CodedRepair), [0], seed))
            .collect();
        let mut receiver: SigSync<u8> = SigSync::new(settings(SignatureSync::CodedRepair), [0], 9);
        for sender in &mut senders {
            for v in 0..16 {
                sender.deliver(0, v, 100 + v, t0);
            }
        }
        for v in 0..8 {
            receiver.deliver(0, v, 100 + v, t0);
        }
        let receiver_bitmap = bitmap(&(0..8).collect::<Vec<_>>());
        let mut decoded = Vec::new();
        let mut innovative = 0;
        for (k, sender) in senders.iter_mut().enumerate() {
            sender.on_have(42, 0, &receiver_bitmap, later);
            let mut s = settings(SignatureSync::CodedRepair);
            s.coded_redundancy = 0.5;
            s.coded_degree = 0;
            sender.settings = s;
            for action in sender.tick(later, |_| vec![42]) {
                if let Action::Coded { packet, .. } = action {
                    assert!(
                        packet.validators.iter().all(|&v| v >= 8),
                        "sender {k} codes only gaps"
                    );
                    let outcome = receiver.on_coded(0, &packet, later);
                    assert_eq!(outcome.mismatches, 0);
                    innovative += usize::from(outcome.innovative);
                    decoded.extend(outcome.decoded);
                }
            }
        }
        // Each sender sent ceil(0.5 * 8) = 4 packets of degree log2(8) + 2 = 6.
        assert_eq!(innovative, 8);
        assert_eq!(receiver.held_count(0), 16);
        assert!(decoded.iter().all(|h| h.origin == 100 + h.validator_id));
    }

    #[test]
    fn repair_budget_is_spent_until_a_new_bitmap_arrives() {
        let t0 = Instant::now();
        let later = t0 + Duration::from_millis(200);
        let mut sync: SigSync<u8> = SigSync::new(settings(SignatureSync::CodedRepair), [0], 1);
        for v in 0..16 {
            sync.deliver(0, v, 0, t0);
        }
        sync.on_have(7, 0, &bitmap(&[0, 1, 2, 3]), later);
        let coded = |actions: Vec<Action<u8>>| {
            actions
                .into_iter()
                .filter(|a| matches!(a, Action::Coded { .. }))
                .count()
        };
        // One mesh peer, redundancy 1: one packet per gap.
        assert_eq!(coded(sync.tick(later, |_| vec![7])), 12);
        assert_eq!(coded(sync.tick(later, |_| vec![7])), 0, "budget spent");
        sync.on_have(7, 0, &bitmap(&[0, 1, 2, 3, 4]), later);
        assert_eq!(coded(sync.tick(later, |_| vec![7])), 11, "re-armed by news");
        // Two mesh peers split the work: ceil(11 / 2) each, the silent one gets none.
        sync.on_have(7, 0, &bitmap(&[0, 1, 2, 3, 4, 5]), later);
        assert_eq!(coded(sync.tick(later, |_| vec![7, 8])), 5);
    }

    #[test]
    fn repair_skips_signatures_the_peer_had_no_time_to_get() {
        let t0 = Instant::now();
        let mut sync: SigSync<u8> = SigSync::new(settings(SignatureSync::CodedRepair), [0], 1);
        for v in 0..8 {
            sync.deliver(0, v, 0, t0);
        }
        let fresh = t0 + Duration::from_millis(150);
        for v in 8..16 {
            sync.deliver(0, v, 0, fresh);
        }
        // The peer's bitmap (holding nothing) arrives 200 ms after the first
        // eight: only those count as missing; gossip may still bring the rest.
        let seen = t0 + Duration::from_millis(200);
        sync.on_have(7, 0, &bitmap(&[]), seen);
        let coded: Vec<_> = sync
            .tick(seen, |_| vec![7])
            .into_iter()
            .filter_map(|a| match a {
                Action::Coded { packet, .. } => Some(packet),
                _ => None,
            })
            .collect();
        assert_eq!(coded.len(), 8);
        assert!(coded.iter().flat_map(|p| &p.validators).all(|&v| v < 8));
    }

    #[test]
    fn incomplete_hosts_repeat_their_bitmap_every_refresh() {
        let t0 = Instant::now();
        let mut sync: SigSync<u8> = SigSync::new(settings(SignatureSync::BitmapPull), [0], 0);
        sync.deliver(0, 1, 0, t0);
        let haves = |actions: Vec<Action<u8>>| {
            actions
                .iter()
                .filter(|a| matches!(a, Action::Have { .. }))
                .count()
        };
        assert_eq!(haves(sync.tick(t0, |_| vec![1])), 1);
        assert_eq!(
            haves(sync.tick(t0 + Duration::from_millis(500), |_| vec![1])),
            0
        );
        assert_eq!(
            haves(sync.tick(t0 + Duration::from_millis(1000), |_| vec![1])),
            1
        );
        // A complete host goes quiet.
        for v in 0..16 {
            sync.deliver(0, v, 0, t0);
        }
        assert_eq!(
            haves(sync.tick(t0 + Duration::from_millis(1100), |_| vec![1])),
            1
        );
        assert_eq!(
            haves(sync.tick(t0 + Duration::from_millis(5000), |_| vec![1])),
            0
        );
    }

    #[test]
    fn gossip_arrival_finishes_a_pending_equation() {
        let now = Instant::now();
        let mut sync: SigSync<u8> = SigSync::new(settings(SignatureSync::CodedRepair), [0], 0);
        let packet = CodedPacket {
            validators: vec![3, 4],
            coeffs: vec![1, 1],
            origins: vec![30, 40],
            symbol: symbol_of(3) ^ symbol_of(4),
            payload: vec![],
        };
        let outcome = sync.on_coded(0, &packet, now);
        assert!(outcome.innovative && outcome.decoded.is_empty());
        let held = sync.deliver(0, 3, 30, now);
        assert_eq!(
            held,
            vec![
                Held {
                    validator_id: 3,
                    origin: 30
                },
                Held {
                    validator_id: 4,
                    origin: 40
                },
            ]
        );
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn automatic_degree_grows_with_the_gaps() {
        assert_eq!(coded_degree(0, 1), 1);
        assert_eq!(coded_degree(0, 16), 7);
        assert_eq!(coded_degree(0, 64), 9);
        assert_eq!(coded_degree(0, 100_000), MAX_AUTO_DEGREE);
        assert_eq!(coded_degree(1, 64), 1, "explicit degree wins");
        assert_eq!(coded_degree(32, 20), 20, "never above the gaps");
    }

    /// Two uncoordinated senders, each in a mesh of two, split 1.1x the gaps
    /// between them; the receiver nearly always decodes everything.
    #[test]
    fn two_uncoordinated_senders_decode_nearly_everything() {
        let t0 = Instant::now();
        let later = t0 + Duration::from_millis(200);
        let settings = SyncSettings {
            mode: SignatureSync::CodedRepair,
            validators_per_subnet: 64,
            grace: Duration::ZERO,
            pull_batch: 4,
            pull_timeout: Duration::from_millis(500),
            coded_degree: 0,
            coded_redundancy: 1.1,
            coded_per_tick: 1000,
            refresh: Duration::from_secs(10),
            payload_bytes: 0,
        };
        let trials = 300;
        let (mut full, mut decoded) = (0, 0);
        for trial in 0..trials {
            let mut receiver: SigSync<u8> = SigSync::new(settings, [0], 1000 + trial);
            let mut bits = Bits::new(64);
            for v in 0..32 {
                receiver.deliver(0, v, 0, t0);
                bits.set(v as usize);
            }
            for k in 0..2 {
                let mut sender: SigSync<u8> = SigSync::new(settings, [0], trial * 2 + k);
                for v in 0..64 {
                    sender.deliver(0, v, 0, t0);
                }
                sender.on_have(1, 0, &bits.to_bytes(64), t0);
                // Peer 2 is the sender's other mesh peer.
                for action in sender.tick(later, |_| vec![1, 2]) {
                    if let Action::Coded { packet, .. } = action {
                        receiver.on_coded(0, &packet, later);
                    }
                }
            }
            let held = receiver.held_count(0);
            decoded += held - 32;
            full += usize::from(held == 64);
        }
        assert!(
            full * 100 >= trials as usize * 90,
            "full decodes {full}/{trials}"
        );
        assert!(
            decoded * 100 >= trials as usize * 32 * 99,
            "decoded {decoded}"
        );
    }
}
