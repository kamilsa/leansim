//! EIP-8334 bundled signature propagation (the gossipsub partial messages
//! version): which signatures go to which peer, and when.
//!
//! A pure state machine like [`crate::node::sigsync::SigSync`]: the caller reports
//! signatures and parts metadata as they arrive, calls [`BundleSync::tick`] every
//! `bundle_tick_ms` and [`BundleSync::advertise`] when gossipsub picks gossip
//! peers, and sends what they return.
//!
//! - Every tick, a host pushes each push target (mesh or fanout peer) every
//!   signature it holds that the peer is not known to hold, oldest first, in
//!   bundles of at most `max_per_bundle`. A peer is known to hold a signature it
//!   sent us, one we sent it, and one it advertised. A signature a peer delivers
//!   while still waiting for the tick is never sent back to it: that is where
//!   bundling saves duplicates over gossipsub's forward-on-receipt. A peer that
//!   was not a target at the subnet's previous tick gets the signatures held then
//!   as backlog, in bundles of their own: gossipsub would never send them, since
//!   it forwards only new messages to a new mesh peer.
//! - With a `stagger`, the two ends of a link take turns: for each signature a
//!   hash of the signature and the two peers names the end that pushes first.
//!   The other end pushes only once it has held the signature for `stagger`
//!   without the peer delivering or advertising it. Each copy then crosses a
//!   link once, unless the first end is slower than the stagger. A host's own
//!   signatures always go out at once. The EIP has no stagger.
//! - With `announce` on top of a stagger, the end that waits tells the peer at
//!   once that it holds the signature (parts metadata `available`, which the EIP
//!   keeps for gossip peers). A peer that hears this before it holds the
//!   signature never pushes it back, and when it gets the signature elsewhere it
//!   announces in turn, which cancels the waiting end's push: the link then
//!   carries no copy at all. A peer that still lacks the signature requests it
//!   like any advertised one.
//! - At gossip time a host advertises to each gossip peer the signatures it holds
//!   that the peer is not known to hold and that it has not advertised to it.
//! - On an advertisement a host requests what it lacks, unless it already asked
//!   someone for it less than `request_timeout` ago, and answers requests with
//!   what it holds; requests it cannot answer are dropped. With a
//!   `request_delay`, it waits that long first and requests only what has not
//!   arrived meanwhile (the EIP requests at once).

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::time::Duration;

use tokio::time::Instant;

use crate::config::experiment::ExperimentConfig;
use crate::node::sigsync::{Bits, Held, UNKNOWN_ORIGIN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleSettings {
    pub validators_per_subnet: usize,
    pub max_per_bundle: usize,
    pub request_timeout: Duration,
    /// Wait this long after an advertisement before requesting; zero requests at once.
    pub request_delay: Duration,
    /// How long the end of a link that does not push a signature first waits for
    /// the other end's copy before pushing it; zero pushes from both ends at once.
    pub stagger: Duration,
    /// With a stagger: the end that waits announces the signature to the peer at
    /// once, and a peer announces back what it holds and was announced.
    pub announce: bool,
    /// The end of a link that does not push a signature first never pushes it:
    /// the hash that orders a stagger's turns picks who may send instead.
    pub sender_only: bool,
    /// With `sender_only`: most targets a signature is pushed to, the ones the
    /// hash ranks first; 0 = every target this host is the sender for.
    pub push_cap: usize,
}

impl BundleSettings {
    /// Without bundling (waggle with `waggle_bundled = false`) every signature
    /// goes in a bundle of its own, with no stagger. With waggle's hashed push
    /// selection the hash picks the sender of each signature on each link, so
    /// there is no stagger either, and announcements need none.
    pub fn from_config(config: &ExperimentConfig) -> Self {
        let bundled = config.bundled();
        let hashed = config.waggle_hashed();
        let stagger = if bundled && !hashed {
            config.bundle_stagger_ms
        } else {
            0
        };
        Self {
            validators_per_subnet: config.validators_per_subnet(),
            max_per_bundle: config.max_signatures_per_bundle(),
            request_timeout: Duration::from_millis(config.bundle_request_timeout_ms),
            request_delay: Duration::from_millis(config.bundle_request_delay_ms),
            stagger: Duration::from_millis(stagger),
            announce: config.bundle_announce && (bundled || hashed),
            sender_only: hashed,
            push_cap: if hashed { config.waggle_push_peers } else { 0 },
        }
    }
}

/// Signatures to push to one peer in one bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push<P> {
    pub peer: P,
    pub subnet: u32,
    pub signatures: Vec<Held>,
    /// Signatures held at the previous tick, when the peer was not a target.
    pub backlog: bool,
}

/// Validators to advertise to one gossip peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert<P> {
    pub peer: P,
    pub subnet: u32,
    pub available: Vec<u32>,
}

/// Validators to request from one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<P> {
    pub peer: P,
    pub subnet: u32,
    pub validators: Vec<u32>,
}

/// What to do about a peer's parts metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataReply {
    /// Validators to request from the peer.
    pub requests: Vec<u32>,
    /// Requested signatures to send the peer, in bundles of at most `max_per_bundle`.
    pub serve: Vec<Vec<Held>>,
}

/// How a signature arrival changed what this host holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// Held for the first time.
    New,
    /// Already held.
    Duplicate,
}

/// What this host knows about one peer in one subnet.
#[derive(Debug, Clone)]
struct PeerView {
    /// Signatures the peer holds: it sent them, we sent them, or it advertised them.
    has: Bits,
    /// Signatures advertised to the peer.
    advertised: Bits,
    /// Signatures the peer knows this host holds: it sent them, we sent them, or
    /// we advertised or announced them.
    knows: Bits,
    /// Signatures this host pushes first on its link with the peer, by
    /// [`pushes_first`]; worked out when a tick first needs them.
    first: Option<Bits>,
    /// Signatures not pushed to the peer because `push_cap` other targets ranked
    /// before it.
    capped: Bits,
}

impl PeerView {
    fn new(size: usize) -> Self {
        Self {
            has: Bits::new(size),
            advertised: Bits::new(size),
            knows: Bits::new(size),
            first: None,
            capped: Bits::new(size),
        }
    }

    /// Whether this host, `local`, pushes column `col` first on its link with `peer`.
    fn pushes_first<P: Hash + Ord>(
        &mut self,
        local: &P,
        peer: &P,
        base: u32,
        size: usize,
        col: u32,
    ) -> bool {
        self.first
            .get_or_insert_with(|| {
                let mut first = Bits::new(size);
                for col in 0..size {
                    if pushes_first(local, peer, base + col as u32) {
                        first.set(col);
                    }
                }
                first
            })
            .get(col as usize)
    }
}

struct SubnetState<P> {
    /// Validator id of column 0.
    base: u32,
    size: usize,
    held: Bits,
    /// When each column was first held.
    held_at: Vec<Option<Instant>>,
    /// Columns signed on this host.
    own: Bits,
    origin: Vec<u32>,
    /// Held columns in the order they arrived; pushes go oldest first.
    order: Vec<u32>,
    /// Columns requested from a gossip peer, and when.
    requested: HashMap<u32, Instant>,
    /// Columns advertised and lacking, waiting out the request delay: the first
    /// advertiser, and when the request is due.
    pending: HashMap<u32, (P, Instant)>,
    peers: HashMap<P, PeerView>,
    /// Held signatures and targets at the previous tick.
    last_tick: Option<(usize, BTreeSet<P>)>,
    /// How many of `order`'s signatures have had their `push_cap` targets picked.
    capped_upto: usize,
}

impl<P: Copy + Eq + Hash + Ord> SubnetState<P> {
    fn new(base: u32, size: usize) -> Self {
        Self {
            base,
            size,
            held: Bits::new(size),
            held_at: vec![None; size],
            own: Bits::new(size),
            origin: vec![UNKNOWN_ORIGIN; size],
            order: Vec::new(),
            requested: HashMap::new(),
            pending: HashMap::new(),
            peers: HashMap::new(),
            last_tick: None,
            capped_upto: 0,
        }
    }

    /// Picks the targets of every signature held since the last call: of the
    /// `peers` this host is the sender for that are not known to hold it, the
    /// `cap` the hash ranks first. The others are marked as capped.
    fn cap_new_signatures(&mut self, local: &P, peers: &[P], cap: usize) {
        let (base, size) = (self.base, self.size);
        for i in self.capped_upto..self.order.len() {
            let col = self.order[i];
            let own = self.own.get(col as usize);
            let mut eligible: Vec<(u64, P)> = Vec::new();
            for &peer in peers {
                let view = self
                    .peers
                    .entry(peer)
                    .or_insert_with(|| PeerView::new(size));
                if !view.has.get(col as usize)
                    && (own || view.pushes_first(local, &peer, base, size, col))
                {
                    eligible.push((pair_hash(local, &peer, base + col), peer));
                }
            }
            if eligible.len() <= cap {
                continue;
            }
            eligible.sort_unstable();
            for (_, peer) in eligible.drain(cap..) {
                if let Some(view) = self.peers.get_mut(&peer) {
                    view.capped.set(col as usize);
                }
            }
        }
        self.capped_upto = self.order.len();
    }

    fn column(&self, validator_id: u64) -> Option<u32> {
        let col = validator_id.checked_sub(u64::from(self.base))?;
        (col < self.size as u64).then_some(col as u32)
    }

    fn view(&mut self, peer: P) -> &mut PeerView {
        let size = self.size;
        self.peers
            .entry(peer)
            .or_insert_with(|| PeerView::new(size))
    }

    fn held_record(&self, col: u32) -> Held {
        Held {
            validator_id: self.base + col,
            origin: self.origin[col as usize],
        }
    }
}

/// Counters the state machine keeps; the caller counts the bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BundleCounters {
    /// Signatures a peer delivered that this host held but had not yet sent it:
    /// pushes the tick saved.
    pub pushes_avoided: u64,
    /// Advertised signatures not requested because a request for them was in flight.
    pub requests_suppressed: u64,
    /// Signatures pushed as backlog to peers that became targets since the previous tick.
    pub backlog_pushes: u64,
    /// Advertised signatures that arrived during the request delay, so were not requested.
    pub requests_avoided: u64,
    /// Signatures pushed by the end of a link that waits: the stagger ran out
    /// before the other end's copy came.
    pub lazy_pushes: u64,
    /// Signatures announced to push targets instead of, or ahead of, a push.
    pub announced: u64,
    /// Requested signatures not served because they were already on their way.
    pub requests_already_sent: u64,
}

pub struct BundleSync<P> {
    settings: BundleSettings,
    /// This host, to tell which end of a link pushes a signature first.
    local: Option<P>,
    /// When the earliest staggered push still waiting is due, as of the last tick.
    next_lazy_due: Option<Instant>,
    /// Announcements the last tick decided on, until the caller takes them.
    announcements: Vec<Advert<P>>,
    subnets: BTreeMap<u32, SubnetState<P>>,
    /// Delayed requests by due time: (due, subnet, column).
    pending_due: BTreeSet<(Instant, u32, u32)>,
    pub counters: BundleCounters,
}

impl<P: Copy + Eq + Hash + Ord> BundleSync<P> {
    /// Tracks `subnets`; the k-th subnet's validators are `k * validators_per_subnet ..`.
    pub fn new(settings: BundleSettings, subnets: impl IntoIterator<Item = u32>) -> Self {
        let size = settings.validators_per_subnet;
        Self {
            settings,
            local: None,
            next_lazy_due: None,
            announcements: Vec::new(),
            subnets: subnets
                .into_iter()
                .map(|subnet| (subnet, SubnetState::new(subnet * size as u32, size)))
                .collect(),
            pending_due: BTreeSet::new(),
            counters: BundleCounters::default(),
        }
    }

    /// Names this host among its peers; the stagger needs it and is off without it.
    pub fn with_local(mut self, local: P) -> Self {
        self.local = Some(local);
        self
    }

    /// The announcements the last tick decided on: signatures to tell push targets
    /// this host holds.
    pub fn take_announcements(&mut self) -> Vec<Advert<P>> {
        std::mem::take(&mut self.announcements)
    }

    /// When the earliest staggered push still waiting was due at the last tick.
    pub fn next_lazy_due(&self) -> Option<Instant> {
        self.next_lazy_due
    }

    pub fn tracks(&self, subnet: u32) -> bool {
        self.subnets.contains_key(&subnet)
    }

    pub fn holds(&self, subnet: u32, validator_id: u32) -> bool {
        self.subnets.get(&subnet).is_some_and(|state| {
            state
                .column(u64::from(validator_id))
                .is_some_and(|col| state.held.get(col as usize))
        })
    }

    pub fn held_count(&self, subnet: u32) -> usize {
        self.subnets
            .get(&subnet)
            .map_or(0, |state| state.order.len())
    }

    /// Drops everything known about `peer`, whose last connection closed: it may
    /// come back as a restarted host holding nothing. Its delayed requests are
    /// dropped too, and it counts as a new push target when it returns.
    pub fn forget_peer(&mut self, peer: P) {
        for (&subnet, state) in &mut self.subnets {
            state.peers.remove(&peer);
            if let Some((_, targets)) = &mut state.last_tick {
                targets.remove(&peer);
            }
            let pending_due = &mut self.pending_due;
            state.pending.retain(|&col, &mut (advertiser, due)| {
                let keep = advertiser != peer;
                if !keep {
                    pending_due.remove(&(due, subnet, col));
                }
                keep
            });
        }
    }

    /// Whether `targets`, the subnet's push targets now, include a peer that was
    /// not one at the previous tick, with signatures held to push it.
    pub fn has_new_targets(&self, subnet: u32, targets: &[P]) -> bool {
        self.subnets.get(&subnet).is_some_and(|state| {
            !state.order.is_empty()
                && match &state.last_tick {
                    Some((_, previous)) => targets.iter().any(|peer| !previous.contains(peer)),
                    None => !targets.is_empty(),
                }
        })
    }

    /// A signature was signed here (`from` = None) or arrived from `from`. None
    /// when the subnet is not tracked or the validator is not in it.
    pub fn deliver(
        &mut self,
        subnet: u32,
        validator_id: u64,
        origin: u32,
        from: Option<P>,
        now: Instant,
    ) -> Option<Arrival> {
        let state = self.subnets.get_mut(&subnet)?;
        let col = state.column(validator_id)?;
        let i = col as usize;
        let held = state.held.get(i);
        if let Some(peer) = from {
            let view = state.view(peer);
            if held && !view.has.get(i) {
                self.counters.pushes_avoided += 1;
            }
            view.has.set(i);
            view.knows.set(i);
        }
        if held {
            return Some(Arrival::Duplicate);
        }
        state.held.set(i);
        state.held_at[i] = Some(now);
        if from.is_none() {
            state.own.set(i);
        }
        state.origin[i] = origin;
        state.order.push(col);
        state.requested.remove(&col);
        if let Some((_, due)) = state.pending.remove(&col) {
            self.pending_due.remove(&(due, subnet, col));
            self.counters.requests_avoided += 1;
        }
        Some(Arrival::New)
    }

    /// This tick's bundles. `targets` names each subnet's push targets.
    pub fn tick(&mut self, now: Instant, mut targets: impl FnMut(u32) -> Vec<P>) -> Vec<Push<P>> {
        let max = self.settings.max_per_bundle;
        let stagger = self.settings.stagger;
        let sender_only = self.settings.sender_only;
        let cap = self.settings.push_cap;
        let local = self.local.filter(|_| sender_only || !stagger.is_zero());
        let announce = self.settings.announce && local.is_some();
        let mut next_lazy_due: Option<Instant> = None;
        let mut pushes = Vec::new();
        for (&subnet, state) in &mut self.subnets {
            if state.order.is_empty() {
                continue;
            }
            let mut peers = targets(subnet);
            peers.sort_unstable();
            peers.dedup();
            if let Some(local) = local.filter(|_| sender_only && cap > 0) {
                state.cap_new_signatures(&local, &peers, cap);
            }
            let (base, size) = (state.base, state.size);
            for &peer in &peers {
                // Signatures held at the previous tick are backlog for a peer that
                // was not a target then.
                let backlog_len = match &state.last_tick {
                    Some((held, previous)) if !previous.contains(&peer) => *held,
                    _ => 0,
                };
                let view = state
                    .peers
                    .entry(peer)
                    .or_insert_with(|| PeerView::new(size));
                let (mut backlog, mut fresh) = (Vec::new(), Vec::new());
                let mut announced = Vec::new();
                for (i, &col) in state.order.iter().enumerate() {
                    if view.has.get(col as usize) {
                        // The peer announced it and may be waiting to push it here.
                        if announce && !view.knows.get(col as usize) {
                            view.knows.set(col as usize);
                            announced.push(state.base + col);
                        }
                        continue;
                    }
                    // The end of the link that does not push this signature first
                    // gives the other end `stagger` to deliver it, or with
                    // `sender_only` leaves it to the other end for good.
                    let waits = local.is_some_and(|local| {
                        !state.own.get(col as usize)
                            && !view.pushes_first(&local, &peer, base, size, col)
                    });
                    if waits {
                        let due = (!sender_only)
                            .then(|| state.held_at[col as usize].map_or(now, |at| at + stagger));
                        if due.is_none_or(|due| due > now) {
                            if announce && !view.knows.get(col as usize) {
                                view.knows.set(col as usize);
                                announced.push(state.base + col);
                            }
                            if let Some(due) = due {
                                next_lazy_due =
                                    Some(next_lazy_due.map_or(due, |next| next.min(due)));
                            }
                            continue;
                        }
                        self.counters.lazy_pushes += 1;
                    }
                    if view.capped.get(col as usize) {
                        continue;
                    }
                    view.has.set(col as usize);
                    view.knows.set(col as usize);
                    if i < backlog_len {
                        backlog.push(col);
                    } else {
                        fresh.push(col);
                    }
                }
                self.counters.backlog_pushes += backlog.len() as u64;
                if !announced.is_empty() {
                    self.counters.announced += announced.len() as u64;
                    self.announcements.push(Advert {
                        peer,
                        subnet,
                        available: announced,
                    });
                }
                for (cols, is_backlog) in [(backlog, true), (fresh, false)] {
                    for chunk in cols.chunks(max) {
                        pushes.push(Push {
                            peer,
                            subnet,
                            signatures: chunk.iter().map(|&col| state.held_record(col)).collect(),
                            backlog: is_backlog,
                        });
                    }
                }
            }
            state.last_tick = Some((state.order.len(), peers.into_iter().collect()));
        }
        self.next_lazy_due = next_lazy_due;
        pushes
    }

    /// What to advertise to `peers`, gossip peers of `subnet`: held signatures each
    /// is not known to hold and has not been told about.
    pub fn advertise(&mut self, subnet: u32, peers: &[P]) -> Vec<Advert<P>> {
        let Some(state) = self.subnets.get_mut(&subnet) else {
            return Vec::new();
        };
        let mut adverts = Vec::new();
        for &peer in peers {
            let order = state.order.clone();
            let base = state.base;
            let view = state.view(peer);
            let available: Vec<u32> = order
                .into_iter()
                .filter(|&col| !view.has.get(col as usize) && !view.advertised.get(col as usize))
                .collect();
            for &col in &available {
                view.advertised.set(col as usize);
                view.knows.set(col as usize);
            }
            if !available.is_empty() {
                adverts.push(Advert {
                    peer,
                    subnet,
                    available: available.into_iter().map(|col| base + col).collect(),
                });
            }
        }
        adverts
    }

    /// A peer's parts metadata arrived: request what it has and this host lacks,
    /// and serve what it requests.
    pub fn on_metadata(
        &mut self,
        peer: P,
        subnet: u32,
        available: &[u64],
        requests: &[u64],
        now: Instant,
    ) -> MetadataReply {
        let timeout = self.settings.request_timeout;
        let delay = self.settings.request_delay;
        let max = self.settings.max_per_bundle;
        let Some(state) = self.subnets.get_mut(&subnet) else {
            return MetadataReply::default();
        };
        let mut reply = MetadataReply::default();
        for &validator_id in available {
            let Some(col) = state.column(validator_id) else {
                continue;
            };
            state.view(peer).has.set(col as usize);
            if state.held.get(col as usize) {
                continue;
            }
            let in_flight = state
                .requested
                .get(&col)
                .is_some_and(|at| now.saturating_duration_since(*at) < timeout);
            if in_flight || state.pending.contains_key(&col) {
                self.counters.requests_suppressed += 1;
                continue;
            }
            if !delay.is_zero() {
                let due = now + delay;
                state.pending.insert(col, (peer, due));
                self.pending_due.insert((due, subnet, col));
                continue;
            }
            state.requested.insert(col, now);
            reply.requests.push(state.base + col);
        }
        let mut serve = Vec::new();
        for &validator_id in requests {
            let Some(col) = state.column(validator_id) else {
                continue;
            };
            if !state.held.get(col as usize) {
                continue;
            }
            // Already pushed and on its way: the peer asked before it arrived.
            let view = state.view(peer);
            if view.has.get(col as usize) {
                self.counters.requests_already_sent += 1;
                continue;
            }
            view.has.set(col as usize);
            view.knows.set(col as usize);
            serve.push(state.held_record(col));
        }
        reply.serve = serve.chunks(max).map(<[Held]>::to_vec).collect();
        reply
    }
}

impl<P: Copy + Eq + Hash + Ord> BundleSync<P> {
    /// A bundle for `peer` was not sent (its send queue was full, say): the peer
    /// does not hold these signatures after all, so a tick pushes them again and
    /// a gossip round advertises them again.
    pub fn unsent_signatures(
        &mut self,
        peer: P,
        subnet: u32,
        validators: impl IntoIterator<Item = u32>,
    ) {
        let Some(state) = self.subnets.get_mut(&subnet) else {
            return;
        };
        for validator_id in validators {
            if let Some(col) = state.column(u64::from(validator_id)) {
                let view = state.view(peer);
                view.has.unset(col as usize);
                view.advertised.unset(col as usize);
            }
        }
    }

    /// An advertisement or announcement for `peer` was not sent: the peer was
    /// not told this host holds these signatures.
    pub fn unsent_available(&mut self, peer: P, subnet: u32, validators: &[u64]) {
        let Some(state) = self.subnets.get_mut(&subnet) else {
            return;
        };
        for &validator_id in validators {
            if let Some(col) = state.column(validator_id) {
                let view = state.view(peer);
                view.advertised.unset(col as usize);
                view.knows.unset(col as usize);
            }
        }
    }

    /// A request was not sent: these signatures can be requested from the next
    /// peer that advertises them.
    pub fn unsent_requests(&mut self, subnet: u32, validators: &[u64]) {
        let Some(state) = self.subnets.get_mut(&subnet) else {
            return;
        };
        for &validator_id in validators {
            if let Some(col) = state.column(validator_id) {
                state.requested.remove(&col);
            }
        }
    }

    /// When the next delayed request is due.
    pub fn next_request_due(&self) -> Option<Instant> {
        self.pending_due.first().map(|&(due, _, _)| due)
    }

    /// Delayed requests due by `now`, for what is still missing, one per peer and subnet.
    pub fn due_requests(&mut self, now: Instant) -> Vec<Request<P>> {
        let timeout = self.settings.request_timeout;
        let mut batches: BTreeMap<(u32, P), Vec<u32>> = BTreeMap::new();
        while let Some(&(due, subnet, col)) = self.pending_due.first() {
            if due > now {
                break;
            }
            self.pending_due.pop_first();
            let Some(state) = self.subnets.get_mut(&subnet) else {
                continue;
            };
            let Some((peer, _)) = state.pending.remove(&col) else {
                continue;
            };
            let in_flight = state
                .requested
                .get(&col)
                .is_some_and(|at| now.saturating_duration_since(*at) < timeout);
            if state.held.get(col as usize) || in_flight {
                continue;
            }
            state.requested.insert(col, now);
            batches
                .entry((subnet, peer))
                .or_default()
                .push(state.base + col);
        }
        batches
            .into_iter()
            .map(|((subnet, peer), validators)| Request {
                peer,
                subnet,
                validators,
            })
            .collect()
    }
}

/// Whether `local` is the end of its link with `peer` that pushes `validator_id`'s
/// signature first. Both ends compute the same hash, so exactly one of them does.
pub fn pushes_first<P: Hash + Ord>(local: &P, peer: &P, validator_id: u32) -> bool {
    let local_is_low = local <= peer;
    let low_first = pair_hash(local, peer, validator_id) & 1 == 0;
    low_first == local_is_low
}

/// A hash of `validator_id`'s signature and the two ends of a link, the same
/// whichever end computes it.
fn pair_hash<P: Hash + Ord>(local: &P, peer: &P, validator_id: u32) -> u64 {
    let (low, high) = if local <= peer {
        (local, peer)
    } else {
        (peer, local)
    };
    let mut hasher = DefaultHasher::new();
    validator_id.hash(&mut hasher);
    low.hash(&mut hasher);
    high.hash(&mut hasher);
    hasher.finish()
}

/// The first tick at or after `now` of a clock ticking every `tick` from `anchor`.
/// A host only wakes for ticks with signatures to push, but they fall where a
/// free-running clock's would.
pub fn next_tick(anchor: Instant, tick: Duration, now: Instant) -> Instant {
    if now <= anchor || tick.is_zero() {
        return anchor.max(now);
    }
    let elapsed = now.duration_since(anchor).as_nanos();
    let step = tick.as_nanos();
    let ticks = elapsed.div_ceil(step);
    anchor + Duration::from_nanos((ticks * step) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_fall_on_the_anchored_clock() {
        let anchor = Instant::now();
        let tick = Duration::from_millis(20);
        let ms = |n| anchor + Duration::from_millis(n);
        assert_eq!(next_tick(anchor, tick, ms(0)), ms(0));
        assert_eq!(next_tick(anchor, tick, ms(1)), ms(20));
        assert_eq!(next_tick(anchor, tick, ms(20)), ms(20));
        assert_eq!(next_tick(anchor, tick, ms(45)), ms(60));
        assert_eq!(next_tick(ms(5), tick, anchor), ms(5), "before the anchor");
        assert_eq!(next_tick(anchor, Duration::ZERO, ms(7)), ms(7));
    }

    fn settings() -> BundleSettings {
        BundleSettings {
            validators_per_subnet: 16,
            max_per_bundle: 3,
            request_timeout: Duration::from_millis(500),
            request_delay: Duration::ZERO,
            stagger: Duration::ZERO,
            announce: false,
            sender_only: false,
            push_cap: 0,
        }
    }

    /// A validator of subnet 0 whose signature `first` pushes first on its link with `waiting`.
    fn validator_pushed_first_by(first: u8, waiting: u8) -> u32 {
        (0..16)
            .find(|&v| pushes_first(&first, &waiting, v))
            .expect("some validator goes each way")
    }

    fn announcing(request_delay: Duration) -> BundleSettings {
        BundleSettings {
            stagger: Duration::from_millis(400),
            announce: true,
            request_delay,
            max_per_bundle: 50,
            ..settings()
        }
    }

    #[test]
    fn an_announced_signature_got_elsewhere_never_crosses_the_link() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        // Host 5 waits, host 9 pushes first.
        let v = validator_pushed_first_by(9, 5);
        let mut waiting: BundleSync<u8> =
            BundleSync::new(announcing(Duration::from_millis(100)), [0]).with_local(5);
        let mut first: BundleSync<u8> =
            BundleSync::new(announcing(Duration::from_millis(100)), [0]).with_local(9);

        // The waiting end gets the signature from peer 1 and announces it to 9 at once.
        waiting.deliver(0, u64::from(v), 0, Some(1), t0);
        assert!(waiting.tick(t0, |_| vec![9]).is_empty());
        assert_eq!(
            waiting.take_announcements(),
            vec![Advert {
                peer: 9,
                subnet: 0,
                available: vec![v]
            }]
        );
        assert!(waiting.take_announcements().is_empty(), "taken once");

        // The first end hears it, waits out its request delay, and meanwhile gets
        // the signature from peer 2: no request, no push back, one announcement.
        let reply = first.on_metadata(5, 0, &[u64::from(v)], &[], ms(40));
        assert!(reply.requests.is_empty() && reply.serve.is_empty());
        first.deliver(0, u64::from(v), 0, Some(2), ms(60));
        assert_eq!(first.counters.requests_avoided, 1);
        assert!(first.tick(ms(60), |_| vec![5]).is_empty());
        assert_eq!(
            first.take_announcements(),
            vec![Advert {
                peer: 5,
                subnet: 0,
                available: vec![v]
            }]
        );
        assert!(first.due_requests(ms(200)).is_empty());

        // That cancels the waiting end's push; nobody has more to say.
        let reply = waiting.on_metadata(9, 0, &[u64::from(v)], &[], ms(100));
        assert!(reply.requests.is_empty());
        assert!(waiting.tick(ms(400), |_| vec![9]).is_empty());
        assert!(waiting.take_announcements().is_empty());
        assert!(first.tick(ms(400), |_| vec![5]).is_empty());
        assert!(first.take_announcements().is_empty());
        assert_eq!(waiting.counters.lazy_pushes, 0);
        assert_eq!(
            (waiting.counters.announced, first.counters.announced),
            (1, 1)
        );
    }

    #[test]
    fn a_peer_lacking_an_announced_signature_requests_it_and_is_served_once() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let v = validator_pushed_first_by(9, 5);
        let mut waiting: BundleSync<u8> =
            BundleSync::new(announcing(Duration::ZERO), [0]).with_local(5);
        let mut first: BundleSync<u8> =
            BundleSync::new(announcing(Duration::ZERO), [0]).with_local(9);
        waiting.deliver(0, u64::from(v), 7, Some(1), t0);
        waiting.tick(t0, |_| vec![9]);
        waiting.take_announcements();

        let reply = first.on_metadata(5, 0, &[u64::from(v)], &[], ms(40));
        assert_eq!(reply.requests, vec![v]);
        let reply = waiting.on_metadata(9, 0, &[], &[u64::from(v)], ms(80));
        assert_eq!(reply.serve.len(), 1);
        // Served: the stagger has nothing left to push, and a repeat request gets nothing.
        assert!(waiting.tick(ms(400), |_| vec![9]).is_empty());
        let again = waiting.on_metadata(9, 0, &[], &[u64::from(v)], ms(420));
        assert!(again.serve.is_empty());
        assert_eq!(waiting.counters.requests_already_sent, 1);
    }

    #[test]
    fn the_end_that_pushes_first_does_not_announce() {
        let t0 = Instant::now();
        let v = validator_pushed_first_by(5, 9);
        let mut sync: BundleSync<u8> =
            BundleSync::new(announcing(Duration::ZERO), [0]).with_local(5);
        sync.deliver(0, u64::from(v), 0, Some(1), t0);
        assert_eq!(validators(&sync.tick(t0, |_| vec![9]), 9), vec![v]);
        assert!(sync.take_announcements().is_empty());

        // Without `announce`, a waiting end stays silent.
        let w = validator_pushed_first_by(9, 5);
        let quiet = BundleSettings {
            announce: false,
            ..announcing(Duration::ZERO)
        };
        let mut sync: BundleSync<u8> = BundleSync::new(quiet, [0]).with_local(5);
        sync.deliver(0, u64::from(w), 0, Some(1), t0);
        assert!(sync.tick(t0, |_| vec![9]).is_empty());
        assert!(sync.take_announcements().is_empty());
    }

    #[test]
    fn exactly_one_end_of_a_link_pushes_a_signature_first() {
        let mut low_first = 0;
        for validator in 0..200 {
            assert_ne!(
                pushes_first(&3u8, &9u8, validator),
                pushes_first(&9u8, &3u8, validator)
            );
            low_first += usize::from(pushes_first(&3u8, &9u8, validator));
        }
        assert!(
            (60..140).contains(&low_first),
            "both ends take turns: {low_first}"
        );
    }

    #[test]
    fn the_end_that_waits_pushes_only_after_the_stagger() {
        let t0 = Instant::now();
        let stagger = Duration::from_millis(100);
        let staggered = BundleSettings {
            stagger,
            max_per_bundle: 50,
            ..settings()
        };
        let mut sync: BundleSync<u8> = BundleSync::new(staggered, [0]).with_local(5);
        // Peer 1 delivers validators 0..16; peer 9 is the other target.
        for v in 0..16 {
            sync.deliver(0, v, 0, Some(1), t0);
        }
        let first: Vec<u32> = (0..16).filter(|&v| pushes_first(&5u8, &9u8, v)).collect();
        let waiting: Vec<u32> = (0..16).filter(|&v| !pushes_first(&5u8, &9u8, v)).collect();
        assert!(!first.is_empty() && !waiting.is_empty());

        let pushes = sync.tick(t0, |_| vec![1, 9]);
        assert_eq!(
            validators(&pushes, 9),
            first,
            "only where this end goes first"
        );
        assert!(validators(&pushes, 1).is_empty(), "peer 1 sent them all");
        assert_eq!(sync.next_lazy_due(), Some(t0 + stagger));

        // Peer 9 delivers one of the waiting ones meanwhile: never pushed to it.
        let saved = waiting[0];
        sync.deliver(
            0,
            u64::from(saved),
            0,
            Some(9),
            t0 + Duration::from_millis(50),
        );
        assert_eq!(sync.counters.pushes_avoided, 1);
        assert!(sync
            .tick(t0 + Duration::from_millis(99), |_| vec![1, 9])
            .is_empty());

        let pushes = sync.tick(t0 + stagger, |_| vec![1, 9]);
        assert_eq!(validators(&pushes, 9), waiting[1..].to_vec());
        assert_eq!(sync.counters.lazy_pushes, waiting.len() as u64 - 1);
        assert_eq!(sync.next_lazy_due(), None);
    }

    fn sender_only(push_cap: usize) -> BundleSettings {
        BundleSettings {
            sender_only: true,
            push_cap,
            max_per_bundle: 50,
            ..settings()
        }
    }

    #[test]
    fn with_sender_only_exactly_one_end_of_a_link_ever_pushes_a_signature() {
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(60);
        let mut five: BundleSync<u8> = BundleSync::new(sender_only(0), [0]).with_local(5);
        let mut nine: BundleSync<u8> = BundleSync::new(sender_only(0), [0]).with_local(9);
        // Both ends get validators 0..16 from peers of their own.
        for v in 0..16 {
            five.deliver(0, v, 0, Some(1), t0);
            nine.deliver(0, v, 0, Some(2), t0);
        }
        let from_five = validators(&five.tick(t0, |_| vec![1, 9]), 9);
        let from_nine = validators(&nine.tick(t0, |_| vec![2, 5]), 5);
        let expected: Vec<u32> = (0..16).filter(|&v| pushes_first(&5u8, &9u8, v)).collect();
        assert_eq!(from_five, expected);
        assert!(!from_five.is_empty() && !from_nine.is_empty());
        let mut all: Vec<u32> = from_five.iter().chain(&from_nine).copied().collect();
        all.sort_unstable();
        assert_eq!(all, (0..16).collect::<Vec<u32>>(), "each crosses once");

        // The end the hash does not pick never pushes, however long it waits.
        assert!(five.tick(later, |_| vec![1, 9]).is_empty());
        assert_eq!(five.next_lazy_due(), None);
        assert_eq!(five.counters.lazy_pushes, 0);
        // A host is the sender of its own signatures on every link.
        let mut own: BundleSync<u8> = BundleSync::new(sender_only(0), [0]).with_local(5);
        for v in 0..16 {
            own.deliver(0, v, 0, None, t0);
        }
        assert_eq!(validators(&own.tick(t0, |_| vec![9]), 9).len(), 16);
    }

    #[test]
    fn a_push_cap_keeps_the_targets_the_hash_ranks_first() {
        let t0 = Instant::now();
        let peers: Vec<u8> = (10..30).collect();
        let mut sync: BundleSync<u8> = BundleSync::new(sender_only(3), [0]).with_local(5);
        // An own signature could go to all twenty peers: it goes to three.
        sync.deliver(0, 0, 0, None, t0);
        // A received one goes to at most three of the peers this host sends it to.
        sync.deliver(0, 1, 0, Some(1), t0);
        let pushes = sync.tick(t0, |_| peers.clone());
        let targets = |pushes: &[Push<u8>], v: u32| -> Vec<u8> {
            pushes
                .iter()
                .filter(|p| p.signatures.iter().any(|h| h.validator_id == v))
                .map(|p| p.peer)
                .collect()
        };
        assert_eq!(targets(&pushes, 0).len(), 3);
        let received = targets(&pushes, 1);
        assert_eq!(received.len(), 3);
        assert!(received.iter().all(|peer| pushes_first(&5u8, peer, 1)));
        assert!(
            peers
                .iter()
                .filter(|peer| pushes_first(&5u8, peer, 1))
                .count()
                > 3,
            "the cap bound"
        );
        // The pick holds: later ticks push the capped peers nothing.
        assert!(sync.tick(t0, |_| peers.clone()).is_empty());

        // A peer known to hold a signature takes none of its three places.
        let mut sync: BundleSync<u8> = BundleSync::new(sender_only(3), [0]).with_local(5);
        sync.deliver(0, 0, 0, None, t0);
        sync.on_metadata(10, 0, &[0], &[], t0);
        sync.on_metadata(11, 0, &[0], &[], t0);
        let pushes = sync.tick(t0, |_| vec![10, 11, 12, 13, 14]);
        assert_eq!(targets(&pushes, 0), vec![12, 13, 14]);

        // A peer that turns up later was capped out of nothing: it gets what this
        // host sends it, as backlog.
        let mut sync: BundleSync<u8> = BundleSync::new(sender_only(1), [0]).with_local(5);
        sync.deliver(0, 0, 0, None, t0);
        assert_eq!(sync.tick(t0, |_| vec![10, 11]).len(), 1);
        let pushes = sync.tick(t0, |_| vec![10, 11, 12]);
        assert_eq!(targets(&pushes, 0), vec![12]);
        assert!(pushes[0].backlog);
    }

    #[test]
    fn with_sender_only_the_other_end_can_announce_instead() {
        let t0 = Instant::now();
        let v = validator_pushed_first_by(9, 5);
        let announcing = BundleSettings {
            announce: true,
            ..sender_only(0)
        };
        let mut sync: BundleSync<u8> = BundleSync::new(announcing, [0]).with_local(5);
        sync.deliver(0, u64::from(v), 0, Some(1), t0);
        assert!(sync.tick(t0, |_| vec![9]).is_empty());
        assert_eq!(
            sync.take_announcements(),
            vec![Advert {
                peer: 9,
                subnet: 0,
                available: vec![v]
            }]
        );
        // Told once; a peer that lacks it requests it and is served.
        sync.tick(t0, |_| vec![9]);
        assert!(sync.take_announcements().is_empty());
        let reply = sync.on_metadata(9, 0, &[], &[u64::from(v)], t0);
        assert_eq!(reply.serve.len(), 1);
    }

    #[test]
    fn own_signatures_are_never_staggered() {
        let t0 = Instant::now();
        let staggered = BundleSettings {
            stagger: Duration::from_millis(100),
            max_per_bundle: 50,
            ..settings()
        };
        let mut sync: BundleSync<u8> = BundleSync::new(staggered, [0]).with_local(5);
        for v in 0..16 {
            sync.deliver(0, v, 0, None, t0);
        }
        let pushes = sync.tick(t0, |_| vec![1, 9]);
        assert_eq!(validators(&pushes, 1).len(), 16);
        assert_eq!(validators(&pushes, 9).len(), 16);
        assert_eq!(sync.next_lazy_due(), None);
        assert_eq!(sync.counters.lazy_pushes, 0);

        // Without a name for this host, or a stagger, both ends push at once.
        let mut unnamed: BundleSync<u8> = BundleSync::new(staggered, [0]);
        for v in 0..16 {
            unnamed.deliver(0, v, 0, Some(1), t0);
        }
        assert_eq!(validators(&unnamed.tick(t0, |_| vec![9]), 9).len(), 16);
    }

    #[test]
    fn delayed_requests_skip_what_arrives_meanwhile() {
        let t0 = Instant::now();
        let delay = Duration::from_millis(100);
        let mut sync: BundleSync<u8> = BundleSync::new(
            BundleSettings {
                request_delay: delay,
                ..settings()
            },
            [0],
        );
        let reply = sync.on_metadata(7, 0, &[1, 2, 3], &[], t0);
        assert!(reply.requests.is_empty(), "nothing requested at once");
        // A second advertiser of the same signatures waits behind the first.
        sync.on_metadata(8, 0, &[2, 3, 4], &[], t0 + Duration::from_millis(10));
        assert_eq!(sync.counters.requests_suppressed, 2);
        assert_eq!(sync.next_request_due(), Some(t0 + delay));
        assert!(sync.due_requests(t0 + Duration::from_millis(99)).is_empty());

        // Signature 2 is pushed during the delay: not requested.
        sync.deliver(0, 2, 0, Some(9), Instant::now());
        assert_eq!(sync.counters.requests_avoided, 1);
        let due = sync.due_requests(t0 + Duration::from_millis(110));
        assert_eq!(
            due,
            vec![
                Request {
                    peer: 7,
                    subnet: 0,
                    validators: vec![1, 3]
                },
                Request {
                    peer: 8,
                    subnet: 0,
                    validators: vec![4]
                },
            ]
        );
        assert_eq!(sync.next_request_due(), None);
        // Now in flight: a new advertisement waits out the timeout, not the delay.
        sync.on_metadata(9, 0, &[1], &[], t0 + Duration::from_millis(120));
        assert_eq!(sync.next_request_due(), None);
    }

    fn validators(pushes: &[Push<u8>], peer: u8) -> Vec<u32> {
        pushes
            .iter()
            .filter(|p| p.peer == peer)
            .flat_map(|p| p.signatures.iter().map(|h| h.validator_id))
            .collect()
    }

    #[test]
    fn arrivals_are_new_once_and_untracked_ones_ignored() {
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [1]);
        // Subnet 1 holds validators 16..32.
        assert_eq!(
            sync.deliver(1, 17, 5, Some(9), Instant::now()),
            Some(Arrival::New)
        );
        assert_eq!(
            sync.deliver(1, 17, 5, Some(8), Instant::now()),
            Some(Arrival::Duplicate)
        );
        assert_eq!(
            sync.deliver(1, 3, 5, None, Instant::now()),
            None,
            "validator of another subnet"
        );
        assert_eq!(
            sync.deliver(0, 3, 5, None, Instant::now()),
            None,
            "untracked subnet"
        );
        assert!(sync.holds(1, 17));
        assert_eq!(sync.held_count(1), 1);
    }

    #[test]
    fn a_tick_pushes_each_target_what_it_lacks_in_bounded_bundles() {
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        for v in 0..5 {
            sync.deliver(0, v, 100 + v as u32, None, Instant::now());
        }
        // Peer 1 sent us validator 2, so it never gets it back.
        sync.deliver(0, 2, 102, Some(1), Instant::now());
        let pushes = sync.tick(Instant::now(), |_| vec![1, 2]);
        assert_eq!(validators(&pushes, 1), vec![0, 1, 3, 4]);
        assert_eq!(validators(&pushes, 2), vec![0, 1, 2, 3, 4]);
        assert!(pushes.iter().all(|p| p.signatures.len() <= 3));
        assert_eq!(pushes.iter().filter(|p| p.peer == 2).count(), 2);
        assert!(pushes
            .iter()
            .flat_map(|p| &p.signatures)
            .all(|h| h.origin == 100 + h.validator_id));
        assert!(
            sync.tick(Instant::now(), |_| vec![1, 2]).is_empty(),
            "nothing is sent twice"
        );
    }

    #[test]
    fn a_signature_delivered_before_the_tick_is_not_sent_back() {
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        sync.deliver(0, 4, 0, Some(1), Instant::now());
        // Before the tick, peer 2 sends it too: the push to peer 2 is avoided.
        assert_eq!(
            sync.deliver(0, 4, 0, Some(2), Instant::now()),
            Some(Arrival::Duplicate)
        );
        assert_eq!(sync.counters.pushes_avoided, 1);
        assert!(sync.tick(Instant::now(), |_| vec![1, 2]).is_empty());
        // A peer that sends what we already pushed it avoids nothing.
        sync.deliver(0, 5, 0, None, Instant::now());
        sync.tick(Instant::now(), |_| vec![3]);
        sync.deliver(0, 5, 0, Some(3), Instant::now());
        assert_eq!(sync.counters.pushes_avoided, 1);
    }

    #[test]
    fn a_new_target_gets_the_backlog_in_bundles_of_its_own() {
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        sync.deliver(0, 1, 0, None, Instant::now());
        sync.tick(Instant::now(), |_| vec![1]);
        sync.deliver(0, 2, 0, None, Instant::now());
        let pushes = sync.tick(Instant::now(), |_| vec![1, 2]);
        assert_eq!(validators(&pushes, 1), vec![2]);
        assert_eq!(validators(&pushes, 2), vec![1, 2]);
        let backlog: Vec<u32> = pushes
            .iter()
            .filter(|p| p.backlog)
            .flat_map(|p| p.signatures.iter().map(|h| h.validator_id))
            .collect();
        assert_eq!(
            backlog,
            vec![1],
            "held at the previous tick, before peer 2 was a target"
        );
        assert!(pushes
            .iter()
            .all(|p| p.backlog == (p.peer == 2 && p.signatures[0].validator_id == 1)));
        assert_eq!(sync.counters.backlog_pushes, 1);

        // A peer that drops out and returns is new again; the first tick has no backlog.
        sync.deliver(0, 3, 0, None, Instant::now());
        sync.tick(Instant::now(), |_| vec![1]);
        sync.deliver(0, 4, 0, None, Instant::now());
        let pushes = sync.tick(Instant::now(), |_| vec![1, 2]);
        assert_eq!(validators(&pushes, 2), vec![3, 4]);
        assert_eq!(sync.counters.backlog_pushes, 2);
        let mut fresh: BundleSync<u8> = BundleSync::new(settings(), [0]);
        fresh.deliver(0, 1, 0, None, Instant::now());
        assert!(fresh
            .tick(Instant::now(), |_| vec![1])
            .iter()
            .all(|p| !p.backlog));
    }

    #[test]
    fn a_forgotten_peer_is_pushed_everything_again() {
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        sync.deliver(0, 1, 0, None, Instant::now());
        sync.deliver(0, 2, 0, Some(7), Instant::now());
        sync.tick(Instant::now(), |_| vec![7]);
        assert!(
            !sync.has_new_targets(0, &[7]),
            "a target of the previous tick"
        );
        assert!(sync.tick(Instant::now(), |_| vec![7]).is_empty());

        // Peer 7 crashed and is back holding nothing: all of it is backlog.
        sync.forget_peer(7);
        assert!(sync.has_new_targets(0, &[7]));
        let pushes = sync.tick(Instant::now(), |_| vec![7]);
        assert_eq!(validators(&pushes, 7), vec![1, 2]);
        assert!(pushes.iter().all(|push| push.backlog));
        assert!(!sync.has_new_targets(0, &[7]));

        // It is advertised everything again as a gossip peer too.
        sync.forget_peer(7);
        assert_eq!(sync.advertise(0, &[7])[0].available, vec![1, 2]);

        let empty: BundleSync<u8> = BundleSync::new(settings(), [0]);
        assert!(!empty.has_new_targets(0, &[7]), "nothing held to push");
        assert!(!sync.has_new_targets(1, &[7]), "untracked subnet");
    }

    #[test]
    fn a_forgotten_peer_is_not_sent_its_delayed_requests() {
        let t0 = Instant::now();
        let delayed = BundleSettings {
            request_delay: Duration::from_millis(100),
            ..settings()
        };
        let mut sync: BundleSync<u8> = BundleSync::new(delayed, [0]);
        sync.on_metadata(7, 0, &[1, 2], &[], t0);
        sync.on_metadata(8, 0, &[3], &[], t0);
        sync.forget_peer(7);
        let requests = sync.due_requests(t0 + Duration::from_millis(100));
        assert_eq!(
            requests,
            vec![Request {
                peer: 8,
                subnet: 0,
                validators: vec![3]
            }]
        );
        assert_eq!(sync.next_request_due(), None);
        // What peer 7 advertised can be requested from the next advertiser.
        let reply = sync.on_metadata(8, 0, &[1], &[], t0 + Duration::from_millis(100));
        assert!(reply.requests.is_empty(), "waits out the request delay");
        assert!(sync.next_request_due().is_some());
    }

    #[test]
    fn unsent_signatures_are_pushed_and_advertised_again() {
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        for v in 0..4 {
            sync.deliver(0, v, 0, None, Instant::now());
        }
        let pushes = sync.tick(Instant::now(), |_| vec![7]);
        assert_eq!(validators(&pushes, 7), vec![0, 1, 2, 3]);
        // The second bundle (validator 3) found the peer's queue full.
        sync.unsent_signatures(7, 0, [3]);
        let pushes = sync.tick(Instant::now(), |_| vec![7]);
        assert_eq!(validators(&pushes, 7), vec![3]);
        assert!(pushes.iter().all(|push| !push.backlog));
        assert!(sync.tick(Instant::now(), |_| vec![7]).is_empty());

        // A served request that was not sent is advertised again.
        assert_eq!(sync.advertise(0, &[8])[0].available, vec![0, 1, 2, 3]);
        let reply = sync.on_metadata(8, 0, &[], &[1, 2], Instant::now());
        assert_eq!(reply.serve.len(), 1);
        sync.unsent_signatures(8, 0, [1, 2]);
        assert_eq!(sync.advertise(0, &[8])[0].available, vec![1, 2]);
        sync.unsent_signatures(8, 9, [1]);
        sync.unsent_signatures(8, 0, [99]);
    }

    #[test]
    fn unsent_metadata_is_sent_again() {
        let t0 = Instant::now();
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        sync.deliver(0, 1, 0, None, t0);
        assert_eq!(sync.advertise(0, &[8])[0].available, vec![1]);
        sync.unsent_available(8, 0, &[1]);
        assert_eq!(sync.advertise(0, &[8])[0].available, vec![1]);
        assert!(sync.advertise(0, &[8]).is_empty());

        // An unsent request is not in flight: the next advertiser is asked.
        assert_eq!(
            sync.on_metadata(7, 0, &[2, 3], &[], t0).requests,
            vec![2, 3]
        );
        sync.unsent_requests(0, &[3]);
        let reply = sync.on_metadata(9, 0, &[2, 3], &[], t0);
        assert_eq!(reply.requests, vec![3]);
        assert_eq!(sync.counters.requests_suppressed, 1);

        // An unsent announcement is announced at the next tick.
        let v = validator_pushed_first_by(9, 5);
        let mut waiting: BundleSync<u8> =
            BundleSync::new(announcing(Duration::ZERO), [0]).with_local(5);
        waiting.deliver(0, u64::from(v), 0, Some(1), t0);
        waiting.tick(t0, |_| vec![9]);
        assert_eq!(waiting.take_announcements().len(), 1);
        waiting.unsent_available(9, 0, &[u64::from(v)]);
        waiting.tick(t0, |_| vec![9]);
        assert_eq!(waiting.take_announcements()[0].available, vec![v]);
    }

    #[test]
    fn adverts_carry_only_news_for_each_peer() {
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        sync.deliver(0, 1, 0, None, Instant::now());
        sync.deliver(0, 2, 0, Some(7), Instant::now());
        let adverts = sync.advertise(0, &[7, 8]);
        assert_eq!(
            adverts,
            vec![
                Advert {
                    peer: 7,
                    subnet: 0,
                    available: vec![1]
                },
                Advert {
                    peer: 8,
                    subnet: 0,
                    available: vec![1, 2]
                },
            ]
        );
        assert!(sync.advertise(0, &[7, 8]).is_empty());
        sync.deliver(0, 3, 0, None, Instant::now());
        assert_eq!(sync.advertise(0, &[8])[0].available, vec![3]);
        assert!(sync.advertise(1, &[8]).is_empty(), "untracked subnet");
    }

    #[test]
    fn metadata_requests_what_is_missing_once_per_timeout() {
        let t0 = Instant::now();
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        sync.deliver(0, 1, 0, None, Instant::now());
        let reply = sync.on_metadata(7, 0, &[1, 2, 3, 99], &[], t0);
        assert_eq!(
            reply.requests,
            vec![2, 3],
            "held and out-of-range ones skipped"
        );
        // Another advertiser of the same signatures is not asked while in flight.
        let reply = sync.on_metadata(8, 0, &[2, 3], &[], t0 + Duration::from_millis(100));
        assert!(reply.requests.is_empty());
        assert_eq!(sync.counters.requests_suppressed, 2);
        // Signature 2 arrives; 3 times out and may be asked of someone else.
        sync.deliver(0, 2, 0, Some(7), Instant::now());
        let reply = sync.on_metadata(8, 0, &[2, 3], &[], t0 + Duration::from_millis(500));
        assert_eq!(reply.requests, vec![3]);
        // An advertiser is known to hold what it advertised: no push to it.
        sync.deliver(0, 3, 0, Some(7), Instant::now());
        assert!(validators(&sync.tick(Instant::now(), |_| vec![8]), 8)
            .iter()
            .all(|&v| v == 1));
    }

    #[test]
    fn requests_are_served_from_what_is_held_in_bounded_bundles() {
        let t0 = Instant::now();
        let mut sync: BundleSync<u8> = BundleSync::new(settings(), [0]);
        for v in 0..5 {
            sync.deliver(0, v, 0, None, Instant::now());
        }
        let reply = sync.on_metadata(7, 0, &[], &[0, 1, 2, 3, 4, 9], t0);
        assert!(reply.requests.is_empty());
        let served: Vec<Vec<u32>> = reply
            .serve
            .iter()
            .map(|b| b.iter().map(|h| h.validator_id).collect())
            .collect();
        assert_eq!(served, vec![vec![0, 1, 2], vec![3, 4]], "9 is not held");
        assert!(
            sync.tick(Instant::now(), |_| vec![7]).is_empty(),
            "served ones are not pushed"
        );
    }
}
