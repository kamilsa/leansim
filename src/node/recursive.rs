//! Announce-and-pull for aggregation proofs, and the recursive aggregator duty.
//!
//! A pure state machine: the caller reports what happened (a proof finished, an
//! announcement or a pulled proof arrived, a pull failed) and executes the
//! returned [`Action`]s on the network. Times are passed in, so tests need no swarm.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use tokio::time::Instant;

use crate::config::plan::NodeDuties;
use crate::messages::proof::ProofId;

/// Network work the caller must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Tell host `to` that this host holds `proof`.
    Announce { to: u32, proof: ProofId },
    /// Pull `proof` from host `from`, which announced it.
    Fetch { from: u32, proof: ProofId },
}

/// A recursive proof whose simulated compute finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursiveProof {
    pub proof: ProofId,
    /// Child proofs it aggregates.
    pub inputs: usize,
    pub is_final: bool,
}

/// Pull state of one wanted child proof.
#[derive(Debug, Default)]
struct Pull {
    /// Announcers not pulled from yet, in announcement order.
    waiting: VecDeque<u32>,
    /// Announcers already queued or pulled from, so each is asked once.
    seen: HashSet<u32>,
    in_flight: usize,
}

pub struct ProofExchange {
    duties: NodeDuties,
    proofs_per_child: usize,
    proof_time: Duration,
    /// Child proof → the seat whose group aggregates it.
    seat_of_child: HashMap<ProofId, usize>,
    held: HashSet<ProofId>,
    pulls: HashMap<ProofId, Pull>,
    /// (proof, host) pairs where the host already knows this host holds, or
    /// itself holds, the proof: never announce those.
    announced: HashSet<(ProofId, u32)>,
    /// Seats whose recursive proof was started.
    started: HashSet<usize>,
    /// Recursive proofs computing: (due, seat).
    pending: Vec<(Instant, usize)>,
}

impl ProofExchange {
    pub fn new(duties: NodeDuties, proofs_per_child: usize, proof_time: Duration) -> Self {
        let mut seat_of_child = HashMap::new();
        for (seat, duty) in duties.seats.iter().enumerate() {
            for &child in &duty.children {
                seat_of_child.insert(
                    ProofId {
                        layer: duty.layer - 1,
                        index: child,
                    },
                    seat,
                );
            }
        }
        Self {
            duties,
            proofs_per_child: proofs_per_child.max(1),
            proof_time,
            seat_of_child,
            held: HashSet::new(),
            pulls: HashMap::new(),
            announced: HashSet::new(),
            started: HashSet::new(),
            pending: Vec::new(),
        }
    }

    pub fn holds(&self, proof: ProofId) -> bool {
        self.held.contains(&proof)
    }

    /// This host finished `proof`: one of its subnet proofs or one of its seats'
    /// recursive proofs. Announces it to the next group, and counts it if this
    /// host also sits in that group.
    pub fn proof_ready(&mut self, proof: ProofId, now: Instant) -> Vec<Action> {
        let targets: Vec<u32> = if proof.layer == 0 {
            self.duties
                .subnets
                .iter()
                .filter(|duty| duty.subnet == proof.index)
                .flat_map(|duty| duty.announce_to.iter().copied())
                .collect()
        } else {
            self.duties
                .seats
                .iter()
                .filter(|seat| (seat.layer, seat.index) == (proof.layer, proof.index))
                .flat_map(|seat| seat.announce_to.iter().copied())
                .collect()
        };
        self.hold(proof, targets, now)
    }

    /// Host `from` announced `proof`. Pulls it when one of this host's groups
    /// aggregates it, it is not held yet, and fewer than `proofs_per_child` pulls
    /// of it are running.
    pub fn announcement(&mut self, proof: ProofId, from: u32) -> Vec<Action> {
        // The announcer holds the proof: never announce it back.
        self.announced.insert((proof, from));
        if !self.seat_of_child.contains_key(&proof) || self.held.contains(&proof) {
            return Vec::new();
        }
        let pull = self.pulls.entry(proof).or_default();
        if pull.seen.insert(from) {
            pull.waiting.push_back(from);
        }
        self.pump(proof)
    }

    /// A pulled proof arrived. A proof already held (an extra accepted copy)
    /// changes nothing.
    pub fn fetched(&mut self, proof: ProofId, now: Instant) -> Vec<Action> {
        self.finish_pull(proof);
        self.hold(proof, Vec::new(), now)
    }

    /// A pull failed (timeout, closed connection, or the host lacked the
    /// proof): pull from the next announcer.
    pub fn fetch_failed(&mut self, proof: ProofId) -> Vec<Action> {
        self.finish_pull(proof);
        self.pump(proof)
    }

    fn finish_pull(&mut self, proof: ProofId) {
        if let Some(pull) = self.pulls.get_mut(&proof) {
            pull.in_flight = pull.in_flight.saturating_sub(1);
        }
    }

    fn pump(&mut self, proof: ProofId) -> Vec<Action> {
        let limit = self.proofs_per_child;
        let mut actions = Vec::new();
        if self.held.contains(&proof) {
            return actions;
        }
        if let Some(pull) = self.pulls.get_mut(&proof) {
            while pull.in_flight < limit {
                let Some(from) = pull.waiting.pop_front() else {
                    break;
                };
                pull.in_flight += 1;
                actions.push(Action::Fetch { from, proof });
            }
        }
        actions
    }

    /// Records `proof` as held and announces it to `targets` plus, when one of
    /// this host's groups aggregates it, that group's other members, and starts
    /// the group's recursive proof once every child is held.
    fn hold(&mut self, proof: ProofId, mut targets: Vec<u32>, now: Instant) -> Vec<Action> {
        if !self.held.insert(proof) {
            return Vec::new();
        }
        let seat = self.seat_of_child.get(&proof).copied();
        if let Some(seat) = seat {
            targets.extend(self.duties.seats[seat].siblings.iter().copied());
        }
        let mut actions = Vec::new();
        for to in targets {
            if self.announced.insert((proof, to)) {
                actions.push(Action::Announce { to, proof });
            }
        }
        if let Some(seat) = seat {
            self.try_start(seat, now);
        }
        actions
    }

    pub fn next_due(&self) -> Option<Instant> {
        self.pending.iter().map(|(due, _)| *due).min()
    }

    /// Recursive proofs whose compute finished by `now`, earliest first.
    pub fn take_due(&mut self, now: Instant) -> Vec<RecursiveProof> {
        let (mut due, waiting): (Vec<_>, Vec<_>) =
            self.pending.drain(..).partition(|(at, _)| *at <= now);
        self.pending = waiting;
        due.sort_by_key(|&(at, seat)| {
            (
                at,
                self.duties.seats[seat].layer,
                self.duties.seats[seat].index,
            )
        });
        due.into_iter()
            .map(|(_, seat)| {
                let duty = &self.duties.seats[seat];
                RecursiveProof {
                    proof: ProofId {
                        layer: duty.layer,
                        index: duty.index,
                    },
                    inputs: duty.children.len(),
                    is_final: duty.is_final,
                }
            })
            .collect()
    }

    /// Starts the seat's recursive proof, once, when every child is held.
    fn try_start(&mut self, seat: usize, now: Instant) {
        let duty = &self.duties.seats[seat];
        let ready = duty.children.iter().all(|&child| {
            self.held.contains(&ProofId {
                layer: duty.layer - 1,
                index: child,
            })
        });
        if ready && self.started.insert(seat) {
            self.pending.push((now + self.proof_time, seat));
        }
    }
}
