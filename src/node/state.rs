use std::collections::{BTreeSet, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use dashmap::DashMap;

use crate::config::experiment::{ExperimentConfig, NodeRole};
use crate::messages::wire::MessageId;

/// A local proof whose simulated aggregation compute is still running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingProof {
    pub due: tokio::time::Instant,
    pub subnet: u32,
    pub sig_count: usize,
}

/// Shared node state used across the event loop and role runtimes.
pub struct NodeState {
    pub node_id: u32,
    pub role: NodeRole,
    pub subnet_id: u32,
    /// Validators run by this host; each publishes one signature.
    pub validator_ids: Vec<u32>,
    /// Explicit subnet subscriptions (gossip membership); empty means "the signing subnets".
    pub explicit_subscribed_subnets: Vec<u32>,
    /// Subnets (committees) this host aggregates; empty unless a local aggregator.
    pub aggregated_subnets: BTreeSet<u32>,
    /// Local aggregator: subnet → unique validator ids whose signatures arrived.
    pub sigs_by_subnet: DashMap<u32, HashSet<u32>>,
    /// Local aggregator: subnets whose local proof is already scheduled or done.
    pub proofs_claimed: DashMap<u32, ()>,
    /// Local aggregator: proofs whose simulated compute has not finished yet.
    pub pending_proofs: Mutex<Vec<PendingProof>>,
    pub start: Instant,
    pub config: ExperimentConfig,

    /// Deduplication: message id → first-seen instant.
    pub seen_messages: DashMap<MessageId, Instant>,

    /// Whether this validator has already sent its signature.
    pub sig_sent: AtomicBool,

    /// Per-node message sequence counter.
    pub seq_counter: AtomicU64,

    /// Per-node bandwidth counters for signature messages (including duplicates).
    pub bytes_sent_sig: AtomicU64,
    pub bytes_recv_sig: AtomicU64,
    pub msgs_sent_sig: AtomicU64,
    pub msgs_recv_sig: AtomicU64,
}

impl NodeState {
    pub fn new(node_id: u32, role: NodeRole, subnet_id: u32, config: ExperimentConfig) -> Self {
        Self {
            node_id,
            role,
            subnet_id,
            validator_ids: match role {
                NodeRole::Relay => Vec::new(),
                _ => vec![node_id],
            },
            explicit_subscribed_subnets: Vec::new(),
            aggregated_subnets: if role == NodeRole::LocalAggregator {
                BTreeSet::from([subnet_id])
            } else {
                BTreeSet::new()
            },
            sigs_by_subnet: DashMap::new(),
            proofs_claimed: DashMap::new(),
            pending_proofs: Mutex::new(Vec::new()),
            start: Instant::now(),
            config,
            seen_messages: DashMap::new(),
            sig_sent: AtomicBool::new(false),
            seq_counter: AtomicU64::new(0),
            bytes_sent_sig: AtomicU64::new(0),
            bytes_recv_sig: AtomicU64::new(0),
            msgs_sent_sig: AtomicU64::new(0),
            msgs_recv_sig: AtomicU64::new(0),
        }
    }

    pub fn with_validator_ids(mut self, validator_ids: Vec<u32>) -> Self {
        self.validator_ids = validator_ids;
        self
    }

    pub fn with_subscribed_subnets(mut self, subnets: Vec<u32>) -> Self {
        self.explicit_subscribed_subnets = subnets;
        self
    }

    pub fn with_aggregated_subnets(mut self, subnets: Vec<u32>) -> Self {
        self.aggregated_subnets = subnets.into_iter().collect();
        self
    }

    pub fn aggregates(&self, subnet: u32) -> bool {
        self.aggregated_subnets.contains(&subnet)
    }

    /// Records a signature for a subnet and returns how many unique validators
    /// of that subnet this host now holds.
    pub fn record_sig(&self, subnet: u32, validator_id: u32) -> usize {
        let mut validators = self.sigs_by_subnet.entry(subnet).or_default();
        validators.insert(validator_id);
        validators.len()
    }

    /// Claims the subnet's local proof; true only the first time per subnet.
    pub fn claim_proof(&self, subnet: u32) -> bool {
        self.proofs_claimed.insert(subnet, ()).is_none()
    }

    pub fn schedule_proof(&self, proof: PendingProof) {
        self.pending_proofs.lock().unwrap().push(proof);
    }

    /// When the earliest pending proof finishes computing, if any.
    pub fn next_proof_due(&self) -> Option<tokio::time::Instant> {
        self.pending_proofs
            .lock()
            .unwrap()
            .iter()
            .map(|proof| proof.due)
            .min()
    }

    /// Removes and returns proofs due by `now`, earliest first (subnet breaks ties).
    pub fn take_due_proofs(&self, now: tokio::time::Instant) -> Vec<PendingProof> {
        let mut pending = self.pending_proofs.lock().unwrap();
        let (mut due, waiting): (Vec<_>, Vec<_>) =
            pending.drain(..).partition(|proof| proof.due <= now);
        *pending = waiting;
        due.sort_by_key(|proof| (proof.due, proof.subnet));
        due
    }

    /// Subnets this host signs in, one per distinct validator subnet.
    pub fn signing_subnets(&self) -> BTreeSet<u32> {
        self.validator_ids
            .iter()
            .map(|&validator_id| self.config.subnet_for_validator(validator_id))
            .collect()
    }

    /// Subnets this host subscribes to for gossip. Falls back to the signing
    /// subnets when the config does not override them (legacy node configs).
    pub fn subscribed_subnets(&self) -> BTreeSet<u32> {
        if self.explicit_subscribed_subnets.is_empty() {
            self.signing_subnets()
        } else {
            self.explicit_subscribed_subnets.iter().copied().collect()
        }
    }

    pub fn next_seq(&self) -> u64 {
        self.seq_counter.fetch_add(1, Ordering::SeqCst)
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Returns true if this message id has already been seen (duplicate).
    pub fn is_duplicate(&self, id: &MessageId) -> bool {
        self.seen_messages.contains_key(id)
    }

    /// Marks a message id as seen. Returns true if it was already present.
    pub fn mark_seen(&self, id: MessageId) -> bool {
        self.seen_messages.insert(id, Instant::now()).is_some()
    }

    pub fn validators_per_subnet(&self) -> usize {
        self.config.validators_per_subnet()
    }
}
