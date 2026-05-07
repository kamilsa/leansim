use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;

use crate::config::experiment::{ExperimentConfig, NodeRole};
use crate::messages::wire::MessageId;

/// Shared node state used across the event loop and role runtimes.
pub struct NodeState {
    pub node_id: u32,
    pub role: NodeRole,
    pub subnet_id: u32,
    pub start: Instant,
    pub config: ExperimentConfig,

    /// Deduplication: message id → first-seen instant.
    pub seen_messages: DashMap<MessageId, Instant>,

    /// Whether this validator has already sent its signature.
    pub sig_sent: AtomicBool,

    /// Local aggregator: set of unique validator ids whose signatures have been received.
    pub received_sigs: DashMap<u32, ()>,

    /// Whether this local aggregator has already published its local proof.
    pub snark1_sent: AtomicBool,

    /// Global aggregator: (sender_id, subnet_id) → covered validator count from that proof.
    pub received_proofs: DashMap<(u32, u32), usize>,

    /// Whether this global aggregator has already completed.
    pub snark2_completed: AtomicBool,

    /// Per-node message sequence counter.
    pub seq_counter: AtomicU64,
}

impl NodeState {
    pub fn new(node_id: u32, role: NodeRole, subnet_id: u32, config: ExperimentConfig) -> Self {
        Self {
            node_id,
            role,
            subnet_id,
            start: Instant::now(),
            config,
            seen_messages: DashMap::new(),
            sig_sent: AtomicBool::new(false),
            received_sigs: DashMap::new(),
            snark1_sent: AtomicBool::new(false),
            received_proofs: DashMap::new(),
            snark2_completed: AtomicBool::new(false),
            seq_counter: AtomicU64::new(0),
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

    pub fn total_validators(&self) -> usize {
        self.config.validator_count
    }
}
