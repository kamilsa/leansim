//! Per-host traffic logs: bytes and messages by direction, message kind, and peer.
//!
//! Only hosts with `traffic_log = true` use a meter; elsewhere the node never
//! builds one. Buckets hold the traffic of `bucket_ms` of simulated time and carry
//! totals by kind; per-peer totals accumulate over the whole run.

use std::collections::BTreeMap;

/// What a byte belongs to, as the dashboard breaks it down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Signature gossip, incoming or forwarded.
    Signature,
    /// A signature the host had already seen.
    DuplicateSignature,
    /// A proof announcement (request-response request).
    ProofAnnounce,
    /// A request to pull a proof.
    ProofRequest,
    /// A proof's bytes, served or fetched.
    ProofPayload,
    /// Acks and "missing" answers to a pull.
    ProofControl,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Signature => "signature",
            Kind::DuplicateSignature => "duplicate_signature",
            Kind::ProofAnnounce => "proof_announce",
            Kind::ProofRequest => "proof_request",
            Kind::ProofPayload => "proof_payload",
            Kind::ProofControl => "proof_control",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

/// One bucket's traffic, by kind.
#[derive(Debug, Clone, Default)]
pub struct Bucket {
    pub start_ms: u64,
    pub width_ms: u64,
    pub inbound: BTreeMap<Kind, u64>,
    pub outbound: BTreeMap<Kind, u64>,
}

/// One peer's traffic over the whole run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerTotals {
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
    pub inbound_msgs: u64,
    pub outbound_msgs: u64,
}

pub struct TrafficMeter {
    bucket_ms: u64,
    current: Option<Bucket>,
    done: Vec<Bucket>,
    peers: BTreeMap<String, PeerTotals>,
}

impl TrafficMeter {
    pub fn new(bucket_ms: u64) -> Self {
        Self {
            bucket_ms: bucket_ms.max(1),
            current: None,
            done: Vec::new(),
            peers: BTreeMap::new(),
        }
    }

    /// Adds one message of `bytes` in `direction`, attributed to `peer`
    /// (`node:<id>` when the peer's node is known, else `peer:<base58 id>`).
    /// Empty buckets are never created: a jump in time just closes the open one.
    pub fn record(&mut self, ts_ms: u64, direction: Direction, kind: Kind, bytes: u64, peer: &str) {
        if let Some(finished) = self.roll(ts_ms) {
            self.done.push(finished);
        }
        let bucket_ms = self.bucket_ms;
        let bucket = self.current.get_or_insert_with(|| Bucket {
            start_ms: ts_ms / bucket_ms * bucket_ms,
            width_ms: bucket_ms,
            ..Bucket::default()
        });
        let kinds = match direction {
            Direction::In => &mut bucket.inbound,
            Direction::Out => &mut bucket.outbound,
        };
        *kinds.entry(kind).or_default() += bytes;

        let totals = self.peers.entry(peer.to_string()).or_default();
        match direction {
            Direction::In => {
                totals.inbound_bytes += bytes;
                totals.inbound_msgs += 1;
            }
            Direction::Out => {
                totals.outbound_bytes += bytes;
                totals.outbound_msgs += 1;
            }
        }
    }

    /// Buckets that ended at or before `ts_ms`, oldest first.
    pub fn drain_due(&mut self, ts_ms: u64) -> Vec<Bucket> {
        let mut out = std::mem::take(&mut self.done);
        if let Some(finished) = self.roll(ts_ms) {
            out.push(finished);
        }
        out
    }

    /// Every bucket still held, including the open one.
    pub fn finish(&mut self) -> Vec<Bucket> {
        let mut out = std::mem::take(&mut self.done);
        out.extend(self.current.take());
        out
    }

    pub fn peers(&self) -> &BTreeMap<String, PeerTotals> {
        &self.peers
    }

    fn roll(&mut self, ts_ms: u64) -> Option<Bucket> {
        let finished = self
            .current
            .as_ref()
            .is_some_and(|bucket| ts_ms >= bucket.start_ms + bucket.width_ms);
        if finished {
            self.current.take()
        } else {
            None
        }
    }
}
