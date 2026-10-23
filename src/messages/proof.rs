//! Announce-and-pull messages for aggregation proofs (request-response, not gossip).

use serde::{Deserialize, Serialize};

/// A proof's place in the aggregation tree. Layer 0 holds the subnet proofs
/// (`index` = subnet); layer `l > 0` holds the recursive proofs of that layer's
/// groups (`index` = group).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofId {
    pub layer: u32,
    pub index: u32,
}

impl ProofId {
    pub fn subnet(subnet: u32) -> Self {
        Self {
            layer: 0,
            index: subnet,
        }
    }
}

/// Requests on the proof protocol. `from` is the sender's node id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofRequest {
    /// The sender holds `proof`; the receiver may pull it.
    Announce { proof: ProofId, from: u32 },
    /// Pull `proof` from a host that announced it.
    Fetch { proof: ProofId, from: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofResponse {
    /// Reply to an announcement.
    Ack,
    /// The pulled proof; `payload` stands in for its bytes (`aggregate_proof_bytes`).
    Proof {
        proof: ProofId,
        from: u32,
        payload: Vec<u8>,
    },
    /// The receiver does not hold the requested proof.
    Missing,
}
