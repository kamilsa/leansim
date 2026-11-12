//! Per-hop signature sync between gossipsub mesh neighbours (request-response,
//! not gossip): bitmaps of held signatures, pulls of missing ones, and sparse
//! coded repair packets. Every message goes to one mesh peer and is never
//! forwarded as is; nothing here needs to know which peer is an aggregator.

use serde::{Deserialize, Serialize};

/// A sparse linear combination over GF(2^8) of a few signatures of one subnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodedPacket {
    /// Validators whose signatures are combined.
    pub validators: Vec<u32>,
    /// One non-zero coefficient per validator.
    pub coeffs: Vec<u8>,
    /// Publishing host of each signature: simulator bookkeeping for the logs,
    /// not counted in [`SyncRequest::wire_bytes`].
    pub origins: Vec<u32>,
    /// The combination of the signatures' one-byte stand-in symbols, so a
    /// receiver can check what it decodes.
    pub symbol: u8,
    /// Stands in for the combined signature bytes (`signature_payload_bytes`).
    pub payload: Vec<u8>,
}

/// One signature answering a pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSignature {
    pub validator_id: u32,
    /// Publishing host (simulator bookkeeping, like [`CodedPacket::origins`]).
    pub origin: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncRequest {
    /// The sender holds the signatures whose bits are set; bit i is the subnet's
    /// i-th validator.
    Have { subnet: u32, bitmap: Vec<u8> },
    /// Pull these validators' signatures.
    Want { subnet: u32, validators: Vec<u32> },
    /// A coded repair packet; answered with [`SyncResponse::Ack`].
    Coded { subnet: u32, packet: CodedPacket },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncResponse {
    Ack,
    /// The pulled signatures the peer holds; missing ones are left out.
    Signatures {
        subnet: u32,
        signatures: Vec<SyncSignature>,
    },
}

/// Framing of a sync message: enum tag, subnet and stream overhead, roughly.
pub const SYNC_HEADER_BYTES: u64 = 8;
/// Bytes per validator index on the wire (an index inside the committee).
pub const INDEX_BYTES: u64 = 2;

impl SyncRequest {
    /// Approximate encoded size, as a compact protocol would send it.
    pub fn wire_bytes(&self) -> u64 {
        SYNC_HEADER_BYTES
            + match self {
                SyncRequest::Have { bitmap, .. } => bitmap.len() as u64,
                SyncRequest::Want { validators, .. } => INDEX_BYTES * validators.len() as u64,
                SyncRequest::Coded { packet, .. } => {
                    // Index and coefficient per signature, the symbol, the payload.
                    (INDEX_BYTES + 1) * packet.validators.len() as u64
                        + 1
                        + packet.payload.len() as u64
                }
            }
    }
}

impl SyncResponse {
    pub fn wire_bytes(&self) -> u64 {
        match self {
            SyncResponse::Ack => 1,
            SyncResponse::Signatures { signatures, .. } => {
                SYNC_HEADER_BYTES
                    + signatures
                        .iter()
                        .map(|sig| INDEX_BYTES + sig.payload.len() as u64)
                        .sum::<u64>()
            }
        }
    }
}
