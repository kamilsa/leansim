//! EIP-8334 bundled signature propagation over gossipsub's partial messages
//! extension (the EIP before it moved to waggle): bundles of signatures, and the
//! parts metadata peers reconcile with.
//!
//! The group of a partial message is the slot, and a run is one slot, so every
//! message uses [`GROUP_ID`]. Validator indices are `u64`, as `ValidatorIndex` is
//! in the EIP's SSZ containers. The EIP's shared `AttestationData` is left out:
//! every signature keeps its full `signature_payload_bytes`, so bundles save only
//! duplicates, not attestation data.

use serde::{Deserialize, Serialize};

/// The partial-message group id: slot 0 as a little-endian `uint64`.
pub const GROUP_ID: [u8; 8] = 0u64.to_le_bytes();

/// Bytes a validator index takes on the wire.
pub const INDEX_BYTES: u64 = 8;

/// Why a bundle was sent (simulator bookkeeping for the logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleKind {
    /// New signatures pushed at a tick.
    Push,
    /// Signatures held before the receiver became a push target.
    Backlog,
    /// Signatures the receiver requested.
    Requested,
}

/// Signatures of one subnet (the EIP's `AttestationBundle`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBundle {
    /// The committee, which is the subnet.
    pub subnet: u32,
    /// The signers; `signatures` holds one signature per validator, in this order.
    pub validators: Vec<u64>,
    /// Publishing host of each signature: simulator bookkeeping for the logs.
    pub origins: Vec<u32>,
    /// Why it was sent (bookkeeping for the logs).
    pub kind: BundleKind,
    /// The signatures, concatenated; each stands in as `signature_payload_bytes` zeros.
    pub signatures: Vec<u8>,
}

/// What a peer holds and wants of one subnet (the EIP's
/// `CommitteeAttestationPartsMetadata`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartsMetadata {
    pub subnet: u32,
    /// Validators whose signatures the sender holds.
    pub available: Vec<u64>,
    /// Validators whose signatures the sender wants from the receiver.
    pub requests: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    Decode,
    Empty,
    TooLarge,
    /// Signature bytes, origins and validators do not line up.
    Malformed,
    /// A validator appears twice.
    Duplicate,
}

impl SignatureBundle {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bincode serialization is infallible")
    }

    /// Decodes a bundle and checks it carries 1..=`max` signatures of
    /// `signature_bytes` each, every validator at most once.
    pub fn decode(data: &[u8], signature_bytes: usize, max: usize) -> Result<Self, BundleError> {
        let bundle: Self = bincode::deserialize(data).map_err(|_| BundleError::Decode)?;
        let n = bundle.validators.len();
        if n == 0 {
            return Err(BundleError::Empty);
        }
        if n > max {
            return Err(BundleError::TooLarge);
        }
        if bundle.origins.len() != n || bundle.signatures.len() != n * signature_bytes {
            return Err(BundleError::Malformed);
        }
        let mut seen = bundle.validators.clone();
        seen.sort_unstable();
        seen.dedup();
        if seen.len() != n {
            return Err(BundleError::Duplicate);
        }
        Ok(bundle)
    }
}

impl PartsMetadata {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bincode serialization is infallible")
    }

    pub fn decode(data: &[u8]) -> Result<Self, BundleError> {
        bincode::deserialize(data).map_err(|_| BundleError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(validators: Vec<u64>, signature_bytes: usize) -> SignatureBundle {
        SignatureBundle {
            subnet: 2,
            origins: vec![7; validators.len()],
            signatures: vec![0; validators.len() * signature_bytes],
            validators,
            kind: BundleKind::Push,
        }
    }

    #[test]
    fn bundles_roundtrip_and_cost_their_signatures() {
        let b = bundle(vec![5, 9, 11], 100);
        let bytes = b.encode();
        assert_eq!(SignatureBundle::decode(&bytes, 100, 50), Ok(b));
        // Signatures, 8-byte indices and 4-byte origins, plus a small header.
        assert!(bytes.len() >= 3 * (100 + 8 + 4) && bytes.len() < 3 * (100 + 8 + 4) + 64);
    }

    #[test]
    fn malformed_bundles_are_rejected() {
        assert_eq!(
            SignatureBundle::decode(&bundle(vec![], 10).encode(), 10, 50),
            Err(BundleError::Empty)
        );
        assert_eq!(
            SignatureBundle::decode(&bundle(vec![1, 2, 3], 10).encode(), 10, 2),
            Err(BundleError::TooLarge)
        );
        assert_eq!(
            SignatureBundle::decode(&bundle(vec![1, 2], 10).encode(), 11, 50),
            Err(BundleError::Malformed)
        );
        assert_eq!(
            SignatureBundle::decode(&bundle(vec![1, 1], 10).encode(), 10, 50),
            Err(BundleError::Duplicate)
        );
        assert_eq!(
            SignatureBundle::decode(&[1, 2, 3], 10, 50),
            Err(BundleError::Decode)
        );
    }

    #[test]
    fn metadata_roundtrips() {
        let m = PartsMetadata {
            subnet: 1,
            available: vec![1, 2],
            requests: vec![3],
        };
        assert_eq!(PartsMetadata::decode(&m.encode()), Ok(m));
    }
}
