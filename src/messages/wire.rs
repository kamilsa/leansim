use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 32-byte content-addressed message identifier.
pub type MessageId = [u8; 32];

/// Wire message types exchanged over gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    ValidatorSignature {
        run_id: String,
        sender_id: u32,
        subnet_id: u32,
        sequence_id: u64,
        created_timestamp_ms: u64,
        padding: Vec<u8>,
    },
    LocalProof {
        run_id: String,
        sender_id: u32,
        subnet_id: u32,
        covered_validator_count: usize,
        sequence_id: u64,
        created_timestamp_ms: u64,
        padding: Vec<u8>,
    },
    GlobalProof {
        run_id: String,
        sender_id: u32,
        covered_signature_count: usize,
        sequence_id: u64,
        created_timestamp_ms: u64,
        padding: Vec<u8>,
    },
}

impl WireMessage {
    /// Computes a SHA-256 message id from the bincode-serialized content.
    pub fn message_id(&self) -> MessageId {
        let bytes = bincode::serialize(self).expect("bincode serialization is infallible");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// Returns a new message with padding adjusted to achieve `target_total_bytes`.
    /// If the unpadded message already exceeds the target, padding is empty.
    pub fn with_payload_size(self, target_total_bytes: usize) -> Self {
        let unpadded_len = bincode::serialize(&self).unwrap_or_default().len();
        let needed = target_total_bytes.saturating_sub(unpadded_len);
        match self {
            Self::ValidatorSignature {
                run_id,
                sender_id,
                subnet_id,
                sequence_id,
                created_timestamp_ms,
                ..
            } => Self::ValidatorSignature {
                run_id,
                sender_id,
                subnet_id,
                sequence_id,
                created_timestamp_ms,
                padding: vec![0u8; needed],
            },
            Self::LocalProof {
                run_id,
                sender_id,
                subnet_id,
                covered_validator_count,
                sequence_id,
                created_timestamp_ms,
                ..
            } => Self::LocalProof {
                run_id,
                sender_id,
                subnet_id,
                covered_validator_count,
                sequence_id,
                created_timestamp_ms,
                padding: vec![0u8; needed],
            },
            Self::GlobalProof {
                run_id,
                sender_id,
                covered_signature_count,
                sequence_id,
                created_timestamp_ms,
                ..
            } => Self::GlobalProof {
                run_id,
                sender_id,
                covered_signature_count,
                sequence_id,
                created_timestamp_ms,
                padding: vec![0u8; needed],
            },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bincode serialization is infallible")
    }

    pub fn decode(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    pub fn run_id(&self) -> &str {
        match self {
            Self::ValidatorSignature { run_id, .. }
            | Self::LocalProof { run_id, .. }
            | Self::GlobalProof { run_id, .. } => run_id,
        }
    }

    pub fn sender_id(&self) -> u32 {
        match self {
            Self::ValidatorSignature { sender_id, .. }
            | Self::LocalProof { sender_id, .. }
            | Self::GlobalProof { sender_id, .. } => *sender_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_deterministic() {
        let a = WireMessage::ValidatorSignature {
            run_id: "test".into(),
            sender_id: 1,
            subnet_id: 0,
            sequence_id: 1,
            created_timestamp_ms: 100,
            padding: vec![0u8; 16],
        };
        let b = a.clone();
        assert_eq!(a.message_id(), b.message_id());
    }

    #[test]
    fn message_id_differs_on_content() {
        let a = WireMessage::ValidatorSignature {
            run_id: "test".into(),
            sender_id: 1,
            subnet_id: 0,
            sequence_id: 1,
            created_timestamp_ms: 100,
            padding: vec![0u8; 16],
        };
        let b = WireMessage::ValidatorSignature {
            run_id: "test".into(),
            sender_id: 2,
            subnet_id: 0,
            sequence_id: 1,
            created_timestamp_ms: 100,
            padding: vec![0u8; 16],
        };
        assert_ne!(a.message_id(), b.message_id());
    }

    #[test]
    fn roundtrip_all_variants() {
        let msgs = vec![
            WireMessage::ValidatorSignature {
                run_id: "r1".into(),
                sender_id: 0,
                subnet_id: 1,
                sequence_id: 42,
                created_timestamp_ms: 1000,
                padding: vec![7u8; 100],
            },
            WireMessage::LocalProof {
                run_id: "r1".into(),
                sender_id: 10,
                subnet_id: 1,
                covered_validator_count: 900,
                sequence_id: 1,
                created_timestamp_ms: 2000,
                padding: vec![0u8; 1000],
            },
            WireMessage::GlobalProof {
                run_id: "r1".into(),
                sender_id: 100,
                covered_signature_count: 7200,
                sequence_id: 1,
                created_timestamp_ms: 3000,
                padding: vec![],
            },
        ];
        for msg in msgs {
            let bytes = msg.encode();
            let decoded = WireMessage::decode(&bytes).unwrap();
            assert_eq!(msg.message_id(), decoded.message_id());
        }
    }

    #[test]
    fn with_payload_size_approximates_target() {
        let msg = WireMessage::GlobalProof {
            run_id: "r".into(),
            sender_id: 0,
            covered_signature_count: 0,
            sequence_id: 0,
            created_timestamp_ms: 0,
            padding: vec![],
        };
        let sized = msg.with_payload_size(4096);
        let bytes = sized.encode();
        // Should be close to target (not exact due to length prefix, but within reason)
        assert!(bytes.len() >= 4096 && bytes.len() < 4200,
            "expected >= 4096, got {}", bytes.len());
    }
}
