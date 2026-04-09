use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Validator,
    LocalAggregator,
    GlobalAggregator,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    Signature {
        validator_id: u32,
        subnet_id: u32,
        data: Vec<u8>,
    },
    SNARK1 {
        aggregator_id: u32,
        subnet_id: u32,
        data: Vec<u8>,
        verified_sigs: usize,
    },
    SNARK2 {
        aggregator_id: u32,
        data: Vec<u8>,
        verified_snarks: usize,
    },
    // Gossipsub 1.2 control messages
    IHAVE {
        id: [u8; 32],
    },
    IWANT {
        id: [u8; 32],
    },
    IDONTWANT {
        id: [u8; 32],
    },
    PUBLISH {
        id: [u8; 32],
        payload: Vec<u8>,
    },
}

impl Message {
    pub fn get_id(&self) -> [u8; 32] {
        // In a real app, this would be a hash of the content
        // For simulation, we can use the content or a unique identifier
        match self {
            Message::Signature { validator_id, subnet_id, .. } => {
                let mut id = [0u8; 32];
                id[0..4].copy_from_slice(&validator_id.to_be_bytes());
                id[4..8].copy_from_slice(&subnet_id.to_be_bytes());
                id[8] = 0; // Signature type
                id
            }
            Message::SNARK1 { aggregator_id, subnet_id, .. } => {
                let mut id = [0u8; 32];
                id[0..4].copy_from_slice(&aggregator_id.to_be_bytes());
                id[4..8].copy_from_slice(&subnet_id.to_be_bytes());
                id[8] = 1; // SNARK1 type
                id
            }
            Message::SNARK2 { aggregator_id, .. } => {
                let mut id = [0u8; 32];
                id[0..4].copy_from_slice(&aggregator_id.to_be_bytes());
                id[8] = 2; // SNARK2 type
                id
            }
            _ => [0u8; 32],
        }
    }
}
