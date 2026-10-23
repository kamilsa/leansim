use serde::{Deserialize, Serialize};
use std::io::{self, Write};

/// Structured event emitted as one JSON line to stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum JsonlEvent {
    /// Emitted by each node at startup to map PeerId → node index.
    NodePeerId {
        node_id: u32,
        peer_id: String,
    },
    SigSent {
        node_id: u32,
        /// Logical validator that signed; absent in logs from before multi-validator hosts.
        #[serde(default)]
        validator_id: Option<u32>,
        subnet_id: u32,
        seq: u64,
        ts_ms: u64,
        byte_size: u64,
    },
    SigReceived {
        node_id: u32,
        /// Host that originally published the signature.
        from_id: u32,
        #[serde(default)]
        validator_id: Option<u32>,
        #[serde(default)]
        from_peer_id: String,
        subnet_id: u32,
        duplicate: bool,
        ts_ms: u64,
        byte_size: u64,
    },
    /// A local aggregator finished its subnet proof (computed, not transmitted).
    LocalProofGenerated {
        node_id: u32,
        subnet_id: u32,
        sig_count: usize,
        latency_ms: u64,
    },
    NodeStats {
        node_id: u32,
        bytes_sent: u64,
        bytes_received: u64,
        msgs_sent: u64,
        msgs_received: u64,
    },
}

/// Emit a single JSONL event to stdout (flushed immediately so Shadow captures it).
pub fn emit(event: &JsonlEvent) {
    let line = serde_json::to_string(event).unwrap();
    println!("{line}");
    io::stdout().flush().ok();
}
