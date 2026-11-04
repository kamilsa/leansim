use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Write};

/// How a signature reached a host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigVia {
    #[default]
    Gossip,
    /// Pulled from a mesh neighbour after its bitmap advertised it.
    Pull,
    /// Decoded from coded repair packets.
    Coded,
}

/// Structured event emitted as one JSON line to stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum JsonlEvent {
    /// Emitted by each node at startup to map PeerId → node index.
    NodePeerId { node_id: u32, peer_id: String },
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
        /// Bytes of the message that carried it; 0 for a decoded signature, whose
        /// packets are counted in [`JsonlEvent::TransportStats`].
        byte_size: u64,
        /// Absent in logs from before signature sync, which were all gossip.
        #[serde(default)]
        via: SigVia,
    },
    /// A local aggregator finished a subnet proof (announced to its layer-1 group
    /// with recursive aggregation).
    LocalProofGenerated {
        node_id: u32,
        subnet_id: u32,
        sig_count: usize,
        latency_ms: u64,
    },
    /// A host told `to_id` that it holds proof (layer, index).
    ProofAnnounced {
        node_id: u32,
        to_id: u32,
        layer: u32,
        index: u32,
        ts_ms: u64,
    },
    /// A host started pulling proof (layer, index) from `from_id`.
    ProofRequested {
        node_id: u32,
        from_id: u32,
        layer: u32,
        index: u32,
        ts_ms: u64,
    },
    /// A pulled proof arrived; `duplicate` when the host already held a copy.
    ProofFetched {
        node_id: u32,
        from_id: u32,
        layer: u32,
        index: u32,
        duplicate: bool,
        ts_ms: u64,
        byte_size: u64,
    },
    /// A pull failed: dial failure, timeout, closed connection, or the peer lacked the proof.
    ProofFetchFailed {
        node_id: u32,
        from_id: u32,
        layer: u32,
        index: u32,
        ts_ms: u64,
    },
    /// A host answered a pull with the proof's bytes.
    ProofServed {
        node_id: u32,
        to_id: u32,
        layer: u32,
        index: u32,
        ts_ms: u64,
        byte_size: u64,
    },
    /// A recursive aggregator finished group `index` of `layer`; `is_final` for the root.
    RecursiveProofGenerated {
        node_id: u32,
        layer: u32,
        index: u32,
        inputs: usize,
        is_final: bool,
        ts_ms: u64,
    },
    NodeStats {
        node_id: u32,
        bytes_sent: u64,
        bytes_received: u64,
        msgs_sent: u64,
        msgs_received: u64,
    },
    /// A host's signature-transport traffic over the run, besides signatures
    /// gossiped (counted by `SigReceived`): gossipsub control ids and the sync
    /// protocol. Byte counts are approximate wire sizes, all as sent by this host.
    /// No `byte_size` field, so it never counts towards the run's signature traffic.
    TransportStats {
        node_id: u32,
        ihave_ids_sent: u64,
        ihave_bytes_sent: u64,
        iwant_ids_sent: u64,
        iwant_bytes_sent: u64,
        idontwant_ids_sent: u64,
        idontwant_bytes_sent: u64,
        idontwant_ids_received: u64,
        forwards_suppressed: u64,
        #[serde(default)]
        queued_forwards_dropped: u64,
        have_sent: u64,
        have_bytes_sent: u64,
        want_sent: u64,
        want_ids_sent: u64,
        want_bytes_sent: u64,
        pull_sigs_served: u64,
        pull_bytes_served: u64,
        pulled_received: u64,
        pulled_duplicates: u64,
        coded_sent: u64,
        coded_bytes_sent: u64,
        coded_received: u64,
        coded_innovative: u64,
        coded_decoded: u64,
        coded_mismatches: u64,
        acks_sent: u64,
        sync_failures: u64,
        pending_rows: u64,
    },
    /// One bucket of a traffic-logging host, by message kind. No `byte_size`
    /// field, so these never count towards the run's signature traffic.
    TrafficBucket {
        node_id: u32,
        start_ms: u64,
        width_ms: u64,
        inbound: BTreeMap<String, u64>,
        outbound: BTreeMap<String, u64>,
    },
    /// One peer's traffic over the whole run, on a traffic-logging host.
    /// `peer` is `node:<id>` when the peer's node is known, else `peer:<base58>`.
    TrafficPeer {
        node_id: u32,
        peer: String,
        inbound_bytes: u64,
        outbound_bytes: u64,
        inbound_msgs: u64,
        outbound_msgs: u64,
    },
}

/// Emit a single JSONL event to stdout (flushed immediately so Shadow captures it).
pub fn emit(event: &JsonlEvent) {
    let line = serde_json::to_string(event).unwrap();
    println!("{line}");
    io::stdout().flush().ok();
}
