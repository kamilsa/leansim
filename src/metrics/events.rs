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
    /// Pushed in an EIP-8334 bundle.
    Bundle,
    /// Sent in an EIP-8334 bundle in answer to this host's request.
    Requested,
    /// Pushed in an EIP-8334 bundle of signatures the sender held before this host
    /// became its push target.
    Backlog,
}

/// When a host's mesh degree was sampled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshSample {
    /// Right after the host signed (or would have, for a host without validators).
    Signing,
    /// At the end of the run.
    Exit,
}

/// Structured event emitted as one JSON line to stdout.
// Events are built and serialized one at a time, so the large TransportStats is fine.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum JsonlEvent {
    /// Emitted by each node at startup to map PeerId → node index.
    NodePeerId { node_id: u32, peer_id: String },
    /// A churny host came online, or crashed (`online: false`) and lost all
    /// state. A host that starts the run offline says so at `ts_ms` 0.
    Churn {
        node_id: u32,
        online: bool,
        ts_ms: u64,
    },
    /// The host's gossipsub mesh peers on one subnet it subscribes to.
    MeshDegree {
        node_id: u32,
        subnet_id: u32,
        peers: u32,
        at: MeshSample,
        ts_ms: u64,
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
        /// Gossip messages that answered this host's IWANTs, and how many of them
        /// were already held on arrival.
        #[serde(default)]
        iwant_responses: u64,
        #[serde(default)]
        iwant_response_duplicates: u64,
        /// Signature copies this host sent on subnets it does not subscribe to
        /// (fanout): they enter the subnet's mesh from outside it.
        #[serde(default)]
        fanout_sigs_sent: u64,
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
        /// EIP-8334 bundles sent, pushed or served, the signatures they carried, and
        /// their frame bytes; framing is what the frames add to the signatures and
        /// their 8-byte validator indices.
        #[serde(default)]
        bundles_sent: u64,
        #[serde(default)]
        bundle_sigs_sent: u64,
        #[serde(default)]
        bundle_bytes_sent: u64,
        #[serde(default)]
        bundle_framing_bytes_sent: u64,
        /// Signatures sent in answer to requests (included in `bundle_sigs_sent`).
        #[serde(default)]
        requested_sigs_served: u64,
        /// Signatures pushed as backlog to new push targets (included in `bundle_sigs_sent`).
        #[serde(default)]
        backlog_sigs_sent: u64,
        /// Parts metadata frames sent (advertisements and requests).
        #[serde(default)]
        metadata_sent: u64,
        #[serde(default)]
        metadata_bytes_sent: u64,
        #[serde(default)]
        available_ids_sent: u64,
        #[serde(default)]
        request_ids_sent: u64,
        /// Signatures a peer delivered while this host was waiting to push them to it.
        #[serde(default)]
        pushes_avoided: u64,
        /// Signatures announced to mesh peers instead of, or ahead of, a push
        /// (their bytes are in `metadata_bytes_sent`).
        #[serde(default)]
        announce_ids_sent: u64,
        /// Requested signatures not served because they were already on their way.
        #[serde(default)]
        requests_already_sent: u64,
        /// Signatures pushed by the end of a link that waits out the stagger, because
        /// the other end's copy did not come in time (included in `bundle_sigs_sent`).
        #[serde(default)]
        lazy_sigs_sent: u64,
        /// Advertised signatures not requested because a request was in flight.
        #[serde(default)]
        requests_suppressed: u64,
        /// Advertised signatures not requested because they arrived during the
        /// request delay.
        #[serde(default)]
        requests_avoided: u64,
        /// Bundles and metadata dropped as malformed.
        #[serde(default)]
        invalid_partials: u64,
        /// Bundles and metadata the transport did not take, because the peer's
        /// waggle send queue was full or the peer was gone. Their signatures are
        /// pushed or advertised again, so they are in none of the counts above.
        #[serde(default)]
        frames_unsent: u64,
        /// Churn: peers this host told that it restarted, after rejoining.
        #[serde(default)]
        restart_notices_sent: u64,
        /// Churn: peers dropped and redialed because they restarted while this
        /// host still held a connection to their previous session.
        #[serde(default)]
        restart_reconnects: u64,
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
