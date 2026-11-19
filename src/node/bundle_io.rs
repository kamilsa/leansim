//! Sends [`BundleSync`]'s bundles and parts metadata, as gossipsub partial
//! messages or as waggle messages, handles the ones peers send, and counts
//! their traffic.
//!
//! Over waggle a subnet is one object, [`GROUP_ID`]: a bundle is its `pieces`
//! and parts metadata its `metadata`, on the stream of the subnet's topic.

use std::collections::{HashMap, HashSet};

use libp2p::gossipsub::{IdentTopic, PartialMessage, TopicHash};
use libp2p::{PeerId, Swarm};
use tokio::time::Instant;
use waggle::handler::ObjectPieces;

use crate::config::experiment::{ExperimentConfig, SignatureTransport};
use crate::messages::bundle::{BundleKind, PartsMetadata, SignatureBundle, GROUP_ID, INDEX_BYTES};
use crate::metrics::events::SigVia;
use crate::metrics::traffic::{Direction, Kind, TrafficMeter};
use crate::network::swarm::SimBehaviour;
use crate::network::topics;
use crate::network::waggle_net;
use crate::node::bundles::{Arrival, BundleSync};
use crate::node::sigsync::Held;
use crate::node::sync_io::Delivery;

/// Bundle traffic, as sent by this host unless named otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BundleStats {
    pub bundles_sent: u64,
    pub bundle_sigs_sent: u64,
    pub bundle_bytes_sent: u64,
    pub bundle_framing_bytes_sent: u64,
    pub requested_sigs_served: u64,
    pub backlog_sigs_sent: u64,
    /// Signatures pushed on subnets this host does not subscribe to (fanout).
    pub fanout_sigs_sent: u64,
    pub metadata_sent: u64,
    pub metadata_bytes_sent: u64,
    pub available_ids_sent: u64,
    pub request_ids_sent: u64,
    pub pushes_avoided: u64,
    pub lazy_sigs_sent: u64,
    pub announce_ids_sent: u64,
    pub requests_already_sent: u64,
    pub requests_suppressed: u64,
    pub requests_avoided: u64,
    pub invalid_partials: u64,
    /// Bundles and metadata the transport did not take: the peer's waggle send
    /// queue was full, or the peer was gone.
    pub frames_unsent: u64,
}

pub struct BundleIo {
    transport: SignatureTransport,
    signature_bytes: usize,
    max_per_bundle: usize,
    run_id: String,
    /// The subnet of each tracked subnet's topic.
    subnets: HashMap<TopicHash, u32>,
    /// Subnets this host signs in without subscribing: pushed to fanout peers.
    publish_only: HashSet<u32>,
    /// A push or announcement of the last flush was not sent.
    retry: bool,
    pub stats: BundleStats,
}

impl BundleIo {
    pub fn new(config: &ExperimentConfig, subnets: impl IntoIterator<Item = u32>) -> Self {
        let run_id = config.run_id.clone();
        Self {
            transport: config.signature_transport,
            signature_bytes: config.signature_payload_bytes,
            max_per_bundle: config.max_signatures_per_bundle(),
            subnets: subnets
                .into_iter()
                .map(|subnet| (subnet_topic(&run_id, subnet), subnet))
                .collect(),
            run_id,
            publish_only: HashSet::new(),
            retry: false,
            stats: BundleStats::default(),
        }
    }

    /// Names the tracked subnets this host does not subscribe to, so pushes on
    /// them count as fanout.
    pub fn with_publish_only(mut self, subnets: impl IntoIterator<Item = u32>) -> Self {
        self.publish_only = subnets.into_iter().collect();
        self
    }

    /// Bytes a signature takes in a bundle: its payload and its validator index.
    pub fn signature_wire_bytes(&self) -> u64 {
        self.signature_bytes as u64 + INDEX_BYTES
    }

    /// The peers this host pushes `subnet`'s signatures to: gossipsub's mesh or
    /// fanout peers, or the subscribers picked over waggle.
    pub fn targets(&self, swarm: &mut Swarm<SimBehaviour>, subnet: u32) -> Vec<PeerId> {
        push_targets(swarm, self.transport, &self.run_id, subnet)
    }

    /// Whether the last flush left pushes or announcements unsent, to try again
    /// at a later tick. Cleared by the call.
    pub fn take_retry(&mut self) -> bool {
        std::mem::take(&mut self.retry)
    }

    /// The tick: push every target the signatures it lacks.
    pub fn flush(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
        now: Instant,
        ts_ms: u64,
    ) {
        let (transport, run_id) = (self.transport, &self.run_id);
        let pushes = sync.tick(now, |subnet| push_targets(swarm, transport, run_id, subnet));
        for push in pushes {
            let kind = if push.backlog {
                BundleKind::Backlog
            } else {
                BundleKind::Push
            };
            let sent = self.send_bundle(
                swarm,
                meter.as_deref_mut(),
                push.peer,
                push.subnet,
                &push.signatures,
                kind,
                ts_ms,
            );
            if !sent {
                sync.unsent_signatures(push.peer, push.subnet, validator_ids(&push.signatures));
                self.retry = true;
            } else if self.publish_only.contains(&push.subnet) {
                self.stats.fanout_sigs_sent += push.signatures.len() as u64;
            }
        }
        for announcement in sync.take_announcements() {
            let metadata = PartsMetadata {
                subnet: announcement.subnet,
                available: announcement.available.into_iter().map(u64::from).collect(),
                requests: Vec::new(),
            };
            let peer = announcement.peer;
            if !self.send_metadata(swarm, meter.as_deref_mut(), peer, &metadata, ts_ms) {
                sync.unsent_available(peer, metadata.subnet, &metadata.available);
                self.retry = true;
            }
        }
    }

    /// Gossipsub picked `peers` as gossip peers of `topic`: advertise to them.
    #[allow(clippy::too_many_arguments)]
    pub fn on_gossip(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        meter: Option<&mut TrafficMeter>,
        topic: &TopicHash,
        peers: &[PeerId],
        ts_ms: u64,
    ) {
        if let Some(&subnet) = self.subnets.get(topic) {
            self.advertise(swarm, sync, meter, subnet, peers, ts_ms);
        }
    }

    /// Advertises to `peers`, gossip peers of `subnet`, what each is not known
    /// to hold and has not been told about.
    #[allow(clippy::too_many_arguments)]
    pub fn advertise(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
        subnet: u32,
        peers: &[PeerId],
        ts_ms: u64,
    ) {
        for advert in sync.advertise(subnet, peers) {
            let metadata = PartsMetadata {
                subnet,
                available: advert.available.into_iter().map(u64::from).collect(),
                requests: Vec::new(),
            };
            if self.send_metadata(swarm, meter.as_deref_mut(), advert.peer, &metadata, ts_ms) {
                self.stats.available_ids_sent += metadata.available.len() as u64;
            } else {
                sync.unsent_available(advert.peer, subnet, &metadata.available);
            }
        }
    }

    /// A partial message arrived: take its signatures, then answer its metadata.
    /// Returns every signature it carried, new or duplicate.
    #[allow(clippy::too_many_arguments)]
    pub fn on_partial(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        meter: Option<&mut TrafficMeter>,
        peer: PeerId,
        message: PartialMessage,
        now: Instant,
        ts_ms: u64,
    ) -> Vec<Delivery> {
        let Some(&subnet) = self.subnets.get(&message.topic) else {
            return Vec::new();
        };
        if message.group_id != GROUP_ID {
            self.stats.invalid_partials += 1;
            return Vec::new();
        }
        let frame = Frame {
            body: message.message.as_deref(),
            metadata: message.metadata.as_deref(),
            bytes: message.frame_len() as u64,
        };
        self.on_frame(swarm, sync, meter, peer, subnet, frame, now, ts_ms)
    }

    /// A waggle message arrived on `subnet`: take its signatures, then answer its
    /// metadata. Returns every signature it carried, new or duplicate.
    #[allow(clippy::too_many_arguments)]
    pub fn on_pieces(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        meter: Option<&mut TrafficMeter>,
        peer: PeerId,
        subnet: u32,
        pieces: ObjectPieces,
        now: Instant,
        ts_ms: u64,
    ) -> Vec<Delivery> {
        if !sync.tracks(subnet) {
            return Vec::new();
        }
        if pieces.object_id != GROUP_ID {
            self.stats.invalid_partials += 1;
            return Vec::new();
        }
        let frame = Frame {
            body: pieces.pieces.as_deref(),
            metadata: pieces.metadata.as_deref(),
            bytes: waggle_net::frame_len(&pieces) as u64,
        };
        self.on_frame(swarm, sync, meter, peer, subnet, frame, now, ts_ms)
    }

    #[allow(clippy::too_many_arguments)]
    fn on_frame(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
        peer: PeerId,
        subnet: u32,
        frame: Frame<'_>,
        now: Instant,
        ts_ms: u64,
    ) -> Vec<Delivery> {
        let label = peer_label(&peer);
        let mut deliveries = Vec::new();

        if let Some(body) = frame.body {
            match SignatureBundle::decode(body, self.signature_bytes, self.max_per_bundle) {
                Ok(bundle) if bundle.subnet == subnet => {
                    let via = match bundle.kind {
                        BundleKind::Push => SigVia::Bundle,
                        BundleKind::Backlog => SigVia::Backlog,
                        BundleKind::Requested => SigVia::Requested,
                    };
                    let per_sig = self.signature_wire_bytes();
                    for (validator, origin) in bundle.validators.iter().zip(&bundle.origins) {
                        let Some(arrival) =
                            sync.deliver(subnet, *validator, *origin, Some(peer), now)
                        else {
                            continue;
                        };
                        let duplicate = arrival == Arrival::Duplicate;
                        if let Some(meter) = meter.as_deref_mut() {
                            let kind = if duplicate {
                                Kind::DuplicateSignature
                            } else {
                                Kind::Signature
                            };
                            meter.record(ts_ms, Direction::In, kind, per_sig, &label);
                        }
                        deliveries.push(Delivery {
                            subnet,
                            validator_id: *validator as u32,
                            origin: *origin,
                            via,
                            duplicate,
                            byte_size: per_sig,
                            from_peer: peer,
                        });
                    }
                }
                _ => self.stats.invalid_partials += 1,
            }
        }
        if let Some(meter) = meter.as_deref_mut() {
            // Whatever the frame adds to the signatures: framing, or metadata alone.
            let signatures = deliveries.len() as u64 * self.signature_wire_bytes();
            let rest = frame.bytes.saturating_sub(signatures);
            meter.record(ts_ms, Direction::In, Kind::SyncControl, rest, &label);
        }

        if let Some(raw) = frame.metadata {
            match PartsMetadata::decode(raw) {
                Ok(metadata) if metadata.subnet == subnet => {
                    let reply = sync.on_metadata(
                        peer,
                        subnet,
                        &metadata.available,
                        &metadata.requests,
                        now,
                    );
                    if !reply.requests.is_empty() {
                        let request = PartsMetadata {
                            subnet,
                            available: Vec::new(),
                            requests: reply.requests.into_iter().map(u64::from).collect(),
                        };
                        if self.send_metadata(swarm, meter.as_deref_mut(), peer, &request, ts_ms) {
                            self.stats.request_ids_sent += request.requests.len() as u64;
                        } else {
                            sync.unsent_requests(subnet, &request.requests);
                        }
                    }
                    for signatures in reply.serve {
                        let sent = self.send_bundle(
                            swarm,
                            meter.as_deref_mut(),
                            peer,
                            subnet,
                            &signatures,
                            BundleKind::Requested,
                            ts_ms,
                        );
                        if sent {
                            self.stats.requested_sigs_served += signatures.len() as u64;
                        } else {
                            sync.unsent_signatures(peer, subnet, validator_ids(&signatures));
                        }
                    }
                }
                _ => self.stats.invalid_partials += 1,
            }
        }
        deliveries
    }

    /// Sends the delayed requests due by `now`.
    pub fn send_due_requests(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
        now: Instant,
        ts_ms: u64,
    ) {
        for request in sync.due_requests(now) {
            let metadata = PartsMetadata {
                subnet: request.subnet,
                available: Vec::new(),
                requests: request.validators.into_iter().map(u64::from).collect(),
            };
            if self.send_metadata(swarm, meter.as_deref_mut(), request.peer, &metadata, ts_ms) {
                self.stats.request_ids_sent += metadata.requests.len() as u64;
            } else {
                sync.unsent_requests(metadata.subnet, &metadata.requests);
            }
        }
    }

    /// The run's counters, with the state machine's.
    pub fn final_stats(&self, sync: &BundleSync<PeerId>) -> BundleStats {
        BundleStats {
            pushes_avoided: sync.counters.pushes_avoided,
            lazy_sigs_sent: sync.counters.lazy_pushes,
            announce_ids_sent: sync.counters.announced,
            requests_already_sent: sync.counters.requests_already_sent,
            requests_suppressed: sync.counters.requests_suppressed,
            backlog_sigs_sent: sync.counters.backlog_pushes,
            requests_avoided: sync.counters.requests_avoided,
            ..self.stats
        }
    }

    /// Sends one bundle; false if the transport did not take it.
    #[allow(clippy::too_many_arguments)]
    fn send_bundle(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        meter: Option<&mut TrafficMeter>,
        peer: PeerId,
        subnet: u32,
        signatures: &[Held],
        kind: BundleKind,
        ts_ms: u64,
    ) -> bool {
        // Before building the bundle: a full queue turns away most of a burst.
        if !self.can_send(swarm, &peer, subnet) {
            self.stats.frames_unsent += 1;
            return false;
        }
        let bundle = SignatureBundle {
            subnet,
            validators: signatures
                .iter()
                .map(|held| u64::from(held.validator_id))
                .collect(),
            origins: signatures.iter().map(|held| held.origin).collect(),
            kind,
            signatures: vec![0; signatures.len() * self.signature_bytes],
        };
        let bytes = self.send(swarm, &peer, subnet, Some(bundle.encode()), None);
        if bytes == 0 {
            self.stats.frames_unsent += 1;
            return false;
        }
        let n = signatures.len() as u64;
        self.stats.bundles_sent += 1;
        self.stats.bundle_sigs_sent += n;
        self.stats.bundle_bytes_sent += bytes;
        self.stats.bundle_framing_bytes_sent +=
            bytes.saturating_sub(n * self.signature_wire_bytes());
        if let Some(meter) = meter {
            meter.record(
                ts_ms,
                Direction::Out,
                Kind::Signature,
                bytes,
                &peer_label(&peer),
            );
        }
        true
    }

    /// Sends parts metadata; false if the transport did not take it.
    fn send_metadata(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        meter: Option<&mut TrafficMeter>,
        peer: PeerId,
        metadata: &PartsMetadata,
        ts_ms: u64,
    ) -> bool {
        let bytes = self.send(swarm, &peer, metadata.subnet, None, Some(metadata.encode()));
        if bytes == 0 {
            self.stats.frames_unsent += 1;
            return false;
        }
        self.stats.metadata_sent += 1;
        self.stats.metadata_bytes_sent += bytes;
        if let Some(meter) = meter {
            meter.record(
                ts_ms,
                Direction::Out,
                Kind::SyncControl,
                bytes,
                &peer_label(&peer),
            );
        }
        true
    }

    /// Whether the transport would take a frame for `peer` now. Gossipsub
    /// answers when it is given the frame.
    fn can_send(&self, swarm: &Swarm<SimBehaviour>, peer: &PeerId, subnet: u32) -> bool {
        match self.transport {
            SignatureTransport::Gossipsub => true,
            SignatureTransport::Waggle => swarm
                .behaviour()
                .waggle
                .as_ref()
                .is_some_and(|waggle| waggle.can_send(peer, subnet)),
        }
    }

    /// Hands one frame to the transport. Returns its bytes on the wire, or 0 if
    /// the transport did not take it.
    fn send(
        &self,
        swarm: &mut Swarm<SimBehaviour>,
        peer: &PeerId,
        subnet: u32,
        body: Option<Vec<u8>>,
        metadata: Option<Vec<u8>>,
    ) -> u64 {
        let bytes = match self.transport {
            SignatureTransport::Gossipsub => {
                let message = PartialMessage {
                    topic: subnet_topic(&self.run_id, subnet),
                    group_id: GROUP_ID.to_vec(),
                    message: body,
                    metadata,
                };
                swarm.behaviour_mut().gossipsub.send_partial(peer, message)
            }
            SignatureTransport::Waggle => {
                let pieces = ObjectPieces {
                    object_id: GROUP_ID.to_vec(),
                    metadata,
                    pieces: body,
                };
                swarm
                    .behaviour_mut()
                    .waggle
                    .as_mut()
                    .map_or(0, |waggle| waggle.send(peer, subnet, pieces))
            }
        };
        bytes as u64
    }
}

/// A bundle, parts metadata or both, as either transport delivers them.
struct Frame<'a> {
    body: Option<&'a [u8]>,
    metadata: Option<&'a [u8]>,
    /// Bytes of the frame on the wire.
    bytes: u64,
}

fn push_targets(
    swarm: &mut Swarm<SimBehaviour>,
    transport: SignatureTransport,
    run_id: &str,
    subnet: u32,
) -> Vec<PeerId> {
    match transport {
        SignatureTransport::Gossipsub => swarm
            .behaviour_mut()
            .gossipsub
            .partial_targets(&subnet_topic(run_id, subnet)),
        SignatureTransport::Waggle => swarm
            .behaviour_mut()
            .waggle
            .as_mut()
            .map_or_else(Vec::new, |waggle| waggle.push_targets(subnet)),
    }
}

fn validator_ids(signatures: &[Held]) -> impl Iterator<Item = u32> + '_ {
    signatures.iter().map(|held| held.validator_id)
}

fn subnet_topic(run_id: &str, subnet: u32) -> TopicHash {
    IdentTopic::new(topics::subnet_topic(run_id, subnet)).hash()
}

fn peer_label(peer: &PeerId) -> String {
    format!("peer:{}", peer.to_base58())
}
