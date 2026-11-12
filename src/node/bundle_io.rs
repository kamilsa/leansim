//! Sends [`BundleSync`]'s bundles and parts metadata as gossipsub partial
//! messages, handles the ones peers send, and counts their traffic.

use std::collections::{HashMap, HashSet};

use libp2p::gossipsub::{IdentTopic, PartialMessage, TopicHash};
use libp2p::{PeerId, Swarm};
use tokio::time::Instant;

use crate::config::experiment::ExperimentConfig;
use crate::messages::bundle::{BundleKind, PartsMetadata, SignatureBundle, GROUP_ID, INDEX_BYTES};
use crate::metrics::events::SigVia;
use crate::metrics::traffic::{Direction, Kind, TrafficMeter};
use crate::network::swarm::SimBehaviour;
use crate::network::topics;
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
}

pub struct BundleIo {
    signature_bytes: usize,
    max_per_bundle: usize,
    run_id: String,
    /// The subnet of each tracked subnet's topic.
    subnets: HashMap<TopicHash, u32>,
    /// Subnets this host signs in without subscribing: pushed to fanout peers.
    publish_only: HashSet<u32>,
    pub stats: BundleStats,
}

impl BundleIo {
    pub fn new(config: &ExperimentConfig, subnets: impl IntoIterator<Item = u32>) -> Self {
        let run_id = config.run_id.clone();
        Self {
            signature_bytes: config.signature_payload_bytes,
            max_per_bundle: config.bundle_max_signatures.max(1),
            subnets: subnets
                .into_iter()
                .map(|subnet| (subnet_topic(&run_id, subnet), subnet))
                .collect(),
            run_id,
            publish_only: HashSet::new(),
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

    /// The tick: push every target the signatures it lacks.
    pub fn flush(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
        now: Instant,
        ts_ms: u64,
    ) {
        let run_id = &self.run_id;
        let pushes = sync.tick(now, |subnet| {
            swarm
                .behaviour_mut()
                .gossipsub
                .partial_targets(&subnet_topic(run_id, subnet))
        });
        for push in pushes {
            let kind = if push.backlog {
                BundleKind::Backlog
            } else {
                BundleKind::Push
            };
            if self.publish_only.contains(&push.subnet) {
                self.stats.fanout_sigs_sent += push.signatures.len() as u64;
            }
            self.send_bundle(
                swarm,
                meter.as_deref_mut(),
                push.peer,
                push.subnet,
                &push.signatures,
                kind,
                ts_ms,
            );
        }
        for announcement in sync.take_announcements() {
            let metadata = PartsMetadata {
                subnet: announcement.subnet,
                available: announcement.available.into_iter().map(u64::from).collect(),
                requests: Vec::new(),
            };
            self.send_metadata(
                swarm,
                meter.as_deref_mut(),
                announcement.peer,
                metadata,
                ts_ms,
            );
        }
    }

    /// Gossipsub picked `peers` as gossip peers of `topic`: advertise to them.
    #[allow(clippy::too_many_arguments)]
    pub fn on_gossip(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
        topic: &TopicHash,
        peers: &[PeerId],
        ts_ms: u64,
    ) {
        let Some(&subnet) = self.subnets.get(topic) else {
            return;
        };
        for advert in sync.advertise(subnet, peers) {
            self.stats.available_ids_sent += advert.available.len() as u64;
            let metadata = PartsMetadata {
                subnet,
                available: advert.available.into_iter().map(u64::from).collect(),
                requests: Vec::new(),
            };
            self.send_metadata(swarm, meter.as_deref_mut(), advert.peer, metadata, ts_ms);
        }
    }

    /// A partial message arrived: take its signatures, then answer its metadata.
    /// Returns every signature it carried, new or duplicate.
    #[allow(clippy::too_many_arguments)]
    pub fn on_partial(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut BundleSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
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
        let label = peer_label(&peer);
        let frame_bytes = message.frame_len() as u64;
        let mut deliveries = Vec::new();

        if let Some(body) = &message.message {
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
            let rest = frame_bytes.saturating_sub(signatures);
            meter.record(ts_ms, Direction::In, Kind::SyncControl, rest, &label);
        }

        if let Some(raw) = &message.metadata {
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
                        self.stats.request_ids_sent += reply.requests.len() as u64;
                        let request = PartsMetadata {
                            subnet,
                            available: Vec::new(),
                            requests: reply.requests.into_iter().map(u64::from).collect(),
                        };
                        self.send_metadata(swarm, meter.as_deref_mut(), peer, request, ts_ms);
                    }
                    for signatures in reply.serve {
                        self.stats.requested_sigs_served += signatures.len() as u64;
                        self.send_bundle(
                            swarm,
                            meter.as_deref_mut(),
                            peer,
                            subnet,
                            &signatures,
                            BundleKind::Requested,
                            ts_ms,
                        );
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
            self.stats.request_ids_sent += request.validators.len() as u64;
            let metadata = PartsMetadata {
                subnet: request.subnet,
                available: Vec::new(),
                requests: request.validators.into_iter().map(u64::from).collect(),
            };
            self.send_metadata(swarm, meter.as_deref_mut(), request.peer, metadata, ts_ms);
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
    ) {
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
        let message = PartialMessage {
            topic: subnet_topic(&self.run_id, subnet),
            group_id: GROUP_ID.to_vec(),
            message: Some(bundle.encode()),
            metadata: None,
        };
        let bytes = swarm.behaviour_mut().gossipsub.send_partial(&peer, message) as u64;
        if bytes == 0 {
            return;
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
    }

    fn send_metadata(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        meter: Option<&mut TrafficMeter>,
        peer: PeerId,
        metadata: PartsMetadata,
        ts_ms: u64,
    ) {
        let message = PartialMessage {
            topic: subnet_topic(&self.run_id, metadata.subnet),
            group_id: GROUP_ID.to_vec(),
            message: None,
            metadata: Some(metadata.encode()),
        };
        let bytes = swarm.behaviour_mut().gossipsub.send_partial(&peer, message) as u64;
        if bytes == 0 {
            return;
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
    }
}

fn subnet_topic(run_id: &str, subnet: u32) -> TopicHash {
    IdentTopic::new(topics::subnet_topic(run_id, subnet)).hash()
}

fn peer_label(peer: &PeerId) -> String {
    format!("peer:{}", peer.to_base58())
}
