//! Executes [`SigSync`] actions on the sync protocol, answers neighbours'
//! sync messages, and counts the protocol's traffic.

use std::collections::HashMap;

use libp2p::request_response::{OutboundRequestId, ResponseChannel};
use libp2p::{PeerId, Swarm};
use tokio::time::Instant;

use crate::messages::sync::{SyncRequest, SyncResponse, SyncSignature};
use crate::metrics::events::{JsonlEvent, SigVia};
use crate::metrics::traffic::{Direction, Kind, TrafficMeter};
use crate::network::swarm::SimBehaviour;
use crate::node::sigsync::{Action, SigSync};

/// A signature that reached this host through the sync protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub subnet: u32,
    pub validator_id: u32,
    pub origin: u32,
    pub via: SigVia,
    /// Already held when it arrived (a pull answered after gossip, say).
    pub duplicate: bool,
    pub byte_size: u64,
    pub from_peer: PeerId,
}

/// Sync protocol counters, as sent by this host unless named otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStats {
    pub have_sent: u64,
    pub have_bytes_sent: u64,
    pub want_sent: u64,
    pub want_ids_sent: u64,
    pub want_bytes_sent: u64,
    pub pull_sigs_served: u64,
    pub pull_bytes_served: u64,
    pub pulled_received: u64,
    pub pulled_duplicates: u64,
    pub coded_sent: u64,
    pub coded_bytes_sent: u64,
    pub coded_received: u64,
    pub coded_innovative: u64,
    pub coded_decoded: u64,
    pub coded_mismatches: u64,
    pub acks_sent: u64,
    pub failures: u64,
}

pub struct SyncIo {
    /// Stands in for one signature's bytes.
    payload: Vec<u8>,
    /// Pulls in flight: request → (subnet, validators asked for).
    pulls: HashMap<OutboundRequestId, (u32, Vec<u32>)>,
    pub stats: SyncStats,
}

impl SyncIo {
    pub fn new(signature_bytes: usize) -> Self {
        Self {
            payload: vec![0; signature_bytes],
            pulls: HashMap::new(),
            stats: SyncStats::default(),
        }
    }

    pub fn execute(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        mut meter: Option<&mut TrafficMeter>,
        actions: Vec<Action<PeerId>>,
        ts_ms: u64,
    ) {
        for action in actions {
            let (peer, request) = match action {
                Action::Have {
                    peer,
                    subnet,
                    bitmap,
                } => (peer, SyncRequest::Have { subnet, bitmap }),
                Action::Want {
                    peer,
                    subnet,
                    validators,
                } => (peer, SyncRequest::Want { subnet, validators }),
                Action::Coded {
                    peer,
                    subnet,
                    packet,
                } => (peer, SyncRequest::Coded { subnet, packet }),
            };
            let bytes = request.wire_bytes();
            let kind = match &request {
                SyncRequest::Have { .. } => {
                    self.stats.have_sent += 1;
                    self.stats.have_bytes_sent += bytes;
                    Kind::SyncControl
                }
                SyncRequest::Want { validators, .. } => {
                    self.stats.want_sent += 1;
                    self.stats.want_ids_sent += validators.len() as u64;
                    self.stats.want_bytes_sent += bytes;
                    Kind::SyncControl
                }
                SyncRequest::Coded { .. } => {
                    self.stats.coded_sent += 1;
                    self.stats.coded_bytes_sent += bytes;
                    Kind::SyncPayload
                }
            };
            let pull = match &request {
                SyncRequest::Want { subnet, validators } => Some((*subnet, validators.clone())),
                _ => None,
            };
            let request_id = swarm.behaviour_mut().sync.send_request(&peer, request);
            if let Some(pull) = pull {
                self.pulls.insert(request_id, pull);
            }
            if let Some(meter) = meter.as_deref_mut() {
                meter.record(ts_ms, Direction::Out, kind, bytes, &peer_label(&peer));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn on_request(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        sync: &mut SigSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
        peer: PeerId,
        request: SyncRequest,
        channel: ResponseChannel<SyncResponse>,
        now: Instant,
        ts_ms: u64,
    ) -> Vec<Delivery> {
        let in_kind = match &request {
            SyncRequest::Coded { .. } => Kind::SyncPayload,
            _ => Kind::SyncControl,
        };
        if let Some(meter) = meter.as_deref_mut() {
            meter.record(
                ts_ms,
                Direction::In,
                in_kind,
                request.wire_bytes(),
                &peer_label(&peer),
            );
        }
        let mut deliveries = Vec::new();
        let response = match request {
            SyncRequest::Have { subnet, bitmap } => {
                sync.on_have(peer, subnet, &bitmap, now);
                SyncResponse::Ack
            }
            SyncRequest::Want { subnet, validators } => {
                let signatures: Vec<SyncSignature> = sync
                    .serve(subnet, &validators)
                    .into_iter()
                    .map(|held| SyncSignature {
                        validator_id: held.validator_id,
                        origin: held.origin,
                        payload: self.payload.clone(),
                    })
                    .collect();
                self.stats.pull_sigs_served += signatures.len() as u64;
                SyncResponse::Signatures { subnet, signatures }
            }
            SyncRequest::Coded { subnet, packet } => {
                self.stats.coded_received += 1;
                let outcome = sync.on_coded(subnet, &packet, now);
                self.stats.coded_innovative += u64::from(outcome.innovative);
                self.stats.coded_mismatches += u64::from(outcome.mismatches);
                self.stats.coded_decoded += outcome.decoded.len() as u64;
                deliveries.extend(outcome.decoded.into_iter().map(|held| Delivery {
                    subnet,
                    validator_id: held.validator_id,
                    origin: held.origin,
                    via: SigVia::Coded,
                    duplicate: false,
                    byte_size: 0,
                    from_peer: peer,
                }));
                SyncResponse::Ack
            }
        };
        let bytes = response.wire_bytes();
        let out_kind = match &response {
            SyncResponse::Ack => {
                self.stats.acks_sent += 1;
                Kind::SyncControl
            }
            SyncResponse::Signatures { .. } => {
                self.stats.pull_bytes_served += bytes;
                Kind::SyncPayload
            }
        };
        if let Some(meter) = meter.as_deref_mut() {
            meter.record(ts_ms, Direction::Out, out_kind, bytes, &peer_label(&peer));
        }
        let _ = swarm.behaviour_mut().sync.send_response(channel, response);
        deliveries
    }

    #[allow(clippy::too_many_arguments)]
    pub fn on_response(
        &mut self,
        sync: &mut SigSync<PeerId>,
        mut meter: Option<&mut TrafficMeter>,
        peer: PeerId,
        request_id: OutboundRequestId,
        response: SyncResponse,
        now: Instant,
        ts_ms: u64,
    ) -> Vec<Delivery> {
        let bytes = response.wire_bytes();
        if let Some(meter) = meter.as_deref_mut() {
            let kind = match &response {
                SyncResponse::Ack => Kind::SyncControl,
                SyncResponse::Signatures { .. } => Kind::SyncPayload,
            };
            meter.record(ts_ms, Direction::In, kind, bytes, &peer_label(&peer));
        }
        let Some((subnet, asked)) = self.pulls.remove(&request_id) else {
            return Vec::new();
        };
        let mut deliveries = Vec::new();
        if let SyncResponse::Signatures { signatures, .. } = response {
            for signature in signatures {
                self.stats.pulled_received += 1;
                let byte_size = crate::messages::sync::INDEX_BYTES + signature.payload.len() as u64;
                let held = sync.deliver(subnet, signature.validator_id, signature.origin, now);
                if held.is_empty() {
                    self.stats.pulled_duplicates += 1;
                    deliveries.push(Delivery {
                        subnet,
                        validator_id: signature.validator_id,
                        origin: signature.origin,
                        via: SigVia::Pull,
                        duplicate: true,
                        byte_size,
                        from_peer: peer,
                    });
                    continue;
                }
                for (k, held) in held.into_iter().enumerate() {
                    // The pulled signature first, then any it let the decoder finish.
                    let (via, byte_size) = if k == 0 {
                        (SigVia::Pull, byte_size)
                    } else {
                        self.stats.coded_decoded += 1;
                        (SigVia::Coded, 0)
                    };
                    deliveries.push(Delivery {
                        subnet,
                        validator_id: held.validator_id,
                        origin: held.origin,
                        via,
                        duplicate: false,
                        byte_size,
                        from_peer: peer,
                    });
                }
            }
        }
        sync.pull_done(subnet, &asked);
        deliveries
    }

    pub fn on_failure(&mut self, sync: &mut SigSync<PeerId>, request_id: OutboundRequestId) {
        self.stats.failures += 1;
        if let Some((subnet, asked)) = self.pulls.remove(&request_id) {
            sync.pull_done(subnet, &asked);
        }
    }

    /// The run's transport counters for this host, gossipsub control included.
    pub fn transport_stats(
        &self,
        node_id: u32,
        control: libp2p::gossipsub::ControlStats,
        pending_rows: usize,
    ) -> JsonlEvent {
        let s = self.stats;
        JsonlEvent::TransportStats {
            node_id,
            ihave_ids_sent: control.ihave_ids_sent,
            ihave_bytes_sent: control.ihave_bytes_sent,
            iwant_ids_sent: control.iwant_ids_sent,
            iwant_bytes_sent: control.iwant_bytes_sent,
            idontwant_ids_sent: control.idontwant_ids_sent,
            idontwant_bytes_sent: control.idontwant_bytes_sent,
            idontwant_ids_received: control.idontwant_ids_received,
            forwards_suppressed: control.forwards_suppressed,
            have_sent: s.have_sent,
            have_bytes_sent: s.have_bytes_sent,
            want_sent: s.want_sent,
            want_ids_sent: s.want_ids_sent,
            want_bytes_sent: s.want_bytes_sent,
            pull_sigs_served: s.pull_sigs_served,
            pull_bytes_served: s.pull_bytes_served,
            pulled_received: s.pulled_received,
            pulled_duplicates: s.pulled_duplicates,
            coded_sent: s.coded_sent,
            coded_bytes_sent: s.coded_bytes_sent,
            coded_received: s.coded_received,
            coded_innovative: s.coded_innovative,
            coded_decoded: s.coded_decoded,
            coded_mismatches: s.coded_mismatches,
            acks_sent: s.acks_sent,
            sync_failures: s.failures,
            pending_rows: pending_rows as u64,
        }
    }
}

fn peer_label(peer: &PeerId) -> String {
    format!("peer:{}", peer.to_base58())
}
