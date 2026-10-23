//! Executes [`ProofExchange`] actions on the proof protocol and logs each step.

use std::collections::HashMap;

use libp2p::request_response::{OutboundRequestId, ResponseChannel};
use libp2p::Swarm;
use tokio::time::Instant;

use crate::messages::proof::{ProofId, ProofRequest, ProofResponse};
use crate::metrics::events::{emit, JsonlEvent};
use crate::network::swarm::{peer_id_for, SimBehaviour};
use crate::node::recursive::{Action, ProofExchange};

pub struct ProofIo {
    node_id: u32,
    /// Stands in for a proof's bytes; every proof is this size.
    payload: Vec<u8>,
    /// Pulls in flight: request → (proof, host pulled from).
    pulls: HashMap<OutboundRequestId, (ProofId, u32)>,
}

impl ProofIo {
    pub fn new(node_id: u32, proof_bytes: usize) -> Self {
        Self {
            node_id,
            payload: vec![0; proof_bytes],
            pulls: HashMap::new(),
        }
    }

    pub fn execute(&mut self, swarm: &mut Swarm<SimBehaviour>, actions: Vec<Action>, ts_ms: u64) {
        for action in actions {
            match action {
                Action::Announce { to, proof } => {
                    let request = ProofRequest::Announce {
                        proof,
                        from: self.node_id,
                    };
                    swarm
                        .behaviour_mut()
                        .proofs
                        .send_request(&peer_id_for(to), request);
                    emit(&JsonlEvent::ProofAnnounced {
                        node_id: self.node_id,
                        to_id: to,
                        layer: proof.layer,
                        index: proof.index,
                        ts_ms,
                    });
                }
                Action::Fetch { from, proof } => {
                    let request = ProofRequest::Fetch {
                        proof,
                        from: self.node_id,
                    };
                    let request_id = swarm
                        .behaviour_mut()
                        .proofs
                        .send_request(&peer_id_for(from), request);
                    self.pulls.insert(request_id, (proof, from));
                    emit(&JsonlEvent::ProofRequested {
                        node_id: self.node_id,
                        from_id: from,
                        layer: proof.layer,
                        index: proof.index,
                        ts_ms,
                    });
                }
            }
        }
    }

    /// Acks an announcement (and maybe starts a pull) or serves a held proof.
    pub fn on_request(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        exchange: &mut ProofExchange,
        request: ProofRequest,
        channel: ResponseChannel<ProofResponse>,
        ts_ms: u64,
    ) {
        match request {
            ProofRequest::Announce { proof, from } => {
                let _ = swarm
                    .behaviour_mut()
                    .proofs
                    .send_response(channel, ProofResponse::Ack);
                let actions = exchange.announcement(proof, from);
                self.execute(swarm, actions, ts_ms);
            }
            ProofRequest::Fetch { proof, from } => {
                let response = if exchange.holds(proof) {
                    emit(&JsonlEvent::ProofServed {
                        node_id: self.node_id,
                        to_id: from,
                        layer: proof.layer,
                        index: proof.index,
                        ts_ms,
                        byte_size: self.payload.len() as u64,
                    });
                    ProofResponse::Proof {
                        proof,
                        from: self.node_id,
                        payload: self.payload.clone(),
                    }
                } else {
                    ProofResponse::Missing
                };
                let _ = swarm
                    .behaviour_mut()
                    .proofs
                    .send_response(channel, response);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn on_response(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        exchange: &mut ProofExchange,
        request_id: OutboundRequestId,
        response: ProofResponse,
        now: Instant,
        ts_ms: u64,
    ) {
        // Announcement acks carry nothing; only pulls are tracked.
        let Some((proof, from)) = self.pulls.remove(&request_id) else {
            return;
        };
        match response {
            ProofResponse::Proof { payload, .. } => {
                emit(&JsonlEvent::ProofFetched {
                    node_id: self.node_id,
                    from_id: from,
                    layer: proof.layer,
                    index: proof.index,
                    duplicate: exchange.holds(proof),
                    ts_ms,
                    byte_size: payload.len() as u64,
                });
                let actions = exchange.fetched(proof, now);
                self.execute(swarm, actions, ts_ms);
            }
            ProofResponse::Ack | ProofResponse::Missing => {
                self.pull_failed(swarm, exchange, proof, from, ts_ms)
            }
        }
    }

    pub fn on_failure(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        exchange: &mut ProofExchange,
        request_id: OutboundRequestId,
        ts_ms: u64,
    ) {
        if let Some((proof, from)) = self.pulls.remove(&request_id) {
            self.pull_failed(swarm, exchange, proof, from, ts_ms);
        }
    }

    fn pull_failed(
        &mut self,
        swarm: &mut Swarm<SimBehaviour>,
        exchange: &mut ProofExchange,
        proof: ProofId,
        from: u32,
        ts_ms: u64,
    ) {
        emit(&JsonlEvent::ProofFetchFailed {
            node_id: self.node_id,
            from_id: from,
            layer: proof.layer,
            index: proof.index,
            ts_ms,
        });
        let actions = exchange.fetch_failed(proof);
        self.execute(swarm, actions, ts_ms);
    }
}
