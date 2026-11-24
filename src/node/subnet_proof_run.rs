//! Single-round subnet proof transport benchmark. No signature traffic or proving.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAcceptance};
use libp2p::request_response::{self as rr, Message};
use libp2p::swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent};
use libp2p::{identity::PublicKey, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{interval_at, sleep_until, Instant, MissedTickBehavior};

use super::subnet_proof_waggle::{ProofWaggle, DRIVE_INTERVAL};
use super::subnet_proofs::{
    pieces, sign_commitment, Admission, Assembly, Piece, ProofKey, Pulls,
    COMMITMENT_SIGNATURE_BYTES,
};
use crate::config::experiment::{ExperimentConfig, NodeConfig};
use crate::network::swarm::{gossipsub_config, node_keypair, peer_id_for};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    AnnouncePull,
    Gossipsub,
    Eip8411,
    Waggle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    mode: Mode,
    release_ms: u64,
    stagger_ms: u64,
    /// No arm sends a commitment ahead any more: the piece arms carry it in every
    /// piece message. This only sets how long before the release the traffic count starts.
    commitment_lead_ms: u64,
    chunks: usize,
    producers: Vec<ProofKey>,
}

fn release_schedule(settings: &Settings, node_id: u32) -> BTreeSet<(u64, ProofKey)> {
    settings
        .producers
        .iter()
        .filter(|p| p.producer == node_id)
        .map(|&key| {
            let stagger = (u64::from(key.producer).wrapping_mul(2654435761)
                ^ u64::from(key.subnet))
                % (settings.stagger_ms + 1);
            (settings.release_ms + stagger, key)
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
enum Gossip {
    Proof(ProofKey, Vec<u8>),
    /// A piece with its Merkle path and its producer's signature over the root.
    Piece(#[serde(with = "serde_bytes")] Vec<u8>, Piece),
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Announce(ProofKey, u32),
    Fetch(ProofKey),
}

#[derive(Debug, Serialize, Deserialize)]
enum Response {
    Ack,
    Missing,
    Proof(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossip: gossipsub::Behaviour,
    pull: rr::cbor::Behaviour<Request, Response>,
    waggle: Toggle<waggle::behaviour::Behaviour>,
}

type ProofSwarm = Swarm<Behaviour>;

pub(super) fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(2 * 1024 * 1024)
        .reject_trailing_bytes()
}

fn log(event: serde_json::Value) {
    println!("{event}");
}

struct Run<'a> {
    cfg: &'a NodeConfig,
    settings: &'a Settings,
    start: Instant,
    topic: IdentTopic,

    assembly: Assembly,
    pulls: Pulls,
    whole: BTreeMap<ProofKey, Vec<u8>>,
    pending: HashMap<rr::OutboundRequestId, (ProofKey, u32)>,
    allowed: BTreeMap<ProofKey, PeerId>,
    keys: BTreeMap<ProofKey, PublicKey>,
    waggle: Option<ProofWaggle>,
}

impl Run<'_> {
    fn bytes(&self) -> usize {
        self.cfg.experiment.aggregate_proof_bytes
    }

    fn announce(&mut self, swarm: &mut ProofSwarm, key: ProofKey) {
        for peer in swarm.connected_peers().copied().collect::<Vec<_>>() {
            swarm
                .behaviour_mut()
                .pull
                .send_request(&peer, Request::Announce(key, self.cfg.node_id));
        }
    }

    fn complete(&self, key: ProofKey) {
        log(
            serde_json::json!({"event":"proof_complete", "node_id":self.cfg.node_id,
            "subnet":key.subnet, "producer":key.producer, "ms":self.start.elapsed().as_millis()}),
        );
    }

    fn hold(&mut self, swarm: &mut ProofSwarm, key: ProofKey, data: Vec<u8>) {
        if self.pulls.finish(key) {
            self.whole.insert(key, data);
            self.complete(key);
            self.announce(swarm, key);
        }
    }

    fn fetch(&mut self, swarm: &mut ProofSwarm, key: ProofKey, provider: Option<u32>) {
        if let Some(id) = provider {
            let request_id = swarm
                .behaviour_mut()
                .pull
                .send_request(&peer_id_for(id), Request::Fetch(key));
            self.pending.insert(request_id, (key, id));
        }
    }

    fn on_pull(&mut self, swarm: &mut ProofSwarm, event: rr::Event<Request, Response>) {
        match event {
            rr::Event::Message { peer, message } => match message {
                Message::Request {
                    request, channel, ..
                } => {
                    let response = match request {
                        Request::Announce(key, id) => {
                            if self.allowed.contains_key(&key)
                                && !self.pulls.holds(key)
                                && peer_id_for(id) == peer
                            {
                                let provider = self.pulls.announce(key, id);
                                self.fetch(swarm, key, provider);
                            }
                            Response::Ack
                        }
                        Request::Fetch(key) => self
                            .whole
                            .get(&key)
                            .cloned()
                            .map_or(Response::Missing, Response::Proof),
                    };
                    let _ = swarm.behaviour_mut().pull.send_response(channel, response);
                }
                Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some((key, id)) = self.pending.remove(&request_id) {
                        match response {
                            Response::Proof(data) if data.len() == self.bytes() => {
                                self.hold(swarm, key, data)
                            }
                            _ => {
                                let next = self.pulls.failed(key, id);
                                self.fetch(swarm, key, next);
                            }
                        }
                    }
                }
            },
            rr::Event::OutboundFailure { request_id, .. } => {
                if let Some((key, id)) = self.pending.remove(&request_id) {
                    let next = self.pulls.failed(key, id);
                    self.fetch(swarm, key, next);
                }
            }
            _ => {}
        }
    }

    fn publish(&self, swarm: &mut ProofSwarm, topic: &IdentTopic, message: Gossip) -> Result<()> {
        swarm
            .behaviour_mut()
            .gossip
            .publish(topic.clone(), codec().serialize(&message)?)
            .with_context(|| format!("node {} publishing {topic}", self.cfg.node_id))?;
        Ok(())
    }

    fn accept_piece(&mut self, signature: &[u8], piece: &Piece) -> MessageAcceptance {
        let Some(producer) = self.keys.get(&piece.key) else {
            return MessageAcceptance::Reject;
        };
        match self.assembly.admit(
            producer,
            signature,
            piece,
            self.settings.chunks,
            self.cfg.experiment.aggregate_proof_bytes,
        ) {
            Admission::Invalid => MessageAcceptance::Reject,
            // The relaying peer may hold the proof to the other signed root in good faith.
            Admission::Conflict => MessageAcceptance::Ignore,
            Admission::Held { complete } => {
                if complete {
                    self.complete(piece.key);
                }
                MessageAcceptance::Accept
            }
        }
    }

    fn on_gossip(
        &mut self,
        swarm: &mut ProofSwarm,
        peer: PeerId,
        id: gossipsub::MessageId,
        message: gossipsub::Message,
    ) {
        use MessageAcceptance::{Accept, Reject};
        let result = match codec().deserialize(&message.data) {
            Ok(Gossip::Proof(key, bytes))
                if self.settings.mode == Mode::Gossipsub
                    && message.topic == self.topic.hash()
                    && self.allowed.get(&key) == message.source.as_ref()
                    && message.source.is_some()
                    && bytes.len() == self.bytes() =>
            {
                self.complete(key);
                Accept
            }
            // Every piece message carries the root signature: a publisher cannot know
            // which receivers already hold it.
            Ok(Gossip::Piece(signature, piece))
                if self.settings.mode == Mode::Eip8411
                    && message.topic == self.topic.hash()
                    && self.allowed.get(&piece.key) == message.source.as_ref()
                    && message.source.is_some() =>
            {
                self.accept_piece(&signature, &piece)
            }
            _ => Reject,
        };
        report_validation(swarm, id, peer, result);
    }
}

fn report_validation(
    swarm: &mut ProofSwarm,
    id: gossipsub::MessageId,
    peer: PeerId,
    result: MessageAcceptance,
) {
    if let Err(err) = swarm
        .behaviour_mut()
        .gossip
        .report_message_validation_result(&id, &peer, result)
    {
        tracing::warn!(%err, "could not forward validated gossip");
    }
}

pub fn run(cfg: &NodeConfig, settings: &Settings) -> Result<()> {
    let experiment = &cfg.experiment;
    ensure!(
        (1..=256).contains(&settings.chunks) && settings.chunks.is_power_of_two(),
        "invalid proof chunk count"
    );
    ensure!(
        experiment.aggregate_proof_bytes <= 2 * 1024 * 1024 - 1024,
        "proof exceeds the experiment GossipSub bound"
    );
    ensure!(
        settings.commitment_lead_ms < settings.release_ms,
        "commitment must be sent after startup"
    );
    ensure!(
        settings.release_ms.saturating_add(settings.stagger_ms)
            < experiment.run_timeout_secs.saturating_mul(1000),
        "proof release exceeds run duration"
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_async(cfg, settings))
}

pub(super) fn prepare(key: ProofKey, config: &ExperimentConfig) -> Vec<u8> {
    let mut data = vec![0; config.aggregate_proof_bytes];
    let mut seed = Sha256::new();
    seed.update(config.geo_seed.to_le_bytes());
    seed.update(key.subnet.to_le_bytes());
    seed.update(key.producer.to_le_bytes());
    StdRng::from_seed(seed.finalize().into()).fill_bytes(&mut data);
    data
}

async fn run_async(cfg: &NodeConfig, settings: &Settings) -> Result<()> {
    let start = Instant::now();
    let experiment = &cfg.experiment;
    let key = node_keypair(cfg.node_id);
    let waggle_topic = format!("/leansim/{}/subnet-proof-waggle/1", experiment.run_id).into_bytes();
    let waggle = (settings.mode == Mode::Waggle).then(|| {
        waggle::behaviour::Behaviour::new(
            waggle::config::Config::default()
                .set_max_topic_subscription(1)
                .set_topic_whitelist(Some([waggle_topic.clone()].into()))
                .set_max_protobuf_size(
                    experiment.aggregate_proof_bytes.div_ceil(settings.chunks)
                        + COMMITMENT_SIGNATURE_BYTES
                        + 1024,
                ),
        )
    });
    // LeanSim signs all pubsub messages at the transport layer. At the application layer
    // a piece is accepted only if its Merkle path leads to a root its producer signed. On
    // GossipSub every piece carries that signature; on Waggle only a peer's first chunk does.
    let gossip = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config(experiment)?,
    )
    .map_err(anyhow::Error::msg)?;
    let pull = rr::cbor::Behaviour::new(
        [(
            StreamProtocol::new("/leansim/subnet-proof-bench/1"),
            rr::ProtocolSupport::Full,
        )],
        rr::Config::default().with_request_timeout(Duration::from_secs(10)),
    );
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| Behaviour {
            gossip,
            pull,
            waggle: waggle.into(),
        })?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(Duration::from_secs(experiment.run_timeout_secs + 10))
        })
        .build();
    let mut run = Run {
        cfg,
        settings,
        start,
        topic: IdentTopic::new(format!("/leansim/{}/subnet-proof", experiment.run_id)),
        assembly: Assembly::default(),
        pulls: Pulls::default(),
        whole: BTreeMap::new(),
        pending: HashMap::new(),
        allowed: settings
            .producers
            .iter()
            .map(|&key| (key, peer_id_for(key.producer)))
            .collect(),
        keys: settings
            .producers
            .iter()
            .map(|&key| (key, node_keypair(key.producer).public()))
            .collect(),
        waggle: (settings.mode == Mode::Waggle).then(|| {
            ProofWaggle::new(
                cfg.node_id,
                experiment.geo_seed,
                settings.chunks,
                experiment.aggregate_proof_bytes,
                waggle_topic.clone(),
                settings.producers.iter().copied(),
            )
        }),
    };
    let waggle_rx = swarm
        .behaviour_mut()
        .waggle
        .as_mut()
        .map(|w| w.subscribe(waggle_topic).expect("new proof topic"));
    if matches!(settings.mode, Mode::Gossipsub | Mode::Eip8411) {
        swarm.behaviour_mut().gossip.subscribe(&run.topic)?;
    }
    swarm.listen_on(cfg.listen_addr.parse()?)?;
    for address in &cfg.seed_addrs {
        swarm.dial(address.parse::<Multiaddr>()?)?;
    }
    // Release times are independent of network mode and stagger by producer duty.
    let mut releases = release_schedule(settings, cfg.node_id);

    let timeout = experiment.run_timeout_secs * 1000;
    let mut sent_before = None;
    let measure_at = settings.release_ms - settings.commitment_lead_ms;
    let mut drive = interval_at(start + Duration::from_millis(measure_at), DRIVE_INTERVAL);
    drive.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let due = releases.first().map_or(timeout, |k| k.0);
        let due = if sent_before.is_none() {
            due.min(measure_at)
        } else {
            due
        };
        tokio::select! {
            biased;
            _ = sleep_until(start + Duration::from_millis(due)) => {
                if sent_before.is_none() && due == measure_at {
                    sent_before = Some(zero_copy_write::stats());
                }
                if due == timeout { break; }
                while releases.first().is_some_and(|k| k.0 == due) {
                    let (_, key) = releases.pop_first().expect("due release");
                    log(serde_json::json!({"event":"proof_release", "node_id":cfg.node_id,
                        "subnet":key.subnet, "producer":key.producer, "ms":start.elapsed().as_millis()}));
                    let neighbours = swarm.connected_peers().count();
                    if neighbours == 0 { bail!("producer {} has no connected peers at release", cfg.node_id); }
                    match settings.mode {
                        Mode::AnnouncePull => run.hold(&mut swarm, key, prepare(key, experiment)),
                        Mode::Gossipsub => {
                            run.publish(&mut swarm, &run.topic, Gossip::Proof(key, prepare(key, experiment)))?;
                            run.complete(key);
                        }
                        Mode::Eip8411 => {
                            let (root, chunks) = pieces(key, &prepare(key, experiment), settings.chunks);
                            let signature = sign_commitment(&node_keypair(cfg.node_id), key, root)?;
                            for piece in chunks {
                                run.publish(&mut swarm, &run.topic, Gossip::Piece(signature.clone(), piece))?;
                            }
                            run.complete(key);
                        }
                        Mode::Waggle => {
                            let (root, chunks) = pieces(key, &prepare(key, experiment), settings.chunks);
                            run.waggle.as_mut().expect("Waggle mode").release(key, root, chunks)?;
                            run.complete(key);
                        }
                    }
                }
            }
            _ = drive.tick(), if waggle_rx.is_some() => {
                run.waggle.as_mut().expect("Waggle mode").drive();
            }
            Ok(event) = async { waggle_rx.as_ref().expect("Waggle mode").recv().await }, if waggle_rx.is_some() => {
                if let Some(key) = run.waggle.as_mut().expect("Waggle mode").on_topic(event) {
                    run.complete(key);
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, num_established, .. } => {
                    if settings.mode == Mode::AnnouncePull && num_established.get() == 1 {
                        for key in run.whole.keys().copied() {
                            swarm.behaviour_mut().pull.send_request(&peer_id, Request::Announce(key, cfg.node_id));
                        }
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, .. } => {
                    if let Some(waggle) = &mut run.waggle {
                        waggle.disconnected(peer_id, connection_id);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Waggle(event)) => {
                    run.waggle.as_mut().expect("Waggle mode").on_behaviour(event);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Pull(event)) if settings.mode == Mode::AnnouncePull => run.on_pull(&mut swarm, event),
                SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Message { propagation_source, message_id, message })) => {
                    run.on_gossip(&mut swarm, propagation_source, message_id, message);
                }
                _ => {}
            }
        }
    }
    let after = zero_copy_write::stats();
    let before = sent_before.context("measurement never started")?;
    let signatures = run.waggle.as_ref().map_or([0; 2], ProofWaggle::signatures);
    log(
        serde_json::json!({"event":"proof_traffic", "node_id":cfg.node_id,
        "bytes":after.shared_bytes + after.copied_bytes - before.shared_bytes - before.copied_bytes,
        "peers":swarm.connected_peers().count(),
        "pending_fetches":run.waggle.as_ref().map_or(run.pending.len(), ProofWaggle::pending),
        "chunks_unsigned":signatures[0], "chunks_signed":signatures[1]}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_sent_ahead_of_a_release() {
        let key = ProofKey {
            subnet: 2,
            producer: 7,
        };
        for mode in [
            Mode::AnnouncePull,
            Mode::Gossipsub,
            Mode::Eip8411,
            Mode::Waggle,
        ] {
            let settings = Settings {
                mode,
                release_ms: 5000,
                stagger_ms: 0,
                commitment_lead_ms: 500,
                chunks: 64,
                producers: vec![key],
            };
            assert_eq!(
                release_schedule(&settings, 7)
                    .into_iter()
                    .collect::<Vec<_>>(),
                vec![(5000, key)]
            );
            assert!(release_schedule(&settings, 8).is_empty());
        }
    }
}
