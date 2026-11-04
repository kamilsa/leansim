use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use libp2p::Swarm;

use leansim::config::experiment::{NodeConfig, NodeRole, SignatureSync};
use leansim::config::plan::AggregationPlan;
use leansim::messages::proof::ProofId;
use leansim::messages::wire::WireMessage;
use leansim::metrics::events::{emit, JsonlEvent, SigVia};
use leansim::metrics::traffic::{Bucket, Direction, Kind, TrafficMeter};
use leansim::network::swarm::{peer_id_for, NetEvent, ReceivedMessage, SimBehaviour};
use leansim::node::proof_io::ProofIo;
use leansim::node::recursive::ProofExchange;
use leansim::node::sigsync::{SigSync, SyncSettings};
use leansim::node::state::NodeState;
use leansim::node::sync_io::{Delivery, SyncIo};

#[derive(Parser)]
#[command(
    name = "lean-sim",
    author,
    version,
    about = "leanSim: Signature aggregation network simulator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a single simulated node.
    Node {
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Node { config } => run_node(config).await,
    }
}

async fn run_node(config_path: PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(&config_path)?;
    let node_config: NodeConfig =
        toml::from_str(&content).map_err(|e| anyhow::anyhow!("invalid node config: {e}"))?;
    node_config
        .experiment
        .validate()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let state = Arc::new(
        NodeState::new(
            node_config.node_id,
            node_config.role,
            node_config.subnet_id,
            node_config.experiment.clone(),
        )
        .with_validator_ids(node_config.signing_validator_ids())
        .with_subscribed_subnets(node_config.subscribed_subnets.clone())
        .with_aggregated_subnets(node_config.aggregated_subnets()),
    );
    let signing_subnets = state.signing_subnets();
    let subscribed_subnets = state.subscribed_subnets();
    let mut explicit_peers = leansim::network::swarm::ExplicitPeerManager::new(
        &node_config.explicit_peer_addrs,
        &node_config.selected_aggregator_addrs,
    )?;

    let mut swarm = leansim::network::swarm::build_swarm(
        node_config.node_id,
        &node_config.listen_addr,
        &node_config.experiment,
    )?;

    leansim::network::swarm::subscribe_to_topics(
        &mut swarm,
        &state.aggregated_subnets,
        &subscribed_subnets,
        &node_config.experiment.run_id,
    )?;

    emit(&JsonlEvent::NodePeerId {
        node_id: state.node_id,
        peer_id: swarm.local_peer_id().to_base58(),
    });

    // Proof duties from the launcher's plan. The hosts this one announces to are
    // dialed with the seeds, so their connections are up before the first proof.
    let plan = node_config
        .aggregation_plan
        .as_deref()
        .map(AggregationPlan::load)
        .transpose()?;
    let duties = plan
        .as_ref()
        .map(|plan| plan.duties_of(node_config.node_id))
        .unwrap_or_default();
    let mut dial_addrs = node_config.seed_addrs.clone();
    if let Some(plan) = &plan {
        for peer in duties.peers() {
            let addr = plan.addrs.get(&peer).ok_or_else(|| {
                anyhow::anyhow!("aggregation plan has no address for node {peer}")
            })?;
            swarm.add_peer_address(peer_id_for(peer), addr.parse()?);
            dial_addrs.push(addr.clone());
        }
    }
    let experiment = &node_config.experiment;
    let mut exchange = ProofExchange::new(
        duties,
        experiment.recursive_proofs_per_child,
        Duration::from_millis(experiment.recursive_aggregation_time_ms),
    );
    let mut proof_io = ProofIo::new(state.node_id, experiment.aggregate_proof_bytes);
    // Signature sync tracks every subnet this host hears gossip on.
    let mut sync: SigSync<libp2p::PeerId> = SigSync::new(
        SyncSettings::from_config(experiment),
        subscribed_subnets.union(&state.aggregated_subnets).copied(),
        u64::from(state.node_id),
    );
    let mut sync_io = SyncIo::new(experiment.signature_payload_bytes);
    let sync_interval = Duration::from_millis(experiment.sync_interval_ms.max(1));
    // Traffic logs only on the hosts the launcher flags, so the rest stay untouched.
    let mut meter = node_config
        .traffic_log
        .then(|| TrafficMeter::new(experiment.traffic_log_bucket_ms));

    let selected_aggregator_topics: Vec<_> = signing_subnets
        .iter()
        .map(|&subnet| {
            libp2p::gossipsub::IdentTopic::new(leansim::network::topics::subnet_topic(
                &node_config.experiment.run_id,
                subnet,
            ))
        })
        .collect();
    leansim::network::swarm::dial_seeds(
        &mut swarm,
        &dial_addrs,
        &mut explicit_peers,
        &selected_aggregator_topics,
        node_config.experiment.mesh_warmup_ms,
    )
    .await?;

    if !state.validator_ids.is_empty() {
        leansim::node::validator::validator_init(&state, &mut swarm).await?;
        let now = tokio::time::Instant::now();
        for &validator_id in &state.validator_ids {
            let subnet = state.config.subnet_for_validator(validator_id);
            sync.deliver(subnet, validator_id, state.node_id, now);
        }
    }
    if node_config.role == NodeRole::LocalAggregator {
        leansim::node::local_aggregator::record_own_signatures(&state);
    }

    let timeout = Duration::from_secs(node_config.experiment.run_timeout_secs);
    let end = tokio::time::Instant::now() + timeout;
    let mut next_sync =
        (sync.mode() != SignatureSync::None).then(|| tokio::time::Instant::now() + sync_interval);

    loop {
        if tokio::time::Instant::now() >= end {
            break;
        }
        // Wake for the next message, the next proof to finish, or the end of the run.
        let wake = [state.next_proof_due(), exchange.next_due(), next_sync]
            .into_iter()
            .flatten()
            .min()
            .map_or(end, |due| due.min(end));
        let event = tokio::time::timeout_at(
            wake,
            leansim::network::swarm::next_event(&mut swarm, &mut explicit_peers),
        )
        .await;

        match event {
            Ok(Some(NetEvent::Gossip(received))) => {
                handle_signature(&state, &swarm, &mut sync, meter.as_mut(), received)
            }
            Ok(Some(NetEvent::SyncRequest {
                peer,
                request,
                channel,
            })) => {
                let deliveries = sync_io.on_request(
                    &mut swarm,
                    &mut sync,
                    meter.as_mut(),
                    peer,
                    request,
                    channel,
                    tokio::time::Instant::now(),
                    state.elapsed_ms(),
                );
                record_deliveries(&state, deliveries);
            }
            Ok(Some(NetEvent::SyncResponse {
                peer,
                request_id,
                response,
            })) => {
                let deliveries = sync_io.on_response(
                    &mut sync,
                    meter.as_mut(),
                    peer,
                    request_id,
                    response,
                    tokio::time::Instant::now(),
                    state.elapsed_ms(),
                );
                record_deliveries(&state, deliveries);
            }
            Ok(Some(NetEvent::SyncFailed { request_id })) => {
                sync_io.on_failure(&mut sync, request_id)
            }
            Ok(Some(NetEvent::ProofRequest { request, channel })) => proof_io.on_request(
                &mut swarm,
                &mut exchange,
                meter.as_mut(),
                request,
                channel,
                state.elapsed_ms(),
            ),
            Ok(Some(NetEvent::ProofResponse {
                request_id,
                response,
            })) => proof_io.on_response(
                &mut swarm,
                &mut exchange,
                meter.as_mut(),
                request_id,
                response,
                tokio::time::Instant::now(),
                state.elapsed_ms(),
            ),
            Ok(Some(NetEvent::ProofFailed { request_id })) => proof_io.on_failure(
                &mut swarm,
                &mut exchange,
                meter.as_mut(),
                request_id,
                state.elapsed_ms(),
            ),
            Ok(None) => break,
            // A proof came due or the run ended; handled below / at the loop top.
            Err(_elapsed) => {}
        }

        let now = tokio::time::Instant::now();
        if let Some(due) = next_sync.filter(|due| *due <= now) {
            let run_id = &state.config.run_id;
            let gossipsub = &swarm.behaviour().gossipsub;
            let actions = sync.tick(now, |subnet| {
                let topic = libp2p::gossipsub::IdentTopic::new(
                    leansim::network::topics::subnet_topic(run_id, subnet),
                );
                gossipsub.mesh_peers(&topic.hash()).copied().collect()
            });
            sync_io.execute(&mut swarm, meter.as_mut(), actions, state.elapsed_ms());
            // Skip ticks missed while busy rather than bursting to catch up.
            next_sync = Some((due + sync_interval).max(now));
        }
        for proof in leansim::node::local_aggregator::complete_due_proofs(&state) {
            let actions = exchange.proof_ready(ProofId::subnet(proof.subnet), now);
            proof_io.execute(&mut swarm, meter.as_mut(), actions, state.elapsed_ms());
        }
        for done in exchange.take_due(now) {
            emit(&JsonlEvent::RecursiveProofGenerated {
                node_id: state.node_id,
                layer: done.proof.layer,
                index: done.proof.index,
                inputs: done.inputs,
                is_final: done.is_final,
                ts_ms: state.elapsed_ms(),
            });
            let actions = exchange.proof_ready(done.proof, now);
            proof_io.execute(&mut swarm, meter.as_mut(), actions, state.elapsed_ms());
        }
        if let Some(meter) = meter.as_mut() {
            for bucket in meter.drain_due(state.elapsed_ms()) {
                emit_bucket(&state, bucket);
            }
        }
    }

    if let Some(meter) = meter.as_mut() {
        for bucket in meter.finish() {
            emit_bucket(&state, bucket);
        }
        for (peer, totals) in meter.peers() {
            emit(&JsonlEvent::TrafficPeer {
                node_id: state.node_id,
                peer: peer.clone(),
                inbound_bytes: totals.inbound_bytes,
                outbound_bytes: totals.outbound_bytes,
                inbound_msgs: totals.inbound_msgs,
                outbound_msgs: totals.outbound_msgs,
            });
        }
    }

    emit(&sync_io.transport_stats(
        state.node_id,
        swarm.behaviour().gossipsub.control_stats(),
        sync.pending_rows(),
    ));
    emit(&JsonlEvent::NodeStats {
        node_id: state.node_id,
        bytes_sent: state.bytes_sent_sig.load(Ordering::Relaxed),
        bytes_received: state.bytes_recv_sig.load(Ordering::Relaxed),
        msgs_sent: state.msgs_sent_sig.load(Ordering::Relaxed),
        msgs_received: state.msgs_recv_sig.load(Ordering::Relaxed),
    });

    let writes = zero_copy_write::stats();
    eprintln!(
        "QUIC send buffers: {} bytes shared with gossipsub, {} bytes copied",
        writes.shared_bytes, writes.copied_bytes
    );

    tracing::info!("node {} exiting", state.node_id);
    Ok(())
}

/// Logs signatures the sync protocol delivered and feeds them to local aggregation.
fn record_deliveries(state: &NodeState, deliveries: Vec<Delivery>) {
    let ts_ms = state.elapsed_ms();
    for delivery in deliveries {
        emit(&JsonlEvent::SigReceived {
            node_id: state.node_id,
            from_id: delivery.origin,
            validator_id: Some(delivery.validator_id),
            from_peer_id: delivery.from_peer.to_base58(),
            subnet_id: delivery.subnet,
            duplicate: delivery.duplicate,
            ts_ms,
            byte_size: delivery.byte_size,
            via: delivery.via,
        });
        if !delivery.duplicate && state.role == NodeRole::LocalAggregator {
            leansim::node::local_aggregator::record_signature(
                state,
                delivery.subnet,
                delivery.validator_id,
            );
        }
    }
}

/// Counts one gossiped signature, unique or duplicate, and feeds local aggregation.
/// A signature already held through the sync protocol counts as a duplicate.
/// On a traffic-logging host it also records the bytes, incoming per forwarding
/// peer and outgoing per mesh peer it estimates a forward to.
fn handle_signature(
    state: &NodeState,
    swarm: &Swarm<SimBehaviour>,
    sync: &mut SigSync<libp2p::PeerId>,
    mut meter: Option<&mut TrafficMeter>,
    received: ReceivedMessage,
) {
    let wire_msg = received.wire_msg;
    let from_peer_str = received.from_peer.to_base58();
    let msg_id = wire_msg.message_id();
    let WireMessage::ValidatorSignature {
        sender_id,
        validator_id,
        subnet_id,
        ..
    } = &wire_msg;
    // Signatures this one let the decoder finish, after itself.
    let mut decoded = Vec::new();
    let mut is_dup = received.is_duplicate;
    if !is_dup && sync.tracks(*subnet_id) {
        let held = sync.deliver(
            *subnet_id,
            *validator_id,
            *sender_id,
            tokio::time::Instant::now(),
        );
        is_dup = held.is_empty();
        decoded.extend(held.into_iter().skip(1));
    }
    if !received.is_duplicate {
        state.mark_seen(msg_id);
    }

    let size = wire_msg.encode().len() as u64;
    // Mesh_n configured, D_lazy ≈ ceil(sqrt(mesh_n))
    let d_lazy = ((state.config.gossipsub_mesh_n as f64).sqrt().ceil() as u64).max(1);
    let ts_ms = state.elapsed_ms();
    if let Some(meter) = meter.as_deref_mut() {
        let included = if is_dup {
            Kind::DuplicateSignature
        } else {
            Kind::Signature
        };
        meter.record(
            ts_ms,
            Direction::In,
            included,
            size,
            &format!("peer:{from_peer_str}"),
        );
        // Gossipsub forwards whatever is new to it, even if sync delivered it first.
        if !received.is_duplicate {
            for peer in forwarding_peers(swarm, &state.config.run_id, *subnet_id, d_lazy) {
                meter.record(ts_ms, Direction::Out, Kind::Signature, size, &peer);
            }
        }
    }
    // Track download bandwidth (both unique and duplicate)
    state.bytes_recv_sig.fetch_add(size, Ordering::Relaxed);
    state.msgs_recv_sig.fetch_add(1, Ordering::Relaxed);
    emit(&JsonlEvent::SigReceived {
        node_id: state.node_id,
        from_id: *sender_id,
        validator_id: Some(*validator_id),
        from_peer_id: from_peer_str,
        subnet_id: *subnet_id,
        duplicate: is_dup,
        ts_ms,
        byte_size: size,
        via: SigVia::Gossip,
    });
    // Approximate lazy gossip traffic. Full-message forwarding to mesh and
    // explicit peers is not observable at this layer.
    if !received.is_duplicate {
        state
            .bytes_sent_sig
            .fetch_add(size * d_lazy, Ordering::Relaxed);
        state.msgs_sent_sig.fetch_add(d_lazy, Ordering::Relaxed);
    }

    if state.role == NodeRole::LocalAggregator {
        leansim::node::local_aggregator::handle_message(state, &wire_msg);
    }
    record_deliveries(
        state,
        decoded
            .into_iter()
            .map(|held| Delivery {
                subnet: *subnet_id,
                validator_id: held.validator_id,
                origin: held.origin,
                via: SigVia::Coded,
                duplicate: false,
                byte_size: 0,
                from_peer: received.from_peer,
            })
            .collect(),
    );
}

/// The mesh peers a unique signature on `subnet` would be forwarded to, up to the
/// lazy fan-out. The gossip layer does not expose forwards, so a traffic log
/// attributes one copy to each mesh peer it can see.
fn forwarding_peers(
    swarm: &Swarm<SimBehaviour>,
    run_id: &str,
    subnet: u32,
    copies: u64,
) -> Vec<String> {
    let topic =
        libp2p::gossipsub::IdentTopic::new(leansim::network::topics::subnet_topic(run_id, subnet));
    swarm
        .behaviour()
        .gossipsub
        .mesh_peers(&topic.hash())
        .take(copies as usize)
        .map(|peer| format!("peer:{}", peer.to_base58()))
        .collect()
}

fn emit_bucket(state: &NodeState, bucket: Bucket) {
    emit(&JsonlEvent::TrafficBucket {
        node_id: state.node_id,
        start_ms: bucket.start_ms,
        width_ms: bucket.width_ms,
        inbound: bucket
            .inbound
            .iter()
            .map(|(kind, bytes)| (kind.as_str().to_string(), *bytes))
            .collect(),
        outbound: bucket
            .outbound
            .iter()
            .map(|(kind, bytes)| (kind.as_str().to_string(), *bytes))
            .collect(),
    });
}
