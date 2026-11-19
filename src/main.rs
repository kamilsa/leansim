use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use libp2p::Swarm;

use leansim::config::experiment::{NodeConfig, NodeRole, SignatureSync, SignatureTransport};
use leansim::config::plan::AggregationPlan;
use leansim::messages::proof::ProofId;
use leansim::messages::wire::WireMessage;
use leansim::metrics::events::{emit, JsonlEvent, MeshSample, SigVia};
use leansim::metrics::traffic::{Bucket, Direction, Kind, TrafficMeter};
use leansim::network::swarm::{peer_id_for, NetEvent, ReceivedMessage, SimBehaviour};
use leansim::node::bundle_io::BundleIo;
use leansim::node::bundles::{next_tick, BundleSettings, BundleSync};
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
    /// Run a node in the proof-only dissemination benchmark.
    SubnetProof {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        settings: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Node { config } => run_node(config),
        Command::SubnetProof { config, settings } => {
            let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(config)?)?;
            cfg.experiment.validate().map_err(anyhow::Error::msg)?;
            let settings = serde_json::from_reader(std::fs::File::open(settings)?)?;
            leansim::node::subnet_proof_run::run(&cfg, &settings)
        }
    }
}

/// How long a host waits before it pushes again what a peer's full send queue
/// turned away.
const SEND_RETRY: Duration = Duration::from_millis(20);

/// What a host keeps across the sessions churn cuts its run into: its
/// measurements, and whether its validators have had their turn to sign.
struct Carry {
    start: std::time::Instant,
    /// How long after the warmup this host signs.
    burst: Duration,
    /// The host signed, or was offline when it should have.
    signing_done: bool,
    /// How far into the run the host's turn to sign came. A host that is online
    /// at the end of the run stays that much longer, so every host has
    /// `run_timeout_secs` after signing, as it has without churn.
    signing_at: Duration,
    sessions: u32,
    meter: Option<TrafficMeter>,
    bytes_sent: u64,
    bytes_received: u64,
    msgs_sent: u64,
    msgs_received: u64,
}

/// One stretch online.
struct Session {
    until: tokio::time::Instant,
    /// The host was offline when the run started or has been since.
    late: bool,
    /// The session lasts until the end of the run.
    last: bool,
}

/// Runs the host for the length of the run: one session without churn, and
/// with it one per stretch online. Each session has a runtime of its own, and
/// going offline drops it with every socket and task of the session, so a crash
/// sends nothing and leaves nothing behind.
fn run_node(config_path: PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(&config_path)?;
    let node_config: NodeConfig =
        toml::from_str(&content).map_err(|e| anyhow::anyhow!("invalid node config: {e}"))?;
    let experiment = &node_config.experiment;
    experiment.validate().map_err(|e| anyhow::anyhow!("{e}"))?;

    let node_id = node_config.node_id;
    let start = std::time::Instant::now();
    let elapsed_ms = || start.elapsed().as_millis() as u64;
    let sleep_until = |ms: u64| {
        let at = start + Duration::from_millis(ms);
        std::thread::sleep(at.saturating_duration_since(std::time::Instant::now()));
    };
    emit(&JsonlEvent::NodePeerId {
        node_id,
        peer_id: peer_id_for(node_id).to_base58(),
    });

    let mut carry = Carry {
        start,
        burst: leansim::node::validator::burst_delay(experiment),
        signing_done: false,
        signing_at: Duration::ZERO,
        sessions: 0,
        // Traffic logs only on the hosts the launcher flags, so the rest stay untouched.
        meter: node_config
            .traffic_log
            .then(|| TrafficMeter::new(experiment.traffic_log_bucket_ms)),
        bytes_sent: 0,
        bytes_received: 0,
        msgs_sent: 0,
        msgs_received: 0,
    };
    let run_ms = experiment.run_timeout_secs * 1000;
    let windows = node_config.online_windows(run_ms);
    if !windows.first().is_some_and(|&(from_ms, _)| from_ms == 0) {
        emit(&JsonlEvent::Churn {
            node_id,
            online: false,
            ts_ms: 0,
        });
    }
    for &(from_ms, until_ms) in &windows {
        sleep_until(from_ms);
        if from_ms > 0 {
            emit(&JsonlEvent::Churn {
                node_id,
                online: true,
                ts_ms: elapsed_ms(),
            });
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let session = Session {
            until: tokio::time::Instant::from_std(start + Duration::from_millis(until_ms)),
            late: from_ms > 0,
            last: until_ms >= run_ms,
        };
        runtime.block_on(run_session(&node_config, &mut carry, session))?;
        drop(runtime);
        if until_ms < run_ms {
            emit(&JsonlEvent::Churn {
                node_id,
                online: false,
                ts_ms: elapsed_ms(),
            });
        }
    }
    sleep_until(run_ms + carry.signing_at.as_millis() as u64);

    if let Some(meter) = carry.meter.as_mut() {
        for bucket in meter.finish() {
            emit_bucket(node_id, bucket);
        }
        for (peer, totals) in meter.peers() {
            emit(&JsonlEvent::TrafficPeer {
                node_id,
                peer: peer.clone(),
                inbound_bytes: totals.inbound_bytes,
                outbound_bytes: totals.outbound_bytes,
                inbound_msgs: totals.inbound_msgs,
                outbound_msgs: totals.outbound_msgs,
            });
        }
    }
    emit(&JsonlEvent::NodeStats {
        node_id,
        bytes_sent: carry.bytes_sent,
        bytes_received: carry.bytes_received,
        msgs_sent: carry.msgs_sent,
        msgs_received: carry.msgs_received,
    });

    let writes = zero_copy_write::stats();
    eprintln!(
        "QUIC send buffers: {} bytes shared with gossipsub, {} bytes copied",
        writes.shared_bytes, writes.copied_bytes
    );

    tracing::info!("node {node_id} exiting");
    Ok(())
}

/// One session: the host from joining the network, with no state but its
/// config, until it crashes or the run ends.
async fn run_session(node_config: &NodeConfig, carry: &mut Carry, session: Session) -> Result<()> {
    let joined = std::time::SystemTime::now();
    let state = Arc::new(
        NodeState::new(
            node_config.node_id,
            node_config.role,
            node_config.subnet_id,
            node_config.experiment.clone(),
        )
        .with_start(carry.start)
        .with_validator_ids(node_config.signing_validator_ids())
        .with_subscribed_subnets(node_config.subscribed_subnets.clone())
        .with_aggregated_subnets(node_config.aggregated_subnets()),
    );
    let signing_subnets = state.signing_subnets();
    let subscribed_subnets = state.subscribed_subnets();
    // Signatures travel as bundles: over gossipsub partial messages, or over
    // waggle, where a bundle holds a single signature without `waggle_bundled`.
    let bundled = node_config.experiment.bundles_enabled();
    let waggle = node_config.experiment.signature_transport == SignatureTransport::Waggle;
    // Bundles track every subnet this host hears or signs in; a subnet it only signs
    // in is pushed to fanout peers.
    let bundle_subnets: Vec<u32> = subscribed_subnets
        .iter()
        .chain(&state.aggregated_subnets)
        .chain(&signing_subnets)
        .copied()
        .collect::<std::collections::BTreeSet<u32>>()
        .into_iter()
        .collect();
    let mut explicit_peers = leansim::network::swarm::ExplicitPeerManager::new(
        &node_config.explicit_peer_addrs,
        &node_config.selected_aggregator_addrs,
    )?;

    let mut swarm = leansim::network::swarm::build_swarm(
        node_config.node_id,
        &node_config.listen_addr,
        &node_config.experiment,
    )?;

    if waggle {
        leansim::network::swarm::track_waggle_subnets(&mut swarm, bundle_subnets.iter().copied());
    } else if bundled {
        leansim::network::swarm::enable_partial_topics(
            &mut swarm,
            bundle_subnets.iter().copied(),
            &node_config.experiment.run_id,
        );
    }
    leansim::network::swarm::subscribe_to_topics(
        &mut swarm,
        &state.aggregated_subnets,
        &subscribed_subnets,
        &node_config.experiment.run_id,
    )?;

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
    // A host that joins after the run started was not there for its peers'
    // dials, so it dials its whole peer table. One back from a crash also tells
    // every peer, which may still hold a connection to its previous session.
    if session.late {
        dial_addrs.extend(node_config.inbound_peer_addrs.iter().cloned());
    }
    if carry.sessions > 0 {
        explicit_peers.announce_restart(joined);
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
    if session.late {
        sync = sync.advertising_empty();
    }
    let mut sync_io = SyncIo::new(experiment.signature_payload_bytes);
    let sync_interval = Duration::from_millis(experiment.sync_interval_ms.max(1));
    let bundle_settings = BundleSettings::from_config(experiment);
    let mut bundles: BundleSync<libp2p::PeerId> =
        BundleSync::new(bundle_settings, bundle_subnets.iter().copied())
            .with_local(*swarm.local_peer_id());
    // Subnets this host is in the mesh of; the rest of its bundle subnets are publish-only.
    let mesh_subnets: std::collections::BTreeSet<u32> = subscribed_subnets
        .union(&state.aggregated_subnets)
        .copied()
        .collect();
    let mut bundle_io = BundleIo::new(experiment, bundle_subnets.iter().copied())
        .with_publish_only(
            bundle_subnets
                .iter()
                .copied()
                .filter(|subnet| !mesh_subnets.contains(subnet)),
        );
    let bundle_tick = Duration::from_millis(experiment.push_tick_ms());
    // Each host's tick clock has its own phase, as real hosts' would.
    let run_start = tokio::time::Instant::from_std(carry.start);
    let bundle_anchor = {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(u64::from(state.node_id));
        let offset_ms = rng.gen_range(0..experiment.push_tick_ms().max(1));
        run_start + Duration::from_millis(offset_ms)
    };
    // The next tick with signatures to push; None while there are none.
    let mut next_bundle_tick: Option<tokio::time::Instant> = None;
    // Signatures received and bytes they took, for NodeStats in bundled mode.
    let (mut bundle_recv_bytes, mut bundle_recv_msgs) = (0u64, 0u64);
    let mut meter = carry.meter.take();

    let selected_aggregator_topics: Vec<_> = signing_subnets
        .iter()
        .map(|&subnet| {
            libp2p::gossipsub::IdentTopic::new(leansim::network::topics::subnet_topic(
                &node_config.experiment.run_id,
                subnet,
            ))
        })
        .collect();
    let dialed = leansim::network::swarm::dial_peers(&mut swarm, &dial_addrs, &explicit_peers)?;
    let warmup = Duration::from_millis(leansim::network::swarm::warmup_ms(
        dialed,
        experiment.mesh_warmup_ms,
    ));
    // The warmup is a stretch of the run, not of the session: a host that joins
    // during it warms up for what is left, and one that joins later not at all.
    let warmup_end = run_start + warmup;
    let warmed = tokio::time::Instant::now() < warmup_end;
    if warmed {
        leansim::network::swarm::poll_warmup(
            &mut swarm,
            &mut explicit_peers,
            warmup_end.min(session.until),
        )
        .await;
        if tokio::time::Instant::now() < session.until {
            leansim::network::swarm::await_selected_aggregators(
                &mut swarm,
                &mut explicit_peers,
                &selected_aggregator_topics,
                warmup,
            )
            .await?;
            tracing::info!("mesh warmup complete");
        }
    }

    // The host's turn to sign comes `burst` after the warmup, or at its end for
    // a host without validators. A host that is offline then misses the slot.
    let now = tokio::time::Instant::now();
    if !carry.signing_done && now < session.until {
        let signs = !state.validator_ids.is_empty();
        let after_warmup = if warmed { now } else { warmup_end };
        let sign_at = if signs {
            after_warmup + carry.burst
        } else {
            after_warmup
        };
        if now > sign_at {
            carry.signing_done = true;
            carry.signing_at = sign_at.saturating_duration_since(run_start);
        } else {
            if signs {
                tokio::time::sleep_until(sign_at.min(session.until)).await;
            }
            if tokio::time::Instant::now() < session.until {
                carry.signing_done = true;
                if signs {
                    leansim::node::validator::publish_signatures(&state, &mut swarm, !bundled)?;
                    let now = tokio::time::Instant::now();
                    for &validator_id in &state.validator_ids {
                        let subnet = state.config.subnet_for_validator(validator_id);
                        sync.deliver(subnet, validator_id, state.node_id, now);
                        if bundled {
                            bundles.deliver(
                                subnet,
                                u64::from(validator_id),
                                state.node_id,
                                None,
                                now,
                            );
                        }
                    }
                    // Own signatures go out at the next tick, like any other.
                    if bundled {
                        next_bundle_tick = Some(next_tick(bundle_anchor, bundle_tick, now));
                    }
                }
                if node_config.role == NodeRole::LocalAggregator {
                    leansim::node::local_aggregator::record_own_signatures(&state);
                }
                emit_mesh_degrees(&state, &mut swarm, &mesh_subnets, MeshSample::Signing);
                carry.signing_at = tokio::time::Instant::now().saturating_duration_since(run_start);
            }
        }
    }

    let end = if session.last {
        session.until + carry.signing_at
    } else {
        session.until
    };
    let mut next_sync =
        (sync.mode() != SignatureSync::None).then(|| tokio::time::Instant::now() + sync_interval);
    // With churn a peer can become a push target long after the signatures have
    // stopped moving, and bundles only tick when there is something new: so
    // every heartbeat the host checks for new targets and ticks for them.
    let heartbeat = Duration::from_millis(experiment.gossipsub_heartbeat_interval_ms.max(1));
    let mut next_target_check =
        (bundled && experiment.churn_enabled()).then(|| tokio::time::Instant::now() + heartbeat);
    // Waggle has no heartbeat to pick gossip peers: this host's clock does.
    let waggle_gossip = Duration::from_millis(experiment.waggle_gossip_interval_ms());
    let mut next_waggle_gossip = (waggle && experiment.waggle_gossip_peers > 0)
        .then(|| tokio::time::Instant::now() + waggle_gossip);

    loop {
        if tokio::time::Instant::now() >= end {
            break;
        }
        // Wake for the next message, the next proof to finish, or the end of the run.
        let wake = [
            state.next_proof_due(),
            exchange.next_due(),
            next_sync,
            next_bundle_tick,
            next_target_check,
            next_waggle_gossip,
            bundles.next_request_due(),
        ]
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
            Ok(Some(frame @ (NetEvent::Partial { .. } | NetEvent::Waggle { .. }))) => {
                let now = tokio::time::Instant::now();
                let deliveries = match frame {
                    NetEvent::Partial { peer, message } => bundle_io.on_partial(
                        &mut swarm,
                        &mut bundles,
                        meter.as_mut(),
                        peer,
                        message,
                        now,
                        state.elapsed_ms(),
                    ),
                    NetEvent::Waggle {
                        peer,
                        subnet,
                        pieces,
                    } => bundle_io.on_pieces(
                        &mut swarm,
                        &mut bundles,
                        meter.as_mut(),
                        peer,
                        subnet,
                        pieces,
                        now,
                        state.elapsed_ms(),
                    ),
                    _ => unreachable!("matched above"),
                };
                bundle_recv_msgs += deliveries.len() as u64;
                bundle_recv_bytes += deliveries.iter().map(|d| d.byte_size).sum::<u64>();
                // New signatures go out at the next tick, even if a later one was
                // already planned for staggered pushes. With announcements, so does
                // the answer to what the peer announced.
                if bundle_settings.announce || deliveries.iter().any(|d| !d.duplicate) {
                    let tick_at = next_tick(bundle_anchor, bundle_tick, now);
                    next_bundle_tick =
                        Some(next_bundle_tick.map_or(tick_at, |planned| planned.min(tick_at)));
                }
                record_deliveries(&state, deliveries);
            }
            Ok(Some(NetEvent::PartialGossip { topic, peers })) => bundle_io.on_gossip(
                &mut swarm,
                &mut bundles,
                meter.as_mut(),
                &topic,
                &peers,
                state.elapsed_ms(),
            ),
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
            Ok(Some(NetEvent::PeerDisconnected { peer })) => {
                sync.forget_peer(peer);
                bundles.forget_peer(peer);
            }
            Ok(None) => break,
            // A proof came due or the run ended; handled below / at the loop top.
            Err(_elapsed) => {}
        }

        let now = tokio::time::Instant::now();
        if bundles.next_request_due().is_some_and(|due| due <= now) {
            bundle_io.send_due_requests(
                &mut swarm,
                &mut bundles,
                meter.as_mut(),
                now,
                state.elapsed_ms(),
            );
        }
        if let Some(due) = next_target_check.filter(|due| *due <= now) {
            let new_targets = bundle_subnets.iter().any(|&subnet| {
                if bundles.held_count(subnet) == 0 {
                    return false;
                }
                let targets = bundle_io.targets(&mut swarm, subnet);
                bundles.has_new_targets(subnet, &targets)
            });
            if new_targets {
                let tick_at = next_tick(bundle_anchor, bundle_tick, now);
                next_bundle_tick =
                    Some(next_bundle_tick.map_or(tick_at, |planned| planned.min(tick_at)));
            }
            next_target_check = Some((due + heartbeat).max(now));
        }
        if next_bundle_tick.is_some_and(|due| due <= now) {
            bundle_io.flush(
                &mut swarm,
                &mut bundles,
                meter.as_mut(),
                now,
                state.elapsed_ms(),
            );
            // Staggered pushes still waiting get the first tick after they are due.
            next_bundle_tick = bundles
                .next_lazy_due()
                .map(|due| next_tick(bundle_anchor, bundle_tick, due));
            // So do the ones a full send queue turned away, once it had time to drain.
            if bundle_io.take_retry() {
                let retry_at = next_tick(bundle_anchor, bundle_tick, now + SEND_RETRY);
                next_bundle_tick =
                    Some(next_bundle_tick.map_or(retry_at, |planned| planned.min(retry_at)));
            }
        }
        if let Some(due) = next_waggle_gossip.filter(|due| *due <= now) {
            for &subnet in &bundle_subnets {
                if bundles.held_count(subnet) == 0 {
                    continue;
                }
                let peers = swarm
                    .behaviour_mut()
                    .waggle
                    .as_mut()
                    .map_or_else(Vec::new, |waggle| waggle.gossip_peers(subnet));
                bundle_io.advertise(
                    &mut swarm,
                    &mut bundles,
                    meter.as_mut(),
                    subnet,
                    &peers,
                    state.elapsed_ms(),
                );
            }
            next_waggle_gossip = Some((due + waggle_gossip).max(now));
        }
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
                emit_bucket(state.node_id, bucket);
            }
        }
    }

    // What the session measured stays with the host; everything else goes with it.
    if session.last {
        emit_mesh_degrees(&state, &mut swarm, &mesh_subnets, MeshSample::Exit);
    }
    let bundle_stats = bundle_io.final_stats(&bundles);
    emit(&sync_io.transport_stats(
        state.node_id,
        swarm.behaviour().gossipsub.control_stats(),
        sync.pending_rows(),
        bundle_stats,
        explicit_peers.link_stats(),
    ));
    // Bundles are counted as sent, not estimated like gossip forwards.
    if bundled {
        carry.bytes_sent += bundle_stats.bundle_bytes_sent;
        carry.bytes_received += bundle_recv_bytes;
        carry.msgs_sent += bundle_stats.bundle_sigs_sent;
        carry.msgs_received += bundle_recv_msgs;
    } else {
        carry.bytes_sent += state.bytes_sent_sig.load(Ordering::Relaxed);
        carry.bytes_received += state.bytes_recv_sig.load(Ordering::Relaxed);
        carry.msgs_sent += state.msgs_sent_sig.load(Ordering::Relaxed);
        carry.msgs_received += state.msgs_recv_sig.load(Ordering::Relaxed);
    }
    carry.meter = meter;
    carry.sessions += 1;
    Ok(())
}

/// Logs how many peers the host pushes to on each subnet it subscribes to: its
/// gossipsub mesh peers, or over waggle the subscribers it picked.
fn emit_mesh_degrees(
    state: &NodeState,
    swarm: &mut Swarm<SimBehaviour>,
    subnets: &std::collections::BTreeSet<u32>,
    at: MeshSample,
) {
    for &subnet in subnets {
        let peers = match swarm.behaviour_mut().waggle.as_mut() {
            Some(waggle) => waggle.push_targets(subnet).len(),
            None => {
                let topic = libp2p::gossipsub::IdentTopic::new(
                    leansim::network::topics::subnet_topic(&state.config.run_id, subnet),
                );
                swarm
                    .behaviour()
                    .gossipsub
                    .mesh_peers(&topic.hash())
                    .count()
            }
        };
        emit(&JsonlEvent::MeshDegree {
            node_id: state.node_id,
            subnet_id: subnet,
            peers: peers as u32,
            at,
            ts_ms: state.elapsed_ms(),
        });
    }
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

fn emit_bucket(node_id: u32, bucket: Bucket) {
    emit(&JsonlEvent::TrafficBucket {
        node_id,
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
