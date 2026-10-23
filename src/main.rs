use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};

use leansim::config::experiment::{NodeConfig, NodeRole};
use leansim::messages::wire::WireMessage;
use leansim::metrics::events::{emit, JsonlEvent};

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
    /// Generate a netviz-compatible trace file from a run manifest and Shadow run.
    Netviz {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        shadow_data: PathBuf,
        #[arg(long)]
        out: PathBuf,
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
        Command::Netviz {
            manifest,
            shadow_data,
            out,
        } => leansim::netviz::generate(&manifest, &shadow_data, &out),
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
        leansim::node::state::NodeState::new(
            node_config.node_id,
            node_config.role,
            node_config.subnet_id,
            node_config.experiment.clone(),
        )
        .with_validator_ids(node_config.signing_validator_ids())
        .with_subscribed_subnets(node_config.subscribed_subnets.clone()),
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
        node_config.role,
        node_config.subnet_id,
        &subscribed_subnets,
        &node_config.experiment.run_id,
    )?;

    emit(&JsonlEvent::NodePeerId {
        node_id: state.node_id,
        peer_id: swarm.local_peer_id().to_base58(),
    });

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
        &node_config.seed_addrs,
        &mut explicit_peers,
        &selected_aggregator_topics,
    )
    .await?;

    if !state.validator_ids.is_empty() {
        leansim::node::validator::validator_init(&state, &mut swarm).await?;
    }
    if node_config.role == NodeRole::LocalAggregator {
        leansim::node::local_aggregator::record_own_signature(&state).await?;
    }

    let timeout = Duration::from_secs(node_config.experiment.run_timeout_secs);
    let end = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = end.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let msg = tokio::time::timeout(
            remaining,
            leansim::network::swarm::next_message(&mut swarm, &mut explicit_peers),
        )
        .await;

        match msg {
            Ok(Some(received)) => {
                let wire_msg = received.wire_msg;
                let from_peer_str = received.from_peer.to_base58();
                let msg_id = wire_msg.message_id();
                let is_dup = received.is_duplicate;
                if !is_dup {
                    state.mark_seen(msg_id);
                }

                let WireMessage::ValidatorSignature {
                    sender_id,
                    validator_id,
                    subnet_id,
                    ..
                } = &wire_msg;
                let size = wire_msg.encode().len() as u64;
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
                    ts_ms: state.elapsed_ms(),
                    byte_size: size,
                });
                // Approximate lazy gossip traffic. Full-message forwarding to mesh and
                // explicit peers is not observable at this layer.
                if !is_dup {
                    // Mesh_n configured, D_lazy ≈ ceil(sqrt(mesh_n))
                    let d_lazy =
                        ((state.config.gossipsub_mesh_n as f64).sqrt().ceil() as u64).max(1);
                    state
                        .bytes_sent_sig
                        .fetch_add(size * d_lazy, Ordering::Relaxed);
                    state.msgs_sent_sig.fetch_add(d_lazy, Ordering::Relaxed);
                }

                if state.role == NodeRole::LocalAggregator {
                    leansim::node::local_aggregator::handle_message(&state, &wire_msg).await?;
                }
            }
            Ok(None) => {
                break;
            }
            Err(_elapsed) => {
                break;
            }
        }
    }

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
