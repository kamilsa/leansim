use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};

use leansim::config::experiment::{ExperimentConfig, NodeConfig, NodeRole};
use leansim::messages::wire::WireMessage;
use leansim::metrics::events::{emit, JsonlEvent};

#[derive(Parser)]
#[command(name = "lean-sim", author, version, about = "leanSim: Signature aggregation network simulator")]
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
    /// Generate Shadow YAML topology and per-node configs from an experiment TOML.
    GenShadow {
        #[arg(long)]
        experiment: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Aggregate JSONL events from a Shadow data directory into a metrics summary.
    Summarize {
        #[arg(long)]
        shadow_data: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate a netviz-compatible trace file from an experiment and Shadow run.
    Netviz {
        #[arg(long)]
        experiment: PathBuf,
        #[arg(long)]
        shadow_data: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env(),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Node { config } => run_node(config).await,
        Command::GenShadow { experiment, out } => {
            let content = std::fs::read_to_string(&experiment)?;
            let exp: ExperimentConfig = toml::from_str(&content)
                .map_err(|e| anyhow::anyhow!("invalid experiment config: {e}"))?;
            exp.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
            leansim::shadow::generator::generate_shadow_config(&exp, &out)?;
            Ok(())
        }
        Command::Summarize { shadow_data, out } => {
            leansim::metrics::summary::summarize(&shadow_data, &out)
        }
        Command::Netviz {
            experiment,
            shadow_data,
            out,
        } => leansim::netviz::generate(&experiment, &shadow_data, &out),
    }
}

async fn run_node(config_path: PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(&config_path)?;
    let node_config: NodeConfig = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("invalid node config: {e}"))?;
    node_config.experiment.validate().map_err(|e| anyhow::anyhow!("{e}"))?;

    let state = Arc::new(leansim::node::state::NodeState::new(
        node_config.node_id,
        node_config.role,
        node_config.subnet_id,
        node_config.experiment.clone(),
    ));

    let mut swarm = leansim::network::swarm::build_swarm(
        node_config.node_id,
        &node_config.listen_addr,
        &node_config.experiment,
    )?;

    leansim::network::swarm::subscribe_to_topics(
        &mut swarm,
        node_config.role,
        node_config.subnet_id,
        &node_config.experiment.run_id,
    )?;

    // Emit peer ID for mesh edge reconstruction
    emit(&JsonlEvent::NodePeerId {
        node_id: state.node_id,
        peer_id: swarm.local_peer_id().to_base58(),
    });

    // Dial seed peers
    leansim::network::swarm::dial_seeds(&mut swarm, &node_config.seed_addrs).await?;

    // Role-specific init
    if node_config.role == NodeRole::Validator {
        leansim::node::validator::validator_init(&state, &mut swarm).await?;
        emit(&JsonlEvent::SigSent {
            node_id: state.node_id,
            subnet_id: state.subnet_id,
            seq: state.seq_counter.load(std::sync::atomic::Ordering::SeqCst),
            ts_ms: state.elapsed_ms(),
            byte_size: node_config.experiment.signature_payload_bytes as u64,
        });
    }

    // Main event loop with timeout
    let timeout = Duration::from_secs(node_config.experiment.run_timeout_secs);
    let end = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = end.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let msg = tokio::time::timeout(
            remaining,
            leansim::network::swarm::next_message(&mut swarm),
        )
        .await;

        match msg {
            Ok(Some(received)) => {
                let wire_msg = received.wire_msg;
                let from_peer_str = received.from_peer.to_base58();
                let msg_id = wire_msg.message_id();
                // Use gossipsub's duplicate detection (from the DuplicateMessage event)
                // instead of our local DashMap which never fires because gossipsub
                // deduplicates at the protocol level before delivering to us.
                let is_dup = received.is_duplicate;
                if !is_dup {
                    state.mark_seen(msg_id);
                }

                // Emit receive event based on message type
                match &wire_msg {
                    WireMessage::ValidatorSignature {
                        sender_id,
                        subnet_id,
                        ..
                    } => {
                        let size = wire_msg.encode().len() as u64;
                        emit(&JsonlEvent::SigReceived {
                            node_id: state.node_id,
                            from_id: *sender_id,
                            from_peer_id: from_peer_str,
                            subnet_id: *subnet_id,
                            duplicate: is_dup,
                            ts_ms: state.elapsed_ms(),
                            byte_size: size,
                        });
                    }
                    WireMessage::LocalProof {
                        sender_id,
                        subnet_id,
                        covered_validator_count,
                        ..
                    } => {
                        let size = wire_msg.encode().len() as u64;
                        emit(&JsonlEvent::LocalProofReceived {
                            node_id: state.node_id,
                            from_id: *sender_id,
                            from_peer_id: from_peer_str,
                            subnet_id: *subnet_id,
                            covered_sigs: *covered_validator_count,
                            duplicate: is_dup,
                            ts_ms: state.elapsed_ms(),
                            byte_size: size,
                        });
                    }
                    _ => {}
                }

                // Dispatch to role handler based on node role
                match state.role {
                    NodeRole::LocalAggregator => {
                        leansim::node::local_aggregator::handle_message(
                            &state, &mut swarm, &wire_msg,
                        )
                        .await?;
                    }
                    NodeRole::GlobalAggregator => {
                        leansim::node::global_aggregator::handle_message(
                            &state, &mut swarm, &wire_msg,
                        )
                        .await?;
                    }
                    NodeRole::Validator => {
                        // Validators ignore incoming messages in v1
                    }
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

    // Emit final node stats
    emit(&JsonlEvent::NodeStats {
        node_id: state.node_id,
        bytes_sent: 0,
        bytes_received: 0,
        msgs_sent: 0,
        msgs_received: 0,
    });

    tracing::info!("node {} exiting", state.node_id);
    Ok(())
}
