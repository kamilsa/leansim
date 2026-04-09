mod config;
mod types;
mod network;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use crate::types::{Message, Role};
use crate::network::Network;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use rand::seq::SliceRandom;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    id: u32,

    #[arg(long)]
    role: String, // "validator", "local_aggregator", "global_aggregator"

    #[arg(long)]
    subnet: u32,

    #[arg(long)]
    addr: SocketAddr,

    #[arg(long, value_delimiter = ',')]
    peers: Vec<SocketAddr>,

    #[arg(long, default_value = "true")]
    use_optimized: bool,

    #[arg(long, default_value_t = 32)]
    validators_per_subnet: usize,
}

struct NodeState {
    id: u32,
    role: Role,
    subnet_id: u32,
    validators_per_subnet: usize,
    peers: Vec<SocketAddr>,
    seen_messages: DashMap<[u8; 32], Instant>,
    received_signatures: DashMap<u32, Vec<u8>>, // validator_id -> data
    received_snarks: DashMap<u32, Vec<u8>>, // subnet_id -> data
    start_time: Instant,
    use_optimized: bool,
    snark1_generated: Mutex<bool>,
    snark2_generated: Mutex<bool>,
    total_received: Mutex<usize>,
    full_messages: DashMap<[u8; 32], Vec<u8>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();

    let role = match args.role.as_str() {
        "validator" => Role::Validator,
        "local_aggregator" => Role::LocalAggregator,
        "global_aggregator" => Role::GlobalAggregator,
        _ => anyhow::bail!("Invalid role"),
    };

    let (tx, mut rx) = mpsc::channel(2000);
    let network = Network::new(args.addr, tx).await?;

    for peer in &args.peers {
        let _ = network.connect(*peer).await;
    }

    let state = Arc::new(NodeState {
        id: args.id,
        role,
        subnet_id: args.subnet,
        validators_per_subnet: args.validators_per_subnet,
        peers: args.peers.clone(),
        seen_messages: DashMap::new(),
        received_signatures: DashMap::new(),
        received_snarks: DashMap::new(),
        start_time: Instant::now(),
        use_optimized: args.use_optimized,
        snark1_generated: Mutex::new(false),
        snark2_generated: Mutex::new(false),
        total_received: Mutex::new(0),
        full_messages: DashMap::new(),
    });

    let state_clone = state.clone();
    let network_clone = network.clone();

    tokio::spawn(async move {
        while let Some((addr, msg)) = rx.recv().await {
            let _ = handle_message(&state_clone, &network_clone, addr, msg).await;
        }
    });

    match role {
        Role::Validator | Role::LocalAggregator => {
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            let msg = Message::Signature {
                validator_id: args.id,
                subnet_id: args.subnet,
                data: vec![0u8; config::SIG_SIZE],
            };
            
            let id = msg.get_id();
            state.seen_messages.insert(id, Instant::now());
            state.full_messages.insert(id, bincode::serialize(&msg).unwrap());
            
            if state.use_optimized {
                let targets = {
                    let mut rng = rand::thread_rng();
                    state.peers.choose_multiple(&mut rng, 3).cloned().collect::<Vec<_>>()
                };
                for target in targets {
                    let _ = network.send_to(target, &msg).await;
                }
            } else {
                let _ = network.broadcast(&msg).await;
            }
        }
        Role::GlobalAggregator => {}
    }

    tokio::time::sleep(Duration::from_secs(20)).await;
    
    let total = *state.total_received.lock().unwrap();
    println!("NODE_STATS ID: {} TOTAL_RECEIVED: {}", state.id, total);

    Ok(())
}

async fn handle_message(state: &Arc<NodeState>, network: &Arc<Network>, from: SocketAddr, msg: Message) -> Result<()> {
    {
        let mut total = state.total_received.lock().unwrap();
        *total += 1;
    }

    match msg {
        Message::IHAVE { id } => {
            if !state.seen_messages.contains_key(&id) {
                let _ = network.send_to(from, &Message::IWANT { id }).await;
            }
        }
        Message::IWANT { id } => {
            if let Some(data) = state.full_messages.get(&id) {
                let full_msg: Message = bincode::deserialize(&data)?;
                let _ = network.send_to(from, &full_msg).await;
            }
        }
        _ => {
            let id = msg.get_id();
            if state.seen_messages.contains_key(&id) {
                return Ok(());
            }
            state.seen_messages.insert(id, Instant::now());
            state.full_messages.insert(id, bincode::serialize(&msg).unwrap());

            match msg {
                Message::Signature { validator_id, subnet_id, data } => {
                    tokio::time::sleep(config::SIG_VERIFY_TIME).await;
                    
                    if state.use_optimized {
                        let sample = {
                            let mut rng = rand::thread_rng();
                            let targets: Vec<_> = state.peers.iter()
                                .filter(|p| **p != from)
                                .cloned()
                                .collect::<Vec<_>>();
                            targets.choose_multiple(&mut rng, 3).cloned().collect::<Vec<_>>()
                        };
                        for target in sample {
                            let _ = network.send_to(target, &Message::Signature { validator_id, subnet_id, data: data.clone() }).await;
                        }
                    } else {
                        let _ = network.broadcast(&Message::Signature { validator_id, subnet_id, data: data.clone() }).await;
                    }

                    if state.role == Role::LocalAggregator && subnet_id == state.subnet_id {
                        state.received_signatures.insert(validator_id, data);
                        let count = state.received_signatures.len();
                        let threshold = (state.validators_per_subnet as f64 * config::SNARK1_THRESHOLD) as usize;
                        
                        if count >= threshold {
                            let should_generate = {
                                let mut generated = state.snark1_generated.lock().unwrap();
                                if !*generated {
                                    *generated = true;
                                    true
                                } else {
                                    false
                                }
                            };

                            if should_generate {
                                tokio::time::sleep(config::AGGREGATION_TIME_PER_SIG * count as u32).await;
                                let snark1 = Message::SNARK1 {
                                    aggregator_id: state.id,
                                    subnet_id: state.subnet_id,
                                    data: vec![0u8; config::SNARK_SIZE],
                                    verified_sigs: count,
                                };
                                let snark1_id = snark1.get_id();
                                state.seen_messages.insert(snark1_id, Instant::now());
                                state.full_messages.insert(snark1_id, bincode::serialize(&snark1).unwrap());
                                
                                if state.use_optimized {
                                    let _ = network.broadcast(&Message::IHAVE { id: snark1_id }).await;
                                } else {
                                    let _ = network.broadcast(&snark1).await;
                                }
                                
                                let latency = state.start_time.elapsed();
                                println!("SNARK1_LATENCY_MS: {}", latency.as_millis());
                            }
                        }
                    }
                }
                Message::SNARK1 { aggregator_id, subnet_id, data, verified_sigs } => {
                    tokio::time::sleep(config::SNARK_VERIFY_TIME).await;
                    
                    if state.use_optimized {
                        let _ = network.broadcast(&Message::IHAVE { id }).await;
                    } else {
                        let _ = network.broadcast(&Message::SNARK1 { aggregator_id, subnet_id, data: data.clone(), verified_sigs }).await;
                    }

                    if state.role == Role::GlobalAggregator {
                        state.received_snarks.insert(subnet_id, data);
                        let count = state.received_snarks.len();
                        let threshold = (config::SUBNETS as f64 * config::SNARK2_THRESHOLD).ceil() as usize;
                        
                        if count >= threshold {
                            let should_generate = {
                                let mut generated = state.snark2_generated.lock().unwrap();
                                if !*generated {
                                    *generated = true;
                                    true
                                } else {
                                    false
                                }
                            };

                            if should_generate {
                                tokio::time::sleep(config::RECURSION_TIME_PER_SNARK * count as u32).await;
                                let snark2 = Message::SNARK2 {
                                    aggregator_id: state.id,
                                    data: vec![0u8; config::SNARK_SIZE],
                                    verified_snarks: count,
                                };
                                state.seen_messages.insert(snark2.get_id(), Instant::now());
                                let _ = network.broadcast(&snark2).await;
                                let latency = state.start_time.elapsed();
                                println!("SIMULATION_RESULT LATENCY_MS: {}", latency.as_millis());
                            }
                        }
                    }
                }
                Message::SNARK2 { .. } => {
                    let _ = network.broadcast(&msg).await;
                }
                _ => {}
            }
        }
    }
    Ok(())
}
