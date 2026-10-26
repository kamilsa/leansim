//! Mesh warmup between real swarms over QUIC.

use std::time::{Duration, Instant};

use futures::StreamExt;
use leansim::config::experiment::ExperimentConfig;
use leansim::network::swarm::{build_swarm, dial_seeds, peer_id_for, ExplicitPeerManager};
use libp2p::swarm::SwarmEvent;

fn config() -> ExperimentConfig {
    toml::from_str("run_id = \"warmup\"\nvalidator_count = 4\nsubnet_count = 1\n").unwrap()
}

#[tokio::test]
async fn a_host_with_nothing_to_dial_waits_for_inbound_peers() {
    let config = config();
    let mut quiet = build_swarm(0, "/ip4/127.0.0.1/udp/0/quic-v1", &config).unwrap();
    let quiet_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = quiet.select_next_some().await {
            break address;
        }
    };
    let mut dialer = build_swarm(1, "/ip4/127.0.0.1/udp/0/quic-v1", &config).unwrap();
    let dialing = tokio::spawn(async move {
        let mut peers = ExplicitPeerManager::new(&[], &[]).unwrap();
        dial_seeds(
            &mut dialer,
            &[quiet_addr.to_string()],
            &mut peers,
            &[],
            Some(1000),
        )
        .await
        .unwrap();
    });

    let mut peers = ExplicitPeerManager::new(&[], &[]).unwrap();
    let start = Instant::now();
    dial_seeds(&mut quiet, &[], &mut peers, &[], Some(1000))
        .await
        .unwrap();
    assert!(start.elapsed() >= Duration::from_millis(1000));
    assert!(quiet.is_connected(&peer_id_for(1)));
    dialing.await.unwrap();
}
