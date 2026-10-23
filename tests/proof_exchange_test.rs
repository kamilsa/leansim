//! The proof protocol between real swarms over QUIC.

use leansim::config::experiment::ExperimentConfig;
use leansim::network::swarm::{build_swarm, peer_id_for};

fn config() -> ExperimentConfig {
    toml::from_str("run_id = \"proofs\"\nvalidator_count = 4\nsubnet_count = 1\n").unwrap()
}

#[tokio::test]
async fn host_identities_derive_from_node_ids() {
    assert_eq!(peer_id_for(3), peer_id_for(3));
    assert_ne!(peer_id_for(3), peer_id_for(4));
    let swarm = build_swarm(3, "/ip4/127.0.0.1/udp/0/quic-v1", &config()).unwrap();
    assert_eq!(*swarm.local_peer_id(), peer_id_for(3));
}
