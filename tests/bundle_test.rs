//! EIP-8334 bundles between two QUIC hosts: signatures advertised to a gossip
//! peer are requested and served, and a tick then pushes only what is new.

use std::time::Duration;

use futures::StreamExt;
use leansim::config::experiment::ExperimentConfig;
use leansim::metrics::events::SigVia;
use leansim::network::swarm::{
    build_swarm, enable_partial_topics, SimBehaviour, SimBehaviourEvent,
};
use leansim::network::topics::subnet_topic;
use leansim::node::bundle_io::BundleIo;
use leansim::node::bundles::{BundleSettings, BundleSync};
use leansim::node::sync_io::Delivery;
use libp2p::{gossipsub, swarm::SwarmEvent, PeerId, Swarm};

fn config() -> ExperimentConfig {
    toml::from_str(
        r#"
run_id = "bundles"
validator_count = 128
subnet_count = 1
signature_payload_bytes = 100
signature_propagation = "bundled"
bundle_max_signatures = 50
gossipsub_mesh_n_low = 1
gossipsub_mesh_n = 2
gossipsub_mesh_n_high = 3
gossipsub_mesh_outbound_min = 0
gossipsub_heartbeat_interval_ms = 100
"#,
    )
    .unwrap()
}

struct Host {
    swarm: Swarm<SimBehaviour>,
    sync: BundleSync<PeerId>,
    io: BundleIo,
    received: Vec<Delivery>,
}

impl Host {
    fn new(node_id: u32, config: &ExperimentConfig) -> Self {
        let mut swarm = build_swarm(node_id, "/ip4/127.0.0.1/udp/0/quic-v1", config).unwrap();
        enable_partial_topics(&mut swarm, [0], &config.run_id);
        let topic = gossipsub::IdentTopic::new(subnet_topic(&config.run_id, 0));
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
        Self {
            swarm,
            sync: BundleSync::new(BundleSettings::from_config(config), [0]),
            io: BundleIo::new(config, [0]),
            received: Vec::new(),
        }
    }

    fn handle(&mut self, event: SwarmEvent<SimBehaviourEvent>) {
        if let SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Partial {
            propagation_source,
            message,
        })) = event
        {
            let deliveries = self.io.on_partial(
                &mut self.swarm,
                &mut self.sync,
                None,
                propagation_source,
                message,
                tokio::time::Instant::now(),
                0,
            );
            self.received.extend(deliveries);
        }
    }
}

/// Polls both hosts until `done` holds for them, or panics after 20 s.
async fn run_until(a: &mut Host, b: &mut Host, what: &str, done: impl Fn(&Host, &Host) -> bool) {
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    while !done(a, b) {
        tokio::select! {
            event = a.swarm.select_next_some() => a.handle(event),
            event = b.swarm.select_next_some() => b.handle(event),
            _ = &mut deadline => panic!("timed out waiting for {what}"),
        }
    }
}

#[tokio::test]
async fn advertised_signatures_are_requested_then_new_ones_pushed() {
    let config = config();
    let mut a = Host::new(0, &config);
    let mut b = Host::new(1, &config);
    let b_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = b.swarm.select_next_some().await {
            break address;
        }
    };
    a.swarm.dial(b_addr).unwrap();
    let b_id = *b.swarm.local_peer_id();
    let a_id = *a.swarm.local_peer_id();
    let topic = gossipsub::IdentTopic::new(subnet_topic(&config.run_id, 0)).hash();

    // Each host learns that the other requests partial messages on the subnet.
    let t = topic.clone();
    run_until(&mut a, &mut b, "partial subscriptions", move |a, b| {
        a.swarm
            .behaviour()
            .gossipsub
            .peer_requests_partial(&b_id, &t)
            && b.swarm
                .behaviour()
                .gossipsub
                .peer_requests_partial(&a_id, &t)
    })
    .await;

    // A holds 60 signatures and advertises them to B as a gossip peer; B requests
    // them all, and A serves them in two bundles.
    for v in 0..60 {
        a.sync
            .deliver(0, v, 1000 + v as u32, None, tokio::time::Instant::now());
    }
    a.io.on_gossip(&mut a.swarm, &mut a.sync, None, &topic, &[b_id], 0);
    run_until(&mut a, &mut b, "the requested signatures", |_, b| {
        b.sync.held_count(0) == 60
    })
    .await;
    assert!(b
        .received
        .iter()
        .all(|d| d.via == SigVia::Requested && !d.duplicate));
    assert!(b
        .received
        .iter()
        .all(|d| d.origin == 1000 + d.validator_id && d.from_peer == a_id));
    assert_eq!(a.io.stats.requested_sigs_served, 60);
    assert_eq!(a.io.stats.bundles_sent, 2, "at most 50 signatures a bundle");
    assert_eq!(b.io.stats.request_ids_sent, 60);
    assert_eq!(a.io.stats.available_ids_sent, 60);

    // Ten more: A's tick pushes only those to its push targets, B among them.
    for v in 60..70 {
        a.sync
            .deliver(0, v, 1000 + v as u32, None, tokio::time::Instant::now());
    }
    let t = topic.clone();
    run_until(&mut a, &mut b, "B in A's mesh", move |a, _| {
        a.swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&t)
            .any(|p| *p == b_id)
    })
    .await;
    a.io.flush(
        &mut a.swarm,
        &mut a.sync,
        None,
        tokio::time::Instant::now(),
        0,
    );
    run_until(&mut a, &mut b, "the pushed signatures", |_, b| {
        b.sync.held_count(0) == 70
    })
    .await;
    let pushed: Vec<u32> = b
        .received
        .iter()
        .filter(|d| d.via == SigVia::Bundle)
        .map(|d| d.validator_id)
        .collect();
    assert_eq!(pushed.len(), 10);
    assert!(pushed.iter().all(|&v| v >= 60));
    assert!(b.received.iter().all(|d| !d.duplicate));

    // B knows A sent it all 70, so B's own tick sends nothing back.
    b.io.flush(
        &mut b.swarm,
        &mut b.sync,
        None,
        tokio::time::Instant::now(),
        0,
    );
    assert_eq!(b.io.stats.bundles_sent, 0);
}
