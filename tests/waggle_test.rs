//! Signatures over waggle between two QUIC hosts: bundles pushed to a
//! subscriber, one signature per message without bundling, advertisements
//! requested and served, and a full send queue retried.

use std::time::Duration;

use futures::StreamExt;
use leansim::config::experiment::ExperimentConfig;
use leansim::metrics::events::SigVia;
use leansim::network::swarm::{
    build_swarm, subscribe_to_topics, track_waggle_subnets, SimBehaviour, SimBehaviourEvent,
};
use leansim::network::waggle_net::{SigWaggle, SigWaggleEvent};
use leansim::node::bundle_io::BundleIo;
use leansim::node::bundles::{BundleSettings, BundleSync};
use leansim::node::sync_io::Delivery;
use libp2p::{swarm::SwarmEvent, PeerId, Swarm};

/// Three subnets of 128 validators over waggle, plus `extra` settings.
fn config(extra: &str) -> ExperimentConfig {
    let config: ExperimentConfig = toml::from_str(&format!(
        r#"
run_id = "waggle"
validator_count = 384
subnet_count = 3
signature_payload_bytes = 100
signature_transport = "waggle"
{extra}
"#
    ))
    .unwrap();
    config.validate().unwrap();
    config
}

struct Host {
    swarm: Swarm<SimBehaviour>,
    sync: BundleSync<PeerId>,
    io: BundleIo,
    received: Vec<Delivery>,
}

impl Host {
    /// A host that holds the signatures of `tracked` and hears `subscribed`.
    fn new(node_id: u32, config: &ExperimentConfig, tracked: &[u32], subscribed: &[u32]) -> Self {
        let mut swarm = build_swarm(node_id, "/ip4/127.0.0.1/udp/0/quic-v1", config).unwrap();
        track_waggle_subnets(&mut swarm, tracked.iter().copied());
        subscribe_to_topics(
            &mut swarm,
            &Default::default(),
            &subscribed.iter().copied().collect(),
            &config.run_id,
        )
        .unwrap();
        let sync = BundleSync::new(BundleSettings::from_config(config), tracked.iter().copied())
            .with_local(*swarm.local_peer_id());
        Self {
            swarm,
            sync,
            io: BundleIo::new(config, tracked.iter().copied()),
            received: Vec::new(),
        }
    }

    fn waggle(&mut self) -> &mut SigWaggle {
        self.swarm.behaviour_mut().waggle.as_mut().unwrap()
    }

    fn id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    fn handle(&mut self, event: SwarmEvent<SimBehaviourEvent>) {
        if let SwarmEvent::Behaviour(SimBehaviourEvent::Waggle(SigWaggleEvent::Pieces {
            peer,
            subnet,
            pieces,
        })) = event
        {
            let deliveries = self.io.on_pieces(
                &mut self.swarm,
                &mut self.sync,
                None,
                peer,
                subnet,
                pieces,
                tokio::time::Instant::now(),
                0,
            );
            self.received.extend(deliveries);
        }
    }

    fn flush(&mut self) {
        self.io.flush(
            &mut self.swarm,
            &mut self.sync,
            None,
            tokio::time::Instant::now(),
            0,
        );
    }

    /// Signs validators `from..to` of `subnet` on this host.
    fn sign(&mut self, subnet: u32, validators: std::ops::Range<u64>) {
        for v in validators {
            let validator = u64::from(subnet) * 128 + v;
            self.sync.deliver(
                subnet,
                validator,
                1000 + validator as u32,
                None,
                tokio::time::Instant::now(),
            );
        }
    }
}

/// Polls both hosts until `done` holds for them, or panics after 20 s. Waggle
/// subscriptions change the hosts without a swarm event, so `done` is also
/// checked every 10 ms.
async fn run_until(
    a: &mut Host,
    b: &mut Host,
    what: &str,
    mut done: impl FnMut(&mut Host, &mut Host) -> bool,
) {
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    while !done(a, b) {
        tokio::select! {
            event = a.swarm.select_next_some() => a.handle(event),
            event = b.swarm.select_next_some() => b.handle(event),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            _ = &mut deadline => panic!("timed out waiting for {what}"),
        }
    }
}

/// Polls both hosts for `time`.
async fn run_for(a: &mut Host, b: &mut Host, time: Duration) {
    let end = tokio::time::sleep(time);
    tokio::pin!(end);
    loop {
        tokio::select! {
            event = a.swarm.select_next_some() => a.handle(event),
            event = b.swarm.select_next_some() => b.handle(event),
            _ = &mut end => return,
        }
    }
}

/// Connects A to B and waits until each subscribes to subnet 0 on the other.
async fn connect(a: &mut Host, b: &mut Host) {
    let b_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = b.swarm.select_next_some().await {
            break address;
        }
    };
    a.swarm.dial(b_addr).unwrap();
    let (a_id, b_id) = (a.id(), b.id());
    run_until(a, b, "subscriptions", move |a, b| {
        a.waggle().is_subscribed(&b_id, 0) && b.waggle().is_subscribed(&a_id, 0)
    })
    .await;
}

#[tokio::test]
async fn bundles_are_pushed_to_subscribers_and_not_sent_back() {
    let config = config("bundle_max_signatures = 50");
    // A signs in subnet 1 without subscribing to it, and subscribes to subnet 2,
    // which B does not track.
    let mut a = Host::new(0, &config, &[0, 1, 2], &[0, 2]);
    let mut b = Host::new(1, &config, &[0, 1], &[0, 1]);
    connect(&mut a, &mut b).await;
    let (a_id, b_id) = (a.id(), b.id());
    run_until(
        &mut a,
        &mut b,
        "B's subscription to subnet 1",
        move |a, _| a.waggle().is_subscribed(&b_id, 1),
    )
    .await;
    run_for(&mut a, &mut b, Duration::from_millis(300)).await;
    assert!(
        !b.waggle().is_subscribed(&a_id, 1),
        "A only publishes there"
    );
    assert!(!b.waggle().is_subscribed(&a_id, 2), "B refused the topic");
    assert_eq!(b.waggle().subscriber_count(2), 0);
    assert_eq!(a.waggle().push_targets(0), vec![b_id]);
    assert_eq!(a.io.targets(&mut a.swarm, 1), vec![b_id]);
    assert!(a.waggle().gossip_peers(0).is_empty(), "B is a push target");

    // A holds 60 signatures of subnet 0 and one of subnet 1: its tick pushes B
    // two bundles of subnet 0 and one of subnet 1.
    a.sign(0, 0..60);
    a.sign(1, 5..6);
    a.flush();
    run_until(&mut a, &mut b, "the pushed signatures", |_, b| {
        b.sync.held_count(0) == 60 && b.sync.held_count(1) == 1
    })
    .await;
    assert_eq!(a.io.stats.bundles_sent, 3, "at most 50 signatures a bundle");
    assert_eq!(a.io.stats.bundle_sigs_sent, 61);
    assert_eq!(a.io.stats.frames_unsent, 0);
    assert!(!a.io.take_retry());
    assert!(b
        .received
        .iter()
        .all(|d| d.via == SigVia::Bundle && !d.duplicate && d.from_peer == a_id));
    assert!(b.received.iter().all(|d| d.origin == 1000 + d.validator_id));
    assert!(b.sync.holds(1, 128 + 5));
    // Frames carry the signatures, their indices and some framing.
    let signatures = 61 * a.io.signature_wire_bytes();
    assert!(a.io.stats.bundle_bytes_sent > signatures);
    assert_eq!(
        a.io.stats.bundle_framing_bytes_sent,
        a.io.stats.bundle_bytes_sent - signatures
    );

    // B knows A sent it all of them, so B's own tick sends nothing back.
    b.flush();
    assert_eq!(b.io.stats.bundles_sent, 0);
    // What B signs goes to A, which subscribes to subnet 0.
    b.sign(0, 100..103);
    b.flush();
    run_until(&mut a, &mut b, "B's signatures", |a, _| {
        a.sync.held_count(0) == 63
    })
    .await;
    assert_eq!(b.io.stats.bundle_sigs_sent, 3);
}

#[tokio::test]
async fn without_bundling_every_signature_is_a_message() {
    let config = config("waggle_bundled = false\nbundle_max_signatures = 50");
    let mut a = Host::new(0, &config, &[0], &[0]);
    let mut b = Host::new(1, &config, &[0], &[0]);
    connect(&mut a, &mut b).await;

    a.sign(0, 0..10);
    a.flush();
    run_until(&mut a, &mut b, "the pushed signatures", |_, b| {
        b.sync.held_count(0) == 10
    })
    .await;
    assert_eq!(a.io.stats.bundles_sent, 10);
    assert_eq!(a.io.stats.bundle_sigs_sent, 10);
    assert!(b
        .received
        .iter()
        .all(|d| d.via == SigVia::Bundle && !d.duplicate));
    b.flush();
    assert_eq!(b.io.stats.bundles_sent, 0);
}

#[tokio::test]
async fn with_hashed_selection_each_signature_crosses_a_link_once() {
    for bundled in [true, false] {
        let config = config(&format!(
            "waggle_push_selection = \"hashed\"\nwaggle_bundled = {bundled}"
        ));
        let mut a = Host::new(0, &config, &[0], &[0]);
        let mut b = Host::new(1, &config, &[0], &[0]);
        connect(&mut a, &mut b).await;
        let (a_id, b_id) = (a.id(), b.id());
        // Every subscriber is a candidate, to push to and to gossip with.
        assert_eq!(a.waggle().push_targets(0), vec![b_id]);
        assert_eq!(a.waggle().gossip_peers(0), vec![b_id]);

        // Both hosts hold validators 0..40 from elsewhere: the hash names one
        // sender for each, so each crosses the link once, and nothing comes back.
        for v in 0..40 {
            let now = tokio::time::Instant::now();
            a.sync.deliver(0, v, 7, Some(PeerId::random()), now);
            b.sync.deliver(0, v, 7, Some(PeerId::random()), now);
        }
        a.flush();
        b.flush();
        let (from_a, from_b) = (a.io.stats.bundle_sigs_sent, b.io.stats.bundle_sigs_sent);
        assert_eq!(from_a + from_b, 40);
        assert!(from_a > 0 && from_b > 0, "both ends send some");
        run_until(&mut a, &mut b, "the pushed signatures", move |a, b| {
            (a.received.len() + b.received.len()) as u64 == 40
        })
        .await;
        assert!(a.received.iter().chain(&b.received).all(|d| d.duplicate));
        let mut crossed: Vec<u32> = a
            .received
            .iter()
            .chain(&b.received)
            .map(|d| d.validator_id)
            .collect();
        crossed.sort_unstable();
        assert_eq!(crossed, (0..40).collect::<Vec<u32>>());
        assert!(a.received.iter().all(|d| d.from_peer == b_id));
        assert!(b.received.iter().all(|d| d.from_peer == a_id));
        a.flush();
        b.flush();
        assert_eq!(
            a.io.stats.bundle_sigs_sent + b.io.stats.bundle_sigs_sent,
            40
        );

        // What a host signs, it sends whatever the hash says.
        a.sign(0, 50..60);
        a.flush();
        run_until(&mut a, &mut b, "A's signatures", |_, b| {
            b.sync.held_count(0) == 50
        })
        .await;
    }
}

#[tokio::test]
async fn advertised_signatures_are_requested_and_served() {
    let config = config("bundle_max_signatures = 50");
    let mut a = Host::new(0, &config, &[0], &[0]);
    let mut b = Host::new(1, &config, &[0], &[0]);
    connect(&mut a, &mut b).await;
    let b_id = b.id();

    // A advertises 60 signatures to B as a gossip peer; B requests them all,
    // and A serves them in two bundles.
    a.sign(0, 0..60);
    a.io.advertise(&mut a.swarm, &mut a.sync, None, 0, &[b_id], 0);
    run_until(&mut a, &mut b, "the requested signatures", |_, b| {
        b.sync.held_count(0) == 60
    })
    .await;
    assert!(b
        .received
        .iter()
        .all(|d| d.via == SigVia::Requested && !d.duplicate));
    assert_eq!(a.io.stats.available_ids_sent, 60);
    assert_eq!(b.io.stats.request_ids_sent, 60);
    assert_eq!(a.io.stats.requested_sigs_served, 60);
    assert_eq!(a.io.stats.bundles_sent, 2);
    assert_eq!((a.io.stats.metadata_sent, b.io.stats.metadata_sent), (1, 1));
    // Served ones are not pushed, nor advertised again.
    a.flush();
    a.io.advertise(&mut a.swarm, &mut a.sync, None, 0, &[b_id], 0);
    assert_eq!(a.io.stats.bundles_sent, 2);
    assert_eq!(a.io.stats.metadata_sent, 1);
}

#[tokio::test]
async fn a_full_send_queue_is_retried_until_everything_arrives() {
    let config = config("waggle_bundled = false\nwaggle_max_send_queue = 2");
    let mut a = Host::new(0, &config, &[0], &[0]);
    let mut b = Host::new(1, &config, &[0], &[0]);
    connect(&mut a, &mut b).await;

    // Thirty messages for a queue of two: the first tick leaves most unsent.
    a.sign(0, 0..30);
    a.flush();
    assert_eq!(a.io.stats.bundles_sent, 2);
    assert_eq!(a.io.stats.frames_unsent, 28);
    assert!(a.io.take_retry());

    for _ in 0..200 {
        if b.sync.held_count(0) == 30 {
            break;
        }
        run_for(&mut a, &mut b, Duration::from_millis(10)).await;
        a.flush();
        a.io.take_retry();
    }
    assert_eq!(b.sync.held_count(0), 30);
    assert_eq!(a.io.stats.bundle_sigs_sent, 30, "each sent exactly once");
    assert!(b.received.iter().all(|d| !d.duplicate));
    a.flush();
    assert!(!a.io.take_retry(), "nothing left to push");
}
