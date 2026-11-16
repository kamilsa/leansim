//! Churn between real swarms over QUIC: a host crashes without a word and comes
//! back with no state, while its peer still holds a connection to it.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use futures::StreamExt;
use leansim::config::experiment::ExperimentConfig;
use leansim::messages::wire::WireMessage;
use leansim::network::swarm::{
    build_swarm, next_event, peer_id_for, publish, ExplicitPeerManager, LinkStats, NetEvent,
    SimBehaviour,
};
use leansim::network::topics::subnet_topic;
use libp2p::{gossipsub::IdentTopic, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};

const STABLE: u32 = 0;
const CHURNY: u32 = 1;
const PATIENCE: Duration = Duration::from_secs(20);

fn config() -> ExperimentConfig {
    toml::from_str(
        r#"
run_id = "churn"
validator_count = 4
subnet_count = 1
signature_payload_bytes = 200
gossipsub_mesh_n_low = 1
gossipsub_mesh_n = 2
gossipsub_mesh_n_high = 3
gossipsub_mesh_outbound_min = 0
gossipsub_heartbeat_interval_ms = 100
"#,
    )
    .unwrap()
}

/// A loopback address on a port that was free a moment ago.
fn free_addr() -> String {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
}

/// What the test sees of a host.
#[derive(Debug, Default, Clone, Copy)]
struct View {
    /// Connected to the other host.
    connected: bool,
    /// The other host is in this one's mesh.
    meshed: bool,
    /// Times the last connection to the other host closed.
    gone: u32,
    /// New gossip messages received.
    heard: u32,
    links: LinkStats,
}

struct Host {
    node_id: u32,
    swarm: Swarm<SimBehaviour>,
    peers: ExplicitPeerManager,
    other: PeerId,
    topic: IdentTopic,
    said: u64,
    view: View,
}

impl Host {
    fn new(node_id: u32, other: u32, listen: &str, config: &ExperimentConfig) -> Self {
        let mut swarm = build_swarm(node_id, listen, config).unwrap();
        let topic = IdentTopic::new(subnet_topic(&config.run_id, 0));
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
        Self {
            node_id,
            swarm,
            peers: ExplicitPeerManager::new(&[], &[]).unwrap(),
            other: peer_id_for(other),
            topic,
            said: 0,
            view: View::default(),
        }
    }

    async fn listen_addr(&mut self) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = self.swarm.select_next_some().await {
                return address;
            }
        }
    }

    /// Handles the host's next event, if one comes soon, and refreshes its view.
    async fn step(&mut self) {
        let event = tokio::time::timeout(
            Duration::from_millis(20),
            next_event(&mut self.swarm, &mut self.peers),
        );
        match event.await {
            Ok(Some(NetEvent::PeerDisconnected { peer })) if peer == self.other => {
                self.view.gone += 1
            }
            Ok(Some(NetEvent::Gossip(message))) if !message.is_duplicate => self.view.heard += 1,
            _ => {}
        }
        self.view.connected = self.swarm.is_connected(&self.other);
        self.view.meshed = self
            .swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&self.topic.hash())
            .any(|peer| *peer == self.other);
        self.view.links = self.peers.link_stats();
    }

    /// Publishes one signature-sized message.
    fn say(&mut self) {
        self.said += 1;
        let message = WireMessage::ValidatorSignature {
            run_id: "churn".into(),
            sender_id: self.node_id,
            validator_id: self.node_id,
            subnet_id: 0,
            sequence_id: self.said,
            created_timestamp_ms: 0,
            padding: vec![],
        }
        .with_payload_size(200);
        publish(&mut self.swarm, &self.topic, &message).unwrap();
    }
}

/// The host that stays: it runs on a thread of its own for the whole test.
struct Stable {
    addr: Multiaddr,
    view: Arc<Mutex<View>>,
    speak: Arc<AtomicU32>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Stable {
    fn start(config: &ExperimentConfig) -> Self {
        let view = Arc::new(Mutex::new(View::default()));
        let speak = Arc::new(AtomicU32::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (addr_tx, addr_rx) = mpsc::channel();
        let thread = {
            let (config, view, speak, stop) =
                (config.clone(), view.clone(), speak.clone(), stop.clone());
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let mut host =
                        Host::new(STABLE, CHURNY, "/ip4/127.0.0.1/udp/0/quic-v1", &config);
                    addr_tx.send(host.listen_addr().await).unwrap();
                    let mut spoken = 0;
                    while !stop.load(Ordering::SeqCst) {
                        host.step().await;
                        *view.lock().unwrap() = host.view;
                        if speak.load(Ordering::SeqCst) > spoken {
                            spoken += 1;
                            host.say();
                        }
                    }
                });
            })
        };
        Self {
            addr: addr_rx.recv().unwrap(),
            view,
            speak,
            stop,
            thread: Some(thread),
        }
    }

    fn view(&self) -> View {
        *self.view.lock().unwrap()
    }
}

impl Drop for Stable {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// One session of the churny host on `listen`: it dials the stable host and
/// runs until `done`, or for `patience` at most. Then it crashes as a leansim
/// host does: its runtime is dropped with the session's sockets and tasks.
/// Returns its last view and whether `done` held.
fn session(
    config: &ExperimentConfig,
    listen: &str,
    stable: &Stable,
    restarted: bool,
    patience: Duration,
    mut done: impl FnMut(&mut Host, View) -> bool,
) -> (View, bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = runtime.block_on(async {
        let mut host = Host::new(CHURNY, STABLE, listen, config);
        if restarted {
            host.peers.announce_restart(SystemTime::now());
        }
        host.swarm.dial(stable.addr.clone()).unwrap();
        let deadline = Instant::now() + patience;
        loop {
            host.step().await;
            if done(&mut host, stable.view()) {
                break (host.view, true);
            }
            if Instant::now() >= deadline {
                break (host.view, false);
            }
        }
    });
    drop(runtime);
    outcome
}

/// A first session until both hosts have each other in their mesh, then a crash.
fn mesh_then_crash(config: &ExperimentConfig, listen: &str, stable: &Stable) {
    let (_, meshed) = session(config, listen, stable, false, PATIENCE, |host, stable| {
        host.view.meshed && stable.meshed
    });
    assert!(meshed, "the hosts never meshed");
}

#[test]
fn a_crashed_host_goes_silently_and_rejoins_on_its_port() {
    let config = config();
    let stable = Stable::start(&config);
    let listen = free_addr();
    mesh_then_crash(&config, &listen, &stable);

    // The crash sent nothing: the stable host still believes in the connection.
    std::thread::sleep(Duration::from_millis(500));
    let left = stable.view();
    assert!(left.connected, "the crash closed the connection");
    assert_eq!(left.gone, 0);

    // Back on the same port with no state. The stable host drops what it knew
    // (its old connection is reset by the new session, or it is told of the
    // restart) and both mesh again; then gossip flows both ways.
    let mut spoke = false;
    let (churny, done) = session(
        &config,
        &listen,
        &stable,
        true,
        PATIENCE,
        |host, stable_view| {
            if !spoke && host.view.meshed && stable_view.meshed && stable_view.gone >= 1 {
                spoke = true;
                host.say();
                stable.speak.fetch_add(1, Ordering::SeqCst);
            }
            spoke && host.view.heard >= 1 && stable_view.heard >= 1
        },
    );
    assert!(
        done,
        "no gossip both ways after the rejoin: {churny:?} / {:?}",
        stable.view()
    );
    assert_eq!(churny.links.restart_notices_sent, 1);
}

#[test]
fn a_peer_drops_its_stale_connection_when_told_of_the_restart() {
    let config = config();
    let stable = Stable::start(&config);
    mesh_then_crash(&config, &free_addr(), &stable);

    // On another port nothing resets the stable host's old connection, so it has
    // an old and a new one until the restart notice arrives.
    let (churny, done) = session(
        &config,
        &free_addr(),
        &stable,
        true,
        PATIENCE,
        |host, stable| host.view.meshed && stable.meshed && stable.gone >= 1,
    );
    assert!(
        done,
        "no mesh after the rejoin: {churny:?} / {:?}",
        stable.view()
    );
    assert_eq!(churny.links.restart_notices_sent, 1);
    assert_eq!(stable.view().links.restart_reconnects, 1);
}

#[test]
fn without_the_restart_notice_the_rejoined_host_stays_out_of_the_mesh() {
    let config = config();
    let stable = Stable::start(&config);
    mesh_then_crash(&config, &free_addr(), &stable);

    // Gossipsub greets only the first connection to a peer, so the stable host
    // never sends the new session its subscriptions.
    let (churny, meshed) = session(
        &config,
        &free_addr(),
        &stable,
        false,
        Duration::from_secs(3),
        |host, _| host.view.meshed,
    );
    assert!(!meshed, "meshed without a notice: {churny:?}");
    assert!(churny.connected);
}
