//! The SEACAST arm of the proof-only benchmark: `seacast::Seacast` on one Waggle topic.
//!
//! A link joins once both subscription streams of the topic are open: ours to the peer
//! (we receive on it) and the peer's to us (we write to it). Each message is one
//! `ObjectPieces` (seacast-bindings.md §3). A writer hands the transport a message only
//! while fewer than two of its messages wait in the peer's Waggle queue, so the backlog
//! stays in SEACAST's own queue where cancel, projection and rarest-first act on it
//! (seacast-lite.md §7.3), as far as the channel can tell.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use libp2p::{swarm::ConnectionId, PeerId};
use tokio::time::Instant;
use waggle::{
    behaviour::Event,
    handler::{PieceSender, TopicEvent},
};

use super::seacast::{Seacast, Stats};
use super::subnet_proofs::ProofKey;

/// How often a busy writer's Waggle queue is looked at.
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Messages a writer may leave in the peer's Waggle queue.
const QUEUE_DEPTH: usize = 2;

struct Link {
    id: ConnectionId,
    receiving: bool,
    sender: Option<PieceSender>,
}

pub(crate) struct ProofSeacast {
    topic: Vec<u8>,
    inner: Seacast,
    links: BTreeMap<PeerId, Link>,
    senders: BTreeMap<PeerId, PieceSender>,
    busy: BTreeSet<PeerId>,
}

impl ProofSeacast {
    pub(crate) fn new(inner: Seacast, topic: Vec<u8>) -> Self {
        Self {
            topic,
            inner,
            links: BTreeMap::new(),
            senders: BTreeMap::new(),
            busy: BTreeSet::new(),
        }
    }

    pub(crate) fn max_message_bytes(&self) -> usize {
        self.inner.max_message_bytes()
    }

    /// Hands every message the writers produced to Waggle, and lets a writer go on
    /// while its queue is short.
    fn pump(&mut self, now: Instant) {
        loop {
            let writes = self.inner.take_writes();
            if writes.is_empty() {
                break;
            }
            for (peer, message) in writes {
                match self.senders.get(&peer) {
                    Some(sender) if sender.try_send(message).is_ok() => {
                        if sender.len() < QUEUE_DEPTH {
                            self.inner.write_done(peer, now);
                        } else {
                            self.busy.insert(peer);
                        }
                    }
                    // The stream went away under the write: the link goes down next.
                    _ => self.inner.write_done(peer, now),
                }
            }
        }
    }

    pub(crate) fn release(&mut self, key: ProofKey, data: &[u8]) -> anyhow::Result<()> {
        let now = Instant::now();
        self.inner.note_release_mesh();
        self.inner.release(key, data, now)?;
        self.pump(now);
        Ok(())
    }

    /// The next instant this host has something to do without a message arriving.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        let poll = (!self.busy.is_empty()).then(|| Instant::now() + POLL_INTERVAL);
        match (self.inner.next_due(), poll) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub(crate) fn drive(&mut self) {
        let now = Instant::now();
        let ready: Vec<PeerId> = self
            .busy
            .iter()
            .filter(|p| self.senders.get(p).is_none_or(|s| s.len() < QUEUE_DEPTH))
            .copied()
            .collect();
        for peer in ready {
            self.busy.remove(&peer);
            self.inner.write_done(peer, now);
        }
        self.inner.on_timer(now);
        self.pump(now);
    }

    fn link(&mut self, peer: PeerId, id: ConnectionId) -> Option<&mut Link> {
        let link = self.links.entry(peer).or_insert(Link {
            id,
            receiving: false,
            sender: None,
        });
        (link.id == id).then_some(link)
    }

    fn ready(&mut self, peer: PeerId) {
        let Some(sender) = self
            .links
            .get(&peer)
            .filter(|l| l.receiving)
            .and_then(|l| l.sender.clone())
        else {
            return;
        };
        let now = Instant::now();
        if self.senders.insert(peer, sender).is_some() {
            // A replaced stream: what was queued on the old one may be lost.
            self.inner.link_down(peer, now);
        }
        self.busy.remove(&peer);
        self.inner.link_up(peer, now);
        self.pump(now);
    }

    fn not_ready(&mut self, peer: PeerId) {
        if self.senders.remove(&peer).is_some() {
            let now = Instant::now();
            self.busy.remove(&peer);
            self.inner.link_down(peer, now);
            self.pump(now);
        }
    }

    pub(crate) fn disconnected(&mut self, peer: PeerId, id: ConnectionId) {
        if self.links.get(&peer).is_some_and(|l| l.id == id) {
            self.links.remove(&peer);
            self.not_ready(peer);
        }
    }

    pub(crate) fn on_behaviour(&mut self, event: Event) {
        match event {
            Event::Subscribed {
                peer_id,
                connection_id,
                topic_id,
                sender,
            } if topic_id == self.topic => {
                if let Some(link) = self.link(peer_id, connection_id) {
                    link.sender = Some(sender);
                    self.ready(peer_id);
                }
            }
            Event::Unsubscribed {
                peer_id,
                connection_id,
                topic_id,
            } if topic_id == self.topic => {
                if let Some(link) = self
                    .links
                    .get_mut(&peer_id)
                    .filter(|l| l.id == connection_id)
                {
                    link.sender = None;
                    self.not_ready(peer_id);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn on_topic(&mut self, event: TopicEvent) -> Option<ProofKey> {
        match event {
            TopicEvent::Opened {
                peer_id,
                connection_id,
            } => {
                if let Some(link) = self.link(peer_id, connection_id) {
                    link.receiving = true;
                    self.ready(peer_id);
                }
                None
            }
            TopicEvent::Closed {
                peer_id,
                connection_id,
            } => {
                if let Some(link) = self
                    .links
                    .get_mut(&peer_id)
                    .filter(|l| l.id == connection_id)
                {
                    link.receiving = false;
                    self.not_ready(peer_id);
                }
                None
            }
            TopicEvent::Pieces {
                peer_id,
                connection_id,
                pieces,
            } => {
                if !self
                    .links
                    .get(&peer_id)
                    .is_some_and(|l| l.id == connection_id && l.receiving)
                {
                    return None;
                }
                let now = Instant::now();
                let done = self.inner.receive(peer_id, &pieces, now);
                self.pump(now);
                done
            }
        }
    }

    pub(crate) fn stats(&self) -> Stats {
        let mut stats = self.inner.stats.clone();
        stats.max_mesh = stats.max_mesh.max(self.inner.mesh_size());
        stats
    }

    pub(crate) fn pending(&self) -> usize {
        self.inner.pending()
    }

    pub(crate) fn mesh_size(&self) -> usize {
        self.inner.mesh_size()
    }
}
