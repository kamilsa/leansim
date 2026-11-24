//! Integrated slot pipeline: authenticated Waggle pieces, each carrying its producer's
//! signed commitment, for local committee proofs and the selected proposer's combined proof.
use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{ensure, Result};
use serde::Deserialize;
use tokio::time::Instant;

use super::subnet_proof_run::prepare;
use super::subnet_proofs::{pieces, ProofKey, COMMITMENT_SIGNATURE_BYTES};
use crate::config::experiment::{NodeConfig, SignatureTransport};
use crate::network::swarm::SimBehaviour;

pub const CHUNKS: usize = 16;
pub const DRIVE_INTERVAL: Duration = super::subnet_proof_waggle::DRIVE_INTERVAL;

#[derive(Debug, Deserialize)]
pub struct Settings {
    proposer: u32,
    producers: Vec<ProofKey>,
}

pub struct Proposer {
    committees: usize,
    held: BTreeSet<u32>,
    compute: Duration,
    due: Option<Instant>,
}

impl Proposer {
    pub fn new(committees: usize, compute: Duration) -> Self {
        Self {
            committees,
            held: BTreeSet::new(),
            compute,
            due: None,
        }
    }

    pub fn hold(&mut self, subnet: u32, now: Instant) {
        if (subnet as usize) < self.committees
            && self.held.insert(subnet)
            && self.held.len() == self.committees
        {
            self.due = Some(now + self.compute);
        }
    }

    pub fn due(&self) -> Option<Instant> {
        self.due
    }

    pub fn finish(&mut self, now: Instant) -> bool {
        if self.due.is_some_and(|due| due <= now) {
            self.due = None;
            true
        } else {
            false
        }
    }
}

pub struct Pipeline {
    node: u32,
    allowed: BTreeSet<ProofKey>,
    global: ProofKey,
    proposer: Option<Proposer>,
}

impl Pipeline {
    pub fn new(cfg: &NodeConfig, settings: &Settings) -> Result<Self> {
        let exp = &cfg.experiment;
        ensure!(
            exp.signature_transport == SignatureTransport::Waggle && !exp.churn_enabled(),
            "the proof pipeline requires Waggle signatures without churn"
        );
        ensure!(
            cfg.aggregation_plan.is_none(),
            "the proof pipeline replaces the recursive tree"
        );
        ensure!(
            exp.aggregate_proof_bytes.div_ceil(CHUNKS) + COMMITMENT_SIGNATURE_BYTES + 1024
                <= exp.waggle_max_message_bytes(),
            "the shared Waggle message limit is too small for a proof chunk"
        );
        let committees = u32::try_from(exp.subnet_count)?;
        let global = ProofKey {
            subnet: committees,
            producer: settings.proposer,
        };
        let mut allowed = BTreeSet::new();
        let mut counts = vec![0; exp.subnet_count];
        for &key in &settings.producers {
            ensure!(
                key.subnet < committees,
                "invalid committee in producer roster"
            );
            ensure!(allowed.insert(key), "duplicate producer duty");
            counts[key.subnet as usize] += 1;
        }
        ensure!(
            counts
                .iter()
                .all(|&n| n > 0 && n == exp.local_aggregators_per_subnet),
            "incorrect producer count per committee"
        );
        ensure!(
            allowed
                .iter()
                .filter(|key| key.producer == cfg.node_id)
                .map(|key| key.subnet)
                .collect::<BTreeSet<_>>()
                == cfg.aggregated_subnets().into_iter().collect(),
            "producer roster does not match this host's aggregation duties"
        );
        allowed.insert(global);
        Ok(Self {
            node: cfg.node_id,
            allowed,
            global,
            proposer: (cfg.node_id == global.producer).then(|| {
                Proposer::new(
                    exp.subnet_count,
                    Duration::from_millis(exp.recursive_aggregation_time_ms),
                )
            }),
        })
    }

    pub fn chunk_topic(run_id: &str) -> Vec<u8> {
        format!("/leansim/{run_id}/subnet-proof-waggle/1").into_bytes()
    }

    /// Every proof this run disseminates: the committee duties and the proposer's global proof.
    pub fn roster(&self) -> Vec<ProofKey> {
        self.allowed.iter().copied().collect()
    }

    pub fn publish(
        &self,
        behaviour: &mut SimBehaviour,
        cfg: &NodeConfig,
        subnet: u32,
    ) -> Result<ProofKey> {
        let key = ProofKey {
            subnet,
            producer: self.node,
        };
        ensure!(
            self.allowed.contains(&key),
            "cannot publish without a proof duty"
        );
        let (root, chunks) = pieces(key, &prepare(key, &cfg.experiment), CHUNKS);
        let waggle = behaviour.waggle.as_mut().expect("validated Waggle config");
        waggle.release_proof(key, root, chunks)?;
        Ok(key)
    }

    pub fn completed(&mut self, key: ProofKey, ts_ms: u64) {
        let kind = if key == self.global {
            "WaggleGlobalHeld"
        } else {
            "WaggleCommitteeHeld"
        };
        println!(
            "{}",
            serde_json::json!({"event":kind,"node_id":self.node,"subnet_id":key.subnet,"producer":key.producer,"ts_ms":ts_ms})
        );
        if let Some(proposer) = &mut self.proposer {
            let waiting = proposer.due().is_none();
            proposer.hold(key.subnet, Instant::now());
            if waiting && proposer.due().is_some() {
                println!(
                    "{}",
                    serde_json::json!({"event":"WaggleProposerReady","node_id":self.node,"ts_ms":ts_ms})
                );
            }
        }
    }

    pub fn due(&self) -> Option<Instant> {
        self.proposer.as_ref().and_then(Proposer::due)
    }

    pub fn take_global(&mut self, now: Instant, ts_ms: u64) -> Option<u32> {
        self.proposer.as_mut().filter(|p| p.due().is_some())?;
        if !self.proposer.as_mut()?.finish(now) {
            return None;
        }
        println!(
            "{}",
            serde_json::json!({"event":"WaggleGlobalGenerated","node_id":self.node,"ts_ms":ts_ms})
        );
        Some(self.global.subnet)
    }
}
