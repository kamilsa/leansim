//! The launcher's aggregation plan (`aggregation-plan.json`): which proofs each
//! host announces to whom, and the recursive groups it holds seats in.

use std::collections::{BTreeSet, HashMap};

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AggregationPlan {
    /// Listen address of every host named in `duties`.
    #[serde(default)]
    pub addrs: HashMap<u32, String>,
    /// Proof duties per host; hosts without any are absent.
    #[serde(default)]
    pub duties: HashMap<u32, NodeDuties>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct NodeDuties {
    #[serde(default)]
    pub subnets: Vec<SubnetDuty>,
    #[serde(default)]
    pub seats: Vec<Seat>,
}

/// A subnet this host aggregates, and the members of the layer-1 group that
/// aggregates it (this host excluded), who hear about its proof.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SubnetDuty {
    pub subnet: u32,
    pub announce_to: Vec<u32>,
}

/// One seat in recursive group `index` of `layer`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Seat {
    pub layer: u32,
    pub index: u32,
    /// The group's children: indices in layer `layer - 1` (subnets for layer 1).
    pub children: Vec<u32>,
    /// The group's other members.
    pub siblings: Vec<u32>,
    /// Members of the parent group (this host excluded); empty for the final group.
    pub announce_to: Vec<u32>,
    pub is_final: bool,
}

impl AggregationPlan {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("reading aggregation plan {path}: {error}"))?;
        serde_json::from_str(&text)
            .map_err(|error| anyhow::anyhow!("parsing aggregation plan {path}: {error}"))
    }

    pub fn duties_of(&self, node_id: u32) -> NodeDuties {
        self.duties.get(&node_id).cloned().unwrap_or_default()
    }
}

impl NodeDuties {
    /// Every host this one announces to, dialed during warmup. Mirrors
    /// `proof_peers` in shadow-sim.py.
    pub fn peers(&self) -> BTreeSet<u32> {
        let subnets = self.subnets.iter().flat_map(|duty| duty.announce_to.iter());
        let seats = self
            .seats
            .iter()
            .flat_map(|seat| seat.siblings.iter().chain(seat.announce_to.iter()));
        subnets.chain(seats).copied().collect()
    }
}
