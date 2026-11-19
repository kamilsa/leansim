//! Pieces and receiver state for the proof-only dissemination experiment.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub type Root = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofKey {
    pub subnet: u32,
    pub producer: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Piece {
    pub key: ProofKey,
    pub index: usize,
    pub data: Vec<u8>,
    pub branch: Vec<Root>,
}

fn parent(left: &Root, right: &Root) -> Root {
    let mut hash = Sha256::new();
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

pub fn pieces(key: ProofKey, data: &[u8], count: usize) -> (Root, Vec<Piece>) {
    assert!(count.is_power_of_two());
    let stride = data.len().div_ceil(count);
    let mut chunks: Vec<_> = (0..count)
        .map(|index| Piece {
            key,
            index,
            data: data[(index * stride).min(data.len())..((index + 1) * stride).min(data.len())]
                .to_vec(),
            branch: Vec::new(),
        })
        .collect();
    let mut layer: Vec<Root> = chunks
        .iter()
        .map(|p| Sha256::digest(&p.data).into())
        .collect();
    for depth in 0..count.trailing_zeros() {
        for chunk in &mut chunks {
            chunk.branch.push(layer[(chunk.index >> depth) ^ 1]);
        }
        let (pairs, _) = layer.as_chunks::<2>();
        layer = pairs
            .iter()
            .map(|[left, right]| parent(left, right))
            .collect();
    }
    (layer[0], chunks)
}

impl Piece {
    pub fn verify(&self, root: Root, count: usize, total_bytes: usize) -> bool {
        if !count.is_power_of_two()
            || self.index >= count
            || self.branch.len() != count.trailing_zeros() as usize
        {
            return false;
        }
        let stride = total_bytes.div_ceil(count);
        let expected_len = stride.min(total_bytes.saturating_sub(self.index * stride));
        if self.data.len() != expected_len {
            return false;
        }
        let mut node = Sha256::digest(&self.data).into();
        for (level, sibling) in self.branch.iter().enumerate() {
            node = if (self.index >> level) & 1 == 0 {
                parent(&node, sibling)
            } else {
                parent(sibling, &node)
            };
        }
        node == root
    }
}

/// Only verified pieces reach this counter; the simulator has no proof consumer.
#[derive(Default)]
pub struct Assembly(BTreeMap<ProofKey, BTreeSet<usize>>);

impl Assembly {
    pub fn insert(&mut self, piece: &Piece, count: usize) -> bool {
        let have = self.0.entry(piece.key).or_default();
        have.insert(piece.index) && have.len() == count
    }
}

#[derive(Default)]
pub struct Pulls(BTreeMap<ProofKey, Pull>);

#[derive(Default)]
struct Pull {
    have: bool,
    active: Option<u32>,
    untried: BTreeSet<u32>,
    seen: BTreeSet<u32>,
}

impl Pull {
    fn next(&mut self) -> Option<u32> {
        if self.have || self.active.is_some() {
            return None;
        }
        self.active = self.untried.pop_first();
        self.active
    }
}

impl Pulls {
    pub fn holds(&self, key: ProofKey) -> bool {
        self.0.get(&key).is_some_and(|pull| pull.have)
    }

    pub fn announce(&mut self, key: ProofKey, provider: u32) -> Option<u32> {
        let pull = self.0.entry(key).or_default();
        if !pull.have && pull.seen.insert(provider) {
            pull.untried.insert(provider);
        }
        pull.next()
    }

    pub fn failed(&mut self, key: ProofKey, provider: u32) -> Option<u32> {
        let pull = self.0.get_mut(&key)?;
        if pull.active != Some(provider) {
            return None;
        }
        pull.active = None;
        pull.next()
    }

    pub fn finish(&mut self, key: ProofKey) -> bool {
        let pull = self.0.entry(key).or_default();
        pull.active = None;
        pull.seen.clear();
        pull.untried.clear();
        !std::mem::replace(&mut pull.have, true)
    }
}
