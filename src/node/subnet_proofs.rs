//! Pieces and receiver state for the proof-only dissemination experiment.
use libp2p::identity::{Keypair, PublicKey, SigningError};
use rand::{rngs::StdRng, RngCore, SeedableRng};
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
    /// The Merkle root this piece and its path lead to, if the piece is well formed.
    pub fn root(&self, count: usize, total_bytes: usize) -> Option<Root> {
        if !count.is_power_of_two()
            || self.index >= count
            || self.branch.len() != count.trailing_zeros() as usize
        {
            return None;
        }
        let stride = total_bytes.div_ceil(count);
        let expected_len = stride.min(total_bytes.saturating_sub(self.index * stride));
        if self.data.len() != expected_len {
            return None;
        }
        let mut node = Sha256::digest(&self.data).into();
        for (level, sibling) in self.branch.iter().enumerate() {
            node = if (self.index >> level) & 1 == 0 {
                parent(&node, sibling)
            } else {
                parent(sibling, &node)
            };
        }
        Some(node)
    }

    pub fn verify(&self, root: Root, count: usize, total_bytes: usize) -> bool {
        self.root(count, total_bytes) == Some(root)
    }
}

/// Size of the one signature over a proof's Merkle root.
pub const COMMITMENT_SIGNATURE_BYTES: usize = 2400;
const ED25519_BYTES: usize = 64;

fn commitment_bytes(key: ProofKey, root: Root) -> Vec<u8> {
    let mut bytes = b"leansim-proof-commitment".to_vec();
    bytes.extend_from_slice(&key.subnet.to_le_bytes());
    bytes.extend_from_slice(&key.producer.to_le_bytes());
    bytes.extend_from_slice(&root);
    bytes
}

fn filler(signature: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; COMMITMENT_SIGNATURE_BYTES - ED25519_BYTES];
    StdRng::from_seed(Sha256::digest(signature).into()).fill_bytes(&mut bytes);
    bytes
}

/// Signs the Merkle root built over a proof's chunks: one signature for the whole proof.
/// The simulator has no post-quantum scheme, so an Ed25519 signature authenticates and
/// deterministic filler brings it to the modelled size.
pub fn sign_commitment(
    keypair: &Keypair,
    key: ProofKey,
    root: Root,
) -> Result<Vec<u8>, SigningError> {
    let mut signature = keypair.sign(&commitment_bytes(key, root))?;
    assert_eq!(signature.len(), ED25519_BYTES);
    let filler = filler(&signature);
    signature.extend(filler);
    Ok(signature)
}

pub fn verify_commitment(public: &PublicKey, key: ProofKey, root: Root, signature: &[u8]) -> bool {
    signature.len() == COMMITMENT_SIGNATURE_BYTES && {
        let (core, rest) = signature.split_at(ED25519_BYTES);
        public.verify(&commitment_bytes(key, root), core) && rest == filler(core)
    }
}

/// Why a piece was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The piece is malformed, or no valid signature covers the root it leads to.
    Invalid,
    /// The producer signed the root it leads to, but the proof is held to another root.
    Conflict,
}

/// The signed Merkle root a host holds a proof to: that of its first valid piece.
#[derive(Default)]
pub struct Commitment(Option<(Root, Vec<u8>)>);

impl Commitment {
    pub fn signed(root: Root, signature: Vec<u8>) -> Self {
        Self(Some((root, signature)))
    }

    pub fn signature(&self) -> Option<&[u8]> {
        self.0.as_ref().map(|(_, signature)| signature.as_slice())
    }

    /// Checks the root a piece leads to against the producer's signature over it.
    /// The signature is verified once per proof; later pieces repeat it byte for byte.
    /// An empty signature passes only if `may_omit` and a signed root is already held.
    pub fn admit(
        &mut self,
        producer: &PublicKey,
        key: ProofKey,
        root: Root,
        signature: &[u8],
        may_omit: bool,
    ) -> Result<(), Refused> {
        let verified = || verify_commitment(producer, key, root, signature);
        match &self.0 {
            Some((held, _)) if *held != root => Err(if verified() {
                Refused::Conflict
            } else {
                Refused::Invalid
            }),
            Some((_, held)) => {
                if (may_omit && signature.is_empty()) || held == signature || verified() {
                    Ok(())
                } else {
                    Err(Refused::Invalid)
                }
            }
            None if verified() => {
                self.0 = Some((root, signature.to_vec()));
                Ok(())
            }
            None => Err(Refused::Invalid),
        }
    }
}

/// Only verified pieces reach this counter; the simulator has no proof consumer.
#[derive(Default)]
pub struct Assembly {
    have: BTreeMap<ProofKey, BTreeSet<usize>>,
    commitments: BTreeMap<ProofKey, Commitment>,
}

/// Outcome of a gossiped piece, which carries its producer's root signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The piece is malformed, or no valid signature covers the root it leads to.
    Invalid,
    /// The piece is validly signed, but an earlier piece pinned another root.
    Conflict,
    Held {
        complete: bool,
    },
}

impl Assembly {
    pub fn insert(&mut self, piece: &Piece, count: usize) -> bool {
        let have = self.have.entry(piece.key).or_default();
        have.insert(piece.index) && have.len() == count
    }

    /// Checks a gossiped piece against the root signature in its own message. Every
    /// message must carry the signature: a publisher cannot know what a receiver holds.
    pub fn admit(
        &mut self,
        producer: &PublicKey,
        signature: &[u8],
        piece: &Piece,
        count: usize,
        total_bytes: usize,
    ) -> Admission {
        let Some(root) = piece.root(count, total_bytes) else {
            return Admission::Invalid;
        };
        let commitment = self.commitments.entry(piece.key).or_default();
        match commitment.admit(producer, piece.key, root, signature, false) {
            Err(Refused::Invalid) => Admission::Invalid,
            Err(Refused::Conflict) => Admission::Conflict,
            Ok(()) => Admission::Held {
                complete: self.insert(piece, count),
            },
        }
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
