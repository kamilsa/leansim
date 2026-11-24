//! Systematic Reed–Solomon over GF(2^8) (polynomial 0x11d), built from a Cauchy
//! matrix: shards `0..k` are the data and `k..n` the parity, and any `k` distinct
//! shards rebuild the data. SEACAST Lite codes a payload with the same field and the
//! same rate (`n = 2k`); it evaluates a polynomial at `0..n-1`, which is a different
//! MDS code with the same property.
use std::sync::OnceLock;

use super::gf256;

fn mul_table() -> &'static [[u8; 256]; 256] {
    static TABLE: OnceLock<Box<[[u8; 256]; 256]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Box::new([[0u8; 256]; 256]);
        for a in 0..256 {
            for b in 0..256 {
                table[a][b] = gf256::mul(a as u8, b as u8);
            }
        }
        table
    })
}

/// `dst ^= c * src`, byte by byte.
fn mul_add(dst: &mut [u8], src: &[u8], c: u8) {
    if c == 0 {
        return;
    }
    let row = &mul_table()[usize::from(c)];
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= row[usize::from(*s)];
    }
}

pub struct Code {
    k: usize,
    n: usize,
    /// `(n - k) × k`: parity shard `j` is the sum of `parity[j][i] · data[i]`.
    parity: Vec<Vec<u8>>,
}

impl Code {
    pub fn new(k: usize, n: usize) -> Self {
        assert!(0 < k && k <= n && n <= 256, "invalid code ({k}, {n})");
        // Cauchy entries 1 / (x_j + y_i) with x_j = k + j and y_i = i: all points are
        // distinct, so every square submatrix of [I; C] is invertible.
        let parity = (0..n - k)
            .map(|j| {
                (0..k)
                    .map(|i| gf256::inv((k + j) as u8 ^ i as u8))
                    .collect()
            })
            .collect();
        Self { k, n, parity }
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn n(&self) -> usize {
        self.n
    }

    fn row(&self, index: usize) -> Vec<u8> {
        if index < self.k {
            let mut row = vec![0; self.k];
            row[index] = 1;
            row
        } else {
            self.parity[index - self.k].clone()
        }
    }

    /// The `n - k` parity shards of `k` equal-length data shards.
    pub fn encode(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.k);
        let len = data[0].len();
        self.parity
            .iter()
            .map(|row| {
                let mut out = vec![0; len];
                for (c, shard) in row.iter().zip(data) {
                    mul_add(&mut out, shard, *c);
                }
                out
            })
            .collect()
    }

    /// The `k` data shards from any `k` distinct shards `(index, bytes)`; `None` if
    /// there are fewer than `k` distinct valid indices or the lengths differ.
    pub fn reconstruct(&self, shards: &[(usize, &[u8])]) -> Option<Vec<Vec<u8>>> {
        let mut chosen: Vec<(usize, &[u8])> = Vec::with_capacity(self.k);
        for &(index, bytes) in shards {
            if index < self.n && !chosen.iter().any(|(i, _)| *i == index) {
                chosen.push((index, bytes));
                if chosen.len() == self.k {
                    break;
                }
            }
        }
        if chosen.len() < self.k {
            return None;
        }
        let len = chosen[0].1.len();
        if chosen.iter().any(|(_, b)| b.len() != len) {
            return None;
        }
        let mut data: Vec<Option<Vec<u8>>> = vec![None; self.k];
        for &(index, bytes) in &chosen {
            if index < self.k {
                data[index] = Some(bytes.to_vec());
            }
        }
        if data.iter().all(Option::is_some) {
            return Some(data.into_iter().map(Option::unwrap).collect());
        }
        let inverse = invert(chosen.iter().map(|(i, _)| self.row(*i)).collect())?;
        for (i, slot) in data.iter_mut().enumerate() {
            if slot.is_none() {
                let mut out = vec![0; len];
                for (c, (_, bytes)) in inverse[i].iter().zip(&chosen) {
                    mul_add(&mut out, bytes, *c);
                }
                *slot = Some(out);
            }
        }
        Some(data.into_iter().map(Option::unwrap).collect())
    }
}

/// Gauss–Jordan inversion of a square matrix over GF(2^8).
fn invert(mut m: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let size = m.len();
    let mut inv: Vec<Vec<u8>> = (0..size)
        .map(|i| {
            let mut row = vec![0; size];
            row[i] = 1;
            row
        })
        .collect();
    for col in 0..size {
        let pivot = (col..size).find(|&r| m[r][col] != 0)?;
        m.swap(col, pivot);
        inv.swap(col, pivot);
        let scale = gf256::inv(m[col][col]);
        for x in 0..size {
            m[col][x] = gf256::mul(m[col][x], scale);
            inv[col][x] = gf256::mul(inv[col][x], scale);
        }
        for r in 0..size {
            let factor = m[r][col];
            if r != col && factor != 0 {
                for x in 0..size {
                    m[r][x] ^= gf256::mul(factor, m[col][x]);
                    inv[r][x] ^= gf256::mul(factor, inv[col][x]);
                }
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, seq::SliceRandom, RngCore, SeedableRng};

    #[test]
    fn any_k_shards_rebuild_the_data() {
        let code = Code::new(8, 16);
        let mut rng = StdRng::seed_from_u64(1);
        let data: Vec<Vec<u8>> = (0..8)
            .map(|_| {
                let mut s = vec![0; 37];
                rng.fill_bytes(&mut s);
                s
            })
            .collect();
        let parity = code.encode(&data);
        let all: Vec<Vec<u8>> = data.iter().chain(&parity).cloned().collect();
        for _ in 0..50 {
            let mut idx: Vec<usize> = (0..16).collect();
            idx.shuffle(&mut rng);
            let pick: Vec<(usize, &[u8])> = idx[..8].iter().map(|&i| (i, &all[i][..])).collect();
            assert_eq!(code.reconstruct(&pick).unwrap(), data);
        }
        // Parity alone is enough, and fewer than k shards are not.
        let parity_only: Vec<(usize, &[u8])> = (8..16).map(|i| (i, &all[i][..])).collect();
        assert_eq!(code.reconstruct(&parity_only).unwrap(), data);
        assert!(code.reconstruct(&parity_only[..7]).is_none());
    }

    #[test]
    fn a_full_rate_half_code_of_64_rebuilds() {
        let code = Code::new(64, 128);
        let data: Vec<Vec<u8>> = (0..64u8).map(|i| vec![i.wrapping_mul(7); 5]).collect();
        let parity = code.encode(&data);
        let pick: Vec<(usize, &[u8])> = (0..64).map(|j| (64 + j, &parity[j][..])).collect();
        assert_eq!(code.reconstruct(&pick).unwrap(), data);
    }
}
