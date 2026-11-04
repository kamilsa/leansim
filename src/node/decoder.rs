//! Incremental Gaussian elimination over GF(2^8) for sparse coded signatures.
//!
//! Each unknown signature is a column. A coded packet is a row: coefficients on a
//! few columns plus a right-hand side, the same combination of the signatures'
//! symbols. The simulator carries no real signature bytes, so each signature is
//! stood for by a one-byte symbol: elimination on it checks that every decoded
//! signature is the one that was encoded.
//!
//! The rows stay in reduced row echelon form: every row has a pivot column that
//! is zero in all other rows. Learning a signature from elsewhere (gossip, a
//! pull) subtracts it out; a row left with a single column decodes that column.

use std::collections::BTreeMap;

use crate::node::gf256::{inv, mul};

/// Column index of a signature inside its subnet.
pub type Column = u16;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Row {
    coeffs: BTreeMap<Column, u8>,
    rhs: u8,
}

impl Row {
    /// self += c * other
    fn axpy(&mut self, c: u8, other: &Row) {
        for (&col, &value) in &other.coeffs {
            let entry = self.coeffs.entry(col).or_insert(0);
            *entry ^= mul(c, value);
            if *entry == 0 {
                self.coeffs.remove(&col);
            }
        }
        self.rhs ^= mul(c, other.rhs);
    }

    fn scale(&mut self, c: u8) {
        for value in self.coeffs.values_mut() {
            *value = mul(*value, c);
        }
        self.rhs = mul(self.rhs, c);
    }
}

/// What a received coded packet did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Insert {
    /// The packet raised the rank (it was not a combination of what was held).
    pub innovative: bool,
    /// Signatures recovered by this packet, with their symbols.
    pub decoded: Vec<(Column, u8)>,
}

#[derive(Debug, Clone)]
pub struct Decoder {
    /// Symbols of the signatures held, by column.
    known: Vec<Option<u8>>,
    /// Pending rows by pivot column.
    rows: BTreeMap<Column, Row>,
}

impl Decoder {
    pub fn new(columns: usize) -> Self {
        Self {
            known: vec![None; columns],
            rows: BTreeMap::new(),
        }
    }

    pub fn is_known(&self, col: Column) -> bool {
        self.known.get(col as usize).is_some_and(Option::is_some)
    }

    /// Rows held that do not decode anything yet.
    pub fn pending_rows(&self) -> usize {
        self.rows.len()
    }

    /// Adds a coded packet: `sum(coeff * symbol[col]) = rhs`.
    pub fn insert(&mut self, entries: &[(Column, u8)], rhs: u8) -> Insert {
        let mut row = Row {
            coeffs: BTreeMap::new(),
            rhs,
        };
        for &(col, coeff) in entries {
            if coeff == 0 || col as usize >= self.known.len() {
                continue;
            }
            match self.known[col as usize] {
                // A held signature is subtracted out of the equation.
                Some(symbol) => row.rhs ^= mul(coeff, symbol),
                None => {
                    let entry = row.coeffs.entry(col).or_insert(0);
                    *entry ^= coeff;
                    if *entry == 0 {
                        row.coeffs.remove(&col);
                    }
                }
            }
        }
        let pivots: Vec<Column> = row
            .coeffs
            .keys()
            .copied()
            .filter(|col| self.rows.contains_key(col))
            .collect();
        for pivot in pivots {
            let c = row.coeffs.get(&pivot).copied().unwrap_or(0);
            if c != 0 {
                let pivot_row = &self.rows[&pivot];
                row.axpy(c, pivot_row);
            }
        }
        if row.coeffs.is_empty() {
            return Insert::default();
        }
        self.add_reduced(row);
        Insert {
            innovative: true,
            decoded: self.harvest(),
        }
    }

    /// Records a signature obtained some other way and returns what that decodes.
    pub fn learn(&mut self, col: Column, symbol: u8) -> Vec<(Column, u8)> {
        let Some(slot) = self.known.get_mut(col as usize) else {
            return Vec::new();
        };
        if slot.is_some() {
            return Vec::new();
        }
        *slot = Some(symbol);
        if let Some(mut row) = self.rows.remove(&col) {
            // Its pivot is now known: the rest of the row is a fresh equation.
            let c = row.coeffs.remove(&col).unwrap_or(0);
            row.rhs ^= mul(c, symbol);
            if !row.coeffs.is_empty() {
                self.add_reduced(row);
            }
        } else {
            for row in self.rows.values_mut() {
                if let Some(c) = row.coeffs.remove(&col) {
                    row.rhs ^= mul(c, symbol);
                }
            }
        }
        self.harvest()
    }

    /// Adds a non-empty row that has no pivot columns of other rows.
    fn add_reduced(&mut self, mut row: Row) {
        let (&pivot, &lead) = row.coeffs.iter().next().expect("row is not empty");
        row.scale(inv(lead));
        for other in self.rows.values_mut() {
            if let Some(&c) = other.coeffs.get(&pivot) {
                other.axpy(c, &row);
            }
        }
        self.rows.insert(pivot, row);
    }

    /// Removes the rows that have only their pivot left: those columns are decoded.
    fn harvest(&mut self) -> Vec<(Column, u8)> {
        let done: Vec<Column> = self
            .rows
            .iter()
            .filter(|(_, row)| row.coeffs.len() == 1)
            .map(|(&pivot, _)| pivot)
            .collect();
        let mut decoded = Vec::with_capacity(done.len());
        for pivot in done {
            let row = self.rows.remove(&pivot).expect("row listed above");
            // Pivots are normalised to 1, so the row reads symbol = rhs.
            self.known[pivot as usize] = Some(row.rhs);
            decoded.push((pivot, row.rhs));
        }
        decoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn symbol(col: Column) -> u8 {
        (col as u8).wrapping_mul(37).wrapping_add(11)
    }

    fn packet(entries: &[(Column, u8)]) -> u8 {
        entries
            .iter()
            .fold(0, |acc, &(col, coeff)| acc ^ mul(coeff, symbol(col)))
    }

    #[test]
    fn xor_of_two_decodes_once_one_is_learned() {
        let mut decoder = Decoder::new(8);
        let entries = [(2, 1), (5, 1)];
        let outcome = decoder.insert(&entries, packet(&entries));
        assert!(outcome.innovative);
        assert!(outcome.decoded.is_empty());
        assert_eq!(decoder.learn(2, symbol(2)), vec![(5, symbol(5))]);
        assert_eq!(decoder.pending_rows(), 0);
    }

    #[test]
    fn packet_over_held_columns_decodes_the_missing_one() {
        let mut decoder = Decoder::new(8);
        decoder.learn(1, symbol(1));
        decoder.learn(3, symbol(3));
        let entries = [(1, 7), (3, 200), (6, 9)];
        let outcome = decoder.insert(&entries, packet(&entries));
        assert_eq!(outcome.decoded, vec![(6, symbol(6))]);
    }

    #[test]
    fn redundant_packet_is_not_innovative() {
        let mut decoder = Decoder::new(8);
        let a = [(0, 3), (1, 5)];
        let b = [(0, mul(3, 9)), (1, mul(5, 9))];
        assert!(decoder.insert(&a, packet(&a)).innovative);
        assert!(!decoder.insert(&b, packet(&b)).innovative);
        assert_eq!(decoder.pending_rows(), 1);
    }

    #[test]
    fn random_sparse_packets_decode_every_column_correctly() {
        let mut rng = StdRng::seed_from_u64(7);
        for trial in 0..20 {
            let n = 64usize;
            let mut decoder = Decoder::new(n);
            // A random third of the columns arrive uncoded at random times.
            let mut decoded = std::collections::BTreeMap::new();
            let mut packets = 0;
            while decoded.len() < n && packets < 10 * n {
                if rng.gen_bool(0.3) {
                    let col = rng.gen_range(0..n) as Column;
                    if !decoder.is_known(col) {
                        decoded.insert(col, symbol(col));
                        for (c, s) in decoder.learn(col, symbol(col)) {
                            decoded.insert(c, s);
                        }
                    }
                    continue;
                }
                packets += 1;
                let degree = rng.gen_range(1..=4);
                let entries: Vec<(Column, u8)> = (0..degree)
                    .map(|_| (rng.gen_range(0..n) as Column, rng.gen_range(1..=255)))
                    .collect();
                for (c, s) in decoder.insert(&entries, packet(&entries)).decoded {
                    decoded.insert(c, s);
                }
            }
            assert_eq!(decoded.len(), n, "trial {trial} did not finish");
            for (col, s) in decoded {
                assert_eq!(s, symbol(col), "trial {trial}: column {col} decoded wrong");
            }
        }
    }
}
