//! Arithmetic in GF(2^8) with the AES/RLNC-standard polynomial x^8+x^4+x^3+x^2+1
//! (0x11d). Addition is XOR; multiplication and inversion use log/exp tables.

use std::sync::OnceLock;

struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for (i, slot) in exp.iter_mut().take(255).enumerate() {
            *slot = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Tables { exp, log }
    })
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

/// Multiplicative inverse; `a` must be non-zero.
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "zero has no inverse in GF(2^8)");
    let t = tables();
    t.exp[255 - t.log[a as usize] as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a = {a}");
        }
    }

    #[test]
    fn multiplication_distributes_over_xor() {
        for a in [1u8, 2, 3, 0x53, 0xca, 0xff] {
            for b in [0u8, 1, 7, 0x80, 0xfe] {
                for c in [0u8, 5, 0x1d, 0xff] {
                    assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
                }
            }
        }
    }

    #[test]
    fn known_product() {
        // 2 * 0x80 overflows and reduces by the polynomial.
        assert_eq!(mul(2, 0x80), 0x1d);
        assert_eq!(mul(0, 0x80), 0);
    }
}
