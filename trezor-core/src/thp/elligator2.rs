//! Elligator2 map to Curve25519 (RFC 9380 §map_to_curve25519), the
//! generator-derivation primitive for CPace pairing.
//!
//! Ported byte-for-byte from the Trezor firmware's
//! `map_to_curve_elligator2_curve25519` (`crypto/elligator2.c`), which
//! computes only the Montgomery u-coordinate of the mapped point. The
//! GF(2^255-19) arithmetic is the standard 5x51-bit-limb field (the
//! ed25519-dalek `FieldElement51` algorithm). Correctness is gated by
//! Trezor's own published test vectors (elligator.org
//! curve25519_direct), so a passing test == byte-exact with the device.

#![allow(dead_code)] // consumed by cpace + the pairing flow (task #7).

const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;

/// A field element in GF(2^255-19), 5 limbs of radix 2^51.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

/// Weak reduction: propagate carries so each limb is < 2^51 (+ small).
fn reduce(mut limbs: [u64; 5]) -> Fe {
    let c0 = limbs[0] >> 51;
    let c1 = limbs[1] >> 51;
    let c2 = limbs[2] >> 51;
    let c3 = limbs[3] >> 51;
    let c4 = limbs[4] >> 51;
    limbs[0] &= LOW_51_BIT_MASK;
    limbs[1] &= LOW_51_BIT_MASK;
    limbs[2] &= LOW_51_BIT_MASK;
    limbs[3] &= LOW_51_BIT_MASK;
    limbs[4] &= LOW_51_BIT_MASK;
    limbs[0] += c4 * 19;
    limbs[1] += c0;
    limbs[2] += c1;
    limbs[3] += c2;
    limbs[4] += c3;
    Fe(limbs)
}

impl Fe {
    fn zero() -> Fe {
        Fe([0; 5])
    }
    fn one() -> Fe {
        Fe([1, 0, 0, 0, 0])
    }
    fn from_u64(x: u64) -> Fe {
        Fe([x, 0, 0, 0, 0])
    }
    /// sqrt(-1) mod p.
    fn sqrt_m1() -> Fe {
        Fe([
            1_718_705_420_411_056,
            234_908_883_556_509,
            2_233_514_472_574_048,
            2_117_202_627_021_982,
            765_476_049_583_133,
        ])
    }

    fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load8 = |i: usize| -> u64 { u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap()) };
        Fe([
            load8(0) & LOW_51_BIT_MASK,
            (load8(6) >> 3) & LOW_51_BIT_MASK,
            (load8(12) >> 6) & LOW_51_BIT_MASK,
            (load8(19) >> 1) & LOW_51_BIT_MASK,
            (load8(24) >> 12) & LOW_51_BIT_MASK,
        ])
    }

    fn to_bytes(self) -> [u8; 32] {
        // Fully reduce to canonical form, then bit-pack.
        let mut limbs = reduce(self.0).0;
        // Compute q = (self + 19) >> 255, the "is >= p" carry.
        let mut q = (limbs[0] + 19) >> 51;
        q = (limbs[1] + q) >> 51;
        q = (limbs[2] + q) >> 51;
        q = (limbs[3] + q) >> 51;
        q = (limbs[4] + q) >> 51;
        limbs[0] += 19 * q;
        limbs[1] += limbs[0] >> 51;
        limbs[0] &= LOW_51_BIT_MASK;
        limbs[2] += limbs[1] >> 51;
        limbs[1] &= LOW_51_BIT_MASK;
        limbs[3] += limbs[2] >> 51;
        limbs[2] &= LOW_51_BIT_MASK;
        limbs[4] += limbs[3] >> 51;
        limbs[3] &= LOW_51_BIT_MASK;
        limbs[4] &= LOW_51_BIT_MASK;

        let mut s = [0u8; 32];
        s[0] = limbs[0] as u8;
        s[1] = (limbs[0] >> 8) as u8;
        s[2] = (limbs[0] >> 16) as u8;
        s[3] = (limbs[0] >> 24) as u8;
        s[4] = (limbs[0] >> 32) as u8;
        s[5] = (limbs[0] >> 40) as u8;
        s[6] = ((limbs[0] >> 48) | (limbs[1] << 3)) as u8;
        s[7] = (limbs[1] >> 5) as u8;
        s[8] = (limbs[1] >> 13) as u8;
        s[9] = (limbs[1] >> 21) as u8;
        s[10] = (limbs[1] >> 29) as u8;
        s[11] = (limbs[1] >> 37) as u8;
        s[12] = ((limbs[1] >> 45) | (limbs[2] << 6)) as u8;
        s[13] = (limbs[2] >> 2) as u8;
        s[14] = (limbs[2] >> 10) as u8;
        s[15] = (limbs[2] >> 18) as u8;
        s[16] = (limbs[2] >> 26) as u8;
        s[17] = (limbs[2] >> 34) as u8;
        s[18] = (limbs[2] >> 42) as u8;
        s[19] = ((limbs[2] >> 50) | (limbs[3] << 1)) as u8;
        s[20] = (limbs[3] >> 7) as u8;
        s[21] = (limbs[3] >> 15) as u8;
        s[22] = (limbs[3] >> 23) as u8;
        s[23] = (limbs[3] >> 31) as u8;
        s[24] = (limbs[3] >> 39) as u8;
        s[25] = ((limbs[3] >> 47) | (limbs[4] << 4)) as u8;
        s[26] = (limbs[4] >> 4) as u8;
        s[27] = (limbs[4] >> 12) as u8;
        s[28] = (limbs[4] >> 20) as u8;
        s[29] = (limbs[4] >> 28) as u8;
        s[30] = (limbs[4] >> 36) as u8;
        s[31] = (limbs[4] >> 44) as u8;
        s
    }

    fn add(&self, rhs: &Fe) -> Fe {
        Fe([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    fn sub(&self, rhs: &Fe) -> Fe {
        // Add 16*p (per-limb) before subtracting so no limb underflows;
        // rhs must be weakly reduced (limbs < 2^52).
        reduce([
            (self.0[0] + 36_028_797_018_963_664) - rhs.0[0],
            (self.0[1] + 36_028_797_018_963_952) - rhs.0[1],
            (self.0[2] + 36_028_797_018_963_952) - rhs.0[2],
            (self.0[3] + 36_028_797_018_963_952) - rhs.0[3],
            (self.0[4] + 36_028_797_018_963_952) - rhs.0[4],
        ])
    }

    fn neg(&self) -> Fe {
        Fe::zero().sub(self)
    }

    fn mul(&self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        let m = |x: u64, y: u64| -> u128 { (x as u128) * (y as u128) };
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        let c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        let mut c1 =
            m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        let mut c2 =
            m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
        let mut c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
        let mut c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);

        let mut out = [0u64; 5];
        c1 += c0 >> 51;
        out[0] = (c0 as u64) & LOW_51_BIT_MASK;
        c2 += c1 >> 51;
        out[1] = (c1 as u64) & LOW_51_BIT_MASK;
        c3 += c2 >> 51;
        out[2] = (c2 as u64) & LOW_51_BIT_MASK;
        c4 += c3 >> 51;
        out[3] = (c3 as u64) & LOW_51_BIT_MASK;
        let carry = (c4 >> 51) as u64;
        out[4] = (c4 as u64) & LOW_51_BIT_MASK;
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= LOW_51_BIT_MASK;
        Fe(out)
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    fn pow2k(&self, k: u32) -> Fe {
        let mut r = *self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    /// Returns (self^(2^250-1), self^11) — the shared chain used by
    /// both `invert` and `pow_p58` (ed25519-dalek `pow22501`).
    fn pow22501(&self) -> (Fe, Fe) {
        let t0 = self.square();
        let t1 = t0.square().square();
        let t2 = self.mul(&t1);
        let t3 = t0.mul(&t2);
        let t4 = t3.square();
        let t5 = t2.mul(&t4);
        let t6 = t5.pow2k(5);
        let t7 = t6.mul(&t5);
        let t8 = t7.pow2k(10);
        let t9 = t8.mul(&t7);
        let t10 = t9.pow2k(20);
        let t11 = t10.mul(&t9);
        let t12 = t11.pow2k(10);
        let t13 = t12.mul(&t7);
        let t14 = t13.pow2k(50);
        let t15 = t14.mul(&t13);
        let t16 = t15.pow2k(100);
        let t17 = t16.mul(&t15);
        let t18 = t17.pow2k(50);
        let t19 = t18.mul(&t13);
        (t19, t3)
    }

    /// Multiplicative inverse, self^(p-2).
    fn invert(&self) -> Fe {
        let (t19, t3) = self.pow22501();
        let t20 = t19.pow2k(5);
        t20.mul(&t3)
    }

    /// self^((p-5)/8) = self^(2^252-3) (the firmware's `pow_two252m3`).
    fn pow_p58(&self) -> Fe {
        let (t19, _) = self.pow22501();
        let t20 = t19.pow2k(2);
        self.mul(&t20)
    }

    fn ct_eq(&self, rhs: &Fe) -> bool {
        self.to_bytes() == rhs.to_bytes()
    }

    /// Returns `a` if `c` is false, `b` if `c` is true. (Inputs here
    /// are derived from the user-known pairing code, so a branch is
    /// acceptable; CT is not required.)
    fn cmov(a: &Fe, b: &Fe, c: bool) -> Fe {
        if c {
            *b
        } else {
            *a
        }
    }
}

/// RFC 9380 map_to_curve_elligator2_curve25519. Maps a 32-byte input
/// (decoded as a field element, top bit masked) to the Montgomery
/// u-coordinate of the mapped point. Mirrors `crypto/elligator2.c`.
pub(crate) fn map_to_curve25519(input: &[u8; 32]) -> [u8; 32] {
    let u = Fe::from_bytes(input);
    let c3 = Fe::sqrt_m1();
    let j = Fe::from_u64(486662);
    let one = Fe::one();

    let tv1 = u.square();
    let tv1 = tv1.add(&tv1); // 2 * u^2
    let xd = tv1.add(&one); // tv1 + 1
    let x1n = j.neg(); // -J

    let tv2 = xd.square();
    let gxd = tv2.mul(&xd); // xd^3

    let mut gx1 = j.mul(&tv1);
    gx1 = gx1.mul(&x1n);
    gx1 = gx1.add(&tv2);
    gx1 = gx1.mul(&x1n);

    let tv3 = gxd.square();
    let tv2b = tv3.square();
    let tv3 = tv3.mul(&gxd);
    let tv3 = tv3.mul(&gx1);
    let tv2b = tv2b.mul(&tv3);

    let y11 = tv2b.pow_p58();
    let y11 = y11.mul(&tv3);
    let y12 = y11.mul(&c3);

    let tv2c = y11.square();
    let tv2c = tv2c.mul(&gxd);
    let e1 = tv2c.ct_eq(&gx1);
    let y1 = Fe::cmov(&y12, &y11, e1);

    let x2n = x1n.mul(&tv1);

    let tv2d = y1.square();
    let tv2d = tv2d.mul(&gxd);
    let e3 = tv2d.ct_eq(&gx1);
    let xn = Fe::cmov(&x2n, &x1n, e3);

    let x = xn.mul(&xd.invert());
    x.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let bytes = (0..32)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        bytes.try_into().unwrap()
    }

    #[test]
    fn field_round_trips_bytes() {
        let b = hex32("66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a12");
        // from_bytes masks the top bit; clear it in the expected too.
        let mut expected = b;
        expected[31] &= 0x7f;
        assert_eq!(Fe::from_bytes(&b).to_bytes(), expected);
    }

    #[test]
    fn matches_trezor_elligator2_vectors() {
        // From elligator.org/vectors/curve25519_direct.vec, the exact
        // vectors Trezor's own test suite checks. A pass means this
        // map is byte-identical to the device's.
        let cases = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a12",
                "04d44290d13100b2c25290c9343d70c12ed4813487a07ac1176daa5925e7975e",
            ),
            (
                "673a505e107189ee54ca93310ac42e4545e9e59050aaac6f8b5f64295c8ec02f",
                "242ae39ef158ed60f20b89396d7d7eef5374aba15dc312a6aea6d1e57cacf85e",
            ),
            (
                "990b30e04e1c3620b4162b91a33429bddb9f1b70f1da6e5f76385ed3f98ab131",
                "998e98021eb4ee653effaa992f3fae4b834de777a953271baaa1fa3fef6b776e",
            ),
            (
                "341a60725b482dd0de2e25a585b208433044bc0a1ba762442df3a0e888ca063c",
                "683a71d7fca4fc6ad3d4690108be808c2e50a5af3174486741d0a83af52aeb01",
            ),
            (
                "922688fa428d42bc1fa8806998fbc5959ae801817e85a42a45e8ec25a0d7541a",
                "696f341266c64bcfa7afa834f8c34b2730be11c932e08474d1a22f26ed82410b",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                map_to_curve25519(&hex32(input)),
                hex32(expected),
                "elligator2 mismatch for input {input}"
            );
        }
    }
}
