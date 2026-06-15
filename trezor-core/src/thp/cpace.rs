//! CPace (host side) for THP CodeEntry pairing.
//!
//! Ported from the firmware `core/src/trezor/wire/thp/cpace.py`. The
//! generator is derived from the 6-digit pairing code and the
//! handshake hash via SHA-512 over the CPace DSI framing, mapped to a
//! Curve25519 point with Elligator2 (see `elligator2`, vector-checked
//! against the device). The shared secret is X25519, and the tag the
//! host sends is SHA-256(shared_secret).
//!
//! X25519 here clamps the scalar (RFC 7748), matching the firmware's
//! `curve25519.multiply` — the same function the THP handshake uses,
//! which we already confirmed interoperates with a real device.

#![allow(dead_code)] // consumed by the pairing flow (task #7).

use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::thp::elligator2::map_to_curve25519;

// DSI = 0x08 || "CPace255" || 0x06  (len(DSI)=8, len(PRS)=6).
const DSI_PREFIX: [u8; 10] = [0x08, 0x43, 0x50, 0x61, 0x63, 0x65, 0x32, 0x35, 0x35, 0x06];
// 0x6f (zpad length = 111) || 111 zero bytes || 0x20 (len(CI) = 32).
const PADDING_LEN: usize = 113;
// Single-byte session id length prefix, sid empty.
const SID: [u8; 1] = [0x00];
/// The pairing code is always a zero-padded 6-digit decimal.
const CODE_LEN: usize = 6;

fn padding() -> [u8; PADDING_LEN] {
    let mut p = [0u8; PADDING_LEN];
    p[0] = 0x6f;
    p[PADDING_LEN - 1] = 0x20;
    p
}

/// Format the numeric pairing code as its 6-byte zero-padded ASCII
/// representation (`f"{code:06}"`), the PRS the CPace DSI hashes.
pub(crate) fn format_code(code: u32) -> [u8; CODE_LEN] {
    let s = format!("{:06}", code % 1_000_000);
    let mut out = [0u8; CODE_LEN];
    out.copy_from_slice(s.as_bytes());
    out
}

/// The CPace generator point for this code + handshake transcript.
pub(crate) fn generator(code: &[u8; CODE_LEN], handshake_hash: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(DSI_PREFIX);
    h.update(code);
    h.update(padding());
    h.update(handshake_hash);
    h.update(SID);
    let pregenerator = h.finalize();
    let mut input = [0u8; 32];
    input.copy_from_slice(&pregenerator[..32]);
    map_to_curve25519(&input)
}

fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*scalar)
        .diffie_hellman(&PublicKey::from(*point))
        .to_bytes()
}

/// Result of the host's CPace step: the public key + tag to put in
/// `ThpCodeEntryCpaceHostTag`.
pub(crate) struct HostCpace {
    pub(crate) host_public: [u8; 32],
    pub(crate) tag: [u8; 32],
}

/// Compute the host's CPace public key and tag. `host_private` is the
/// host's ephemeral CPace scalar (random in production; supplied here
/// for testability).
pub(crate) fn host_cpace(
    code: &[u8; CODE_LEN],
    handshake_hash: &[u8],
    trezor_public: &[u8; 32],
    host_private: &[u8; 32],
) -> HostCpace {
    let g = generator(code, handshake_hash);
    let host_public = x25519(host_private, &g);
    let shared = x25519(host_private, trezor_public);
    let tag: [u8; 32] = Sha256::digest(shared).into();
    HostCpace { host_public, tag }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_zero_padded_six_digits() {
        assert_eq!(&format_code(42), b"000042");
        assert_eq!(&format_code(123_456), b"123456");
    }

    #[test]
    fn padding_is_111_zeros_between_markers() {
        let p = padding();
        assert_eq!(p[0], 0x6f);
        assert_eq!(p[PADDING_LEN - 1], 0x20);
        assert!(p[1..PADDING_LEN - 1].iter().all(|&b| b == 0));
    }

    #[test]
    fn host_and_trezor_agree_on_cpace_tag() {
        // Loopback: both derive the same generator from the code +
        // handshake hash, then the X25519/CPace exchange yields a
        // matching shared secret -> matching tag. (Elligator2 itself
        // is validated against the device's vectors separately.)
        let code = format_code(314_159);
        let handshake_hash = [0x5au8; 32];

        let trezor_private = [0x33u8; 32];
        let host_private = [0x44u8; 32];

        let g = generator(&code, &handshake_hash);
        let trezor_public = x25519(&trezor_private, &g);

        let host = host_cpace(&code, &handshake_hash, &trezor_public, &host_private);

        // Trezor side recomputes the shared secret + tag from the
        // host's public key.
        let trezor_shared = x25519(&trezor_private, &host.host_public);
        let trezor_tag: [u8; 32] = Sha256::digest(trezor_shared).into();

        assert_eq!(host.tag, trezor_tag);

        // A wrong code corrupts the host's PUBLIC key, so the device's
        // shared secret (from that public key) no longer matches the
        // tag the host sends. Model the device recomputing against the
        // wrong-code host_public.
        let wrong = host_cpace(
            &format_code(271_828),
            &handshake_hash,
            &trezor_public,
            &host_private,
        );
        let device_shared_wrong = x25519(&trezor_private, &wrong.host_public);
        let device_tag_wrong: [u8; 32] = Sha256::digest(device_shared_wrong).into();
        assert_ne!(wrong.tag, device_tag_wrong);
    }
}
