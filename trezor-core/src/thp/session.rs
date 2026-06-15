//! THP L3/L4 encrypted transport session.
//!
//! After the handshake, application messages are sealed with
//! AES-256-GCM under the two handshake-derived keys, with monotonic
//! per-direction nonces. The IV and nonce rules are taken from the
//! Trezor firmware (`core/src/trezor/wire/thp/crypto.py` +
//! `channel.py`), which is the authoritative source the spec doc
//! omits:
//!
//!   - IV = `b"\x00\x00\x00\x00" || u64_be(nonce)` (12 bytes).
//!   - AAD is empty for transport messages.
//!   - Each direction has its own nonce counter, incremented by 1
//!     after every message.
//!   - For the host: outgoing (request) uses `key_request` starting
//!     at nonce 0; incoming (response) uses `key_response` starting
//!     at nonce 1 (nonce 0 was consumed by the handshake completion
//!     response).
//!
//! The application payload sealed here is, per `sessions.md`:
//! `session_id(1) || message_type(2, big-endian) || protobuf`.

// Driven by the channel/client layers (task #2 / #4); exercised by
// the loopback tests now.
#![allow(dead_code)]

use crate::error::TrezorError;
use crate::thp::aead;
use crate::thp::noise::SessionKeys;

const APP_HEADER_LEN: usize = 3; // session_id(1) + message_type(2)

fn iv_from_nonce(nonce: u64) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[4..].copy_from_slice(&nonce.to_be_bytes());
    iv
}

/// One endpoint of an encrypted THP channel: a send key/nonce and a
/// receive key/nonce.
pub(crate) struct Session {
    key_send: [u8; 32],
    key_recv: [u8; 32],
    nonce_send: u64,
    nonce_recv: u64,
}

impl Session {
    pub(crate) fn new(
        key_send: [u8; 32],
        key_recv: [u8; 32],
        nonce_send: u64,
        nonce_recv: u64,
    ) -> Self {
        Self {
            key_send,
            key_recv,
            nonce_send,
            nonce_recv,
        }
    }

    /// Build the host's session from a completed handshake: send with
    /// `key_request` (nonce 0), receive with `key_response` (nonce 1).
    pub(crate) fn from_handshake(keys: &SessionKeys) -> Self {
        Self::new(
            keys.key_request,
            keys.key_response,
            keys.nonce_request,
            keys.nonce_response,
        )
    }

    /// Seal an already-framed application payload (`session_id ||
    /// message_type || protobuf`) into the transport ciphertext
    /// (`ciphertext || tag`) and advance the send nonce.
    pub(crate) fn seal(&mut self, app_payload: &[u8]) -> Vec<u8> {
        let ct = aead::seal(
            &self.key_send,
            &iv_from_nonce(self.nonce_send),
            b"",
            app_payload,
        );
        self.nonce_send += 1;
        ct
    }

    /// Open a transport ciphertext into its application payload and
    /// advance the receive nonce. The nonce only advances on success,
    /// so a rejected (tampered/replayed) message can be retried.
    pub(crate) fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TrezorError> {
        let pt = aead::open(
            &self.key_recv,
            &iv_from_nonce(self.nonce_recv),
            b"",
            ciphertext,
        )?;
        self.nonce_recv += 1;
        Ok(pt)
    }
}

/// Encode an application message: `session_id || message_type(BE) ||
/// protobuf`.
pub(crate) fn encode_app_message(session_id: u8, message_type: u16, protobuf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(APP_HEADER_LEN + protobuf.len());
    out.push(session_id);
    out.extend_from_slice(&message_type.to_be_bytes());
    out.extend_from_slice(protobuf);
    out
}

/// Decode an application message into `(session_id, message_type,
/// protobuf_bytes)`.
pub(crate) fn decode_app_message(payload: &[u8]) -> Result<(u8, u16, &[u8]), TrezorError> {
    if payload.len() < APP_HEADER_LEN {
        return Err(TrezorError::thp(
            "application message shorter than its 3-byte header",
        ));
    }
    let session_id = payload[0];
    let message_type = u16::from_be_bytes([payload[1], payload[2]]);
    Ok((session_id, message_type, &payload[APP_HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iv_encodes_nonce_as_zero_padded_be_u64() {
        assert_eq!(iv_from_nonce(0), [0u8; 12]);
        assert_eq!(iv_from_nonce(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            iv_from_nonce(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn app_message_round_trips() {
        let framed = encode_app_message(0, 0x0011, b"\xde\xad");
        assert_eq!(framed, vec![0x00, 0x00, 0x11, 0xde, 0xad]);
        let (sid, mt, body) = decode_app_message(&framed).unwrap();
        assert_eq!((sid, mt, body), (0, 0x0011, &b"\xde\xad"[..]));
    }

    fn paired_sessions() -> (Session, Session) {
        let k_req = [0x11u8; 32];
        let k_resp = [0x22u8; 32];
        // Host: send key_request@0, recv key_response@1.
        let host = Session::new(k_req, k_resp, 0, 1);
        // Trezor mirror: send key_response@1, recv key_request@0.
        let trezor = Session::new(k_resp, k_req, 1, 0);
        (host, trezor)
    }

    #[test]
    fn transport_round_trips_both_directions_with_advancing_nonces() {
        let (mut host, mut trezor) = paired_sessions();

        // Host -> Trezor, several messages (request nonces 0,1,2).
        for i in 0..3u8 {
            let msg = vec![i; 10];
            let ct = host.seal(&msg);
            assert_eq!(trezor.open(&ct).unwrap(), msg);
        }
        // Trezor -> Host (response nonces 1,2).
        for i in 0..2u8 {
            let msg = vec![0xF0 | i; 5];
            let ct = trezor.seal(&msg);
            assert_eq!(host.open(&ct).unwrap(), msg);
        }
        assert_eq!(host.nonce_send, 3);
        assert_eq!(host.nonce_recv, 3);
    }

    #[test]
    fn tampered_ciphertext_is_rejected_and_nonce_holds() {
        let (mut host, mut trezor) = paired_sessions();
        let mut ct = host.seal(b"important");
        ct[0] ^= 0xFF;
        assert!(trezor.open(&ct).is_err());
        // Receive nonce did not advance, so the next genuine message
        // (still request nonce 0 from the sender's view) still opens.
        // Re-seal from a fresh sender to model retransmission.
        let mut host2 = Session::new([0x11u8; 32], [0x22u8; 32], 0, 1);
        let good = host2.seal(b"important");
        assert_eq!(trezor.open(&good).unwrap(), b"important");
    }
}
