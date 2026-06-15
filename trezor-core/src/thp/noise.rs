//! THP L3 secure-channel handshake (host side).
//!
//! A bespoke Noise-XX-style handshake, implemented verbatim from the
//! THP spec's host state machine (HH0..HH3). It is NOT a stock Noise
//! XX, so `snow` cannot be used: the cipher is **AES-256-GCM**
//! (`Noise_XX_25519_AESGCM_SHA256`), Trezor sends a *masked* static
//! public key, and the transcript hash `h` mixes `device_properties`
//! and a `try_to_unlock` byte at positions a stock implementation
//! would not. All primitives (HKDF, AES-GCM IVs, the transcript
//! hashing order) follow the spec's "Common definitions" exactly.
//!
//! Correctness here is verified in-process by a loopback test against
//! a spec-faithful Trezor-side responder (TH1/TH2): both sides must
//! derive identical `key_request` / `key_response` and the responder
//! must recover the host's static key. Agreement against a real
//! device is the remaining on-device spike item.

// Consumed by the channel layer (task #2) once it drives the
// handshake over real packets; exercised by the loopback test now.
#![allow(dead_code)]

use hmac::{Hmac, Mac};
use prost::Message;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::TrezorError;
use crate::proto::hw::trezor::messages::thp::ThpHandshakeCompletionReqNoisePayload;
use crate::thp::aead::{open as aead_decrypt, seal as aead_encrypt};

type HmacSha256 = Hmac<Sha256>;

/// Noise protocol name: 28 ASCII bytes + 4 NUL padding = 32 bytes.
pub(crate) const PROTOCOL_NAME: &[u8; 32] = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00";

/// AES-GCM IV `0^96` (twelve zero bytes).
const IV_ZERO: [u8; 12] = [0u8; 12];
/// AES-GCM IV `0^95 || 1` (twelve bytes, only the last bit set).
const IV_ONE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

// Wire sizes from the spec's handshake message tables.
const PUBKEY_LEN: usize = 32;
const ENC_STATIC_LEN: usize = 48; // 32-byte masked static + 16-byte tag
const TAG_LEN: usize = 16;
const INIT_RESPONSE_LEN: usize = PUBKEY_LEN + ENC_STATIC_LEN + TAG_LEN; // 96

/// SHA-256 over the concatenation of `parts`.
fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// THP's HKDF (spec "Common definitions"): returns
/// `(chaining_key, key)`. Note this is the protocol's own two-output
/// construction, not RFC 5869 HKDF-Expand.
fn hkdf(ck: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp_key = hmac_sha256(ck, input);
    let output_1 = hmac_sha256(&temp_key, &[0x01]);
    let mut second_input = [0u8; 33];
    second_input[..32].copy_from_slice(&output_1);
    second_input[32] = 0x02;
    let output_2 = hmac_sha256(&temp_key, &second_input);
    (output_1, output_2)
}

/// X25519 scalar multiplication (RFC 7748; clamps the scalar).
fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*scalar)
        .diffie_hellman(&PublicKey::from(*point))
        .to_bytes()
}

/// X25519 public key for a private scalar (clamped · base point).
fn public_key(scalar: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*scalar)).to_bytes()
}

fn random_scalar() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("platform RNG");
    bytes
}

fn as_array32(slice: &[u8]) -> Result<[u8; 32], TrezorError> {
    <[u8; 32]>::try_from(slice).map_err(|_| TrezorError::thp("expected a 32-byte field"))
}

/// The encrypted-session secrets produced by a completed handshake.
/// `key_request` encrypts host→Trezor application messages,
/// `key_response` decrypts Trezor→host. Nonces start at 0 / 1 per the
/// spec and are advanced by the session layer.
#[derive(Clone)]
pub(crate) struct SessionKeys {
    pub(crate) key_request: [u8; 32],
    pub(crate) key_response: [u8; 32],
    pub(crate) nonce_request: u64,
    pub(crate) nonce_response: u64,
    /// Decrypted Trezor state byte(s) (paired / unpaired); the
    /// channel layer interprets these to decide pairing vs. ready.
    pub(crate) trezor_state: Vec<u8>,
    /// The Trezor's masked static public key, the lookup key for a
    /// stored pairing credential on the next reconnect.
    pub(crate) trezor_masked_static_pubkey: [u8; 32],
    /// Final handshake transcript hash `h`. CPace's CodeEntry pairing
    /// mixes this in as the channel identifier.
    pub(crate) handshake_hash: [u8; 32],
    /// The host's static public key used in this handshake; the
    /// `ThpCredentialRequest` identifies the credential by it.
    pub(crate) host_static_pubkey: [u8; 32],
}

/// Drives the host side of the THP handshake. One per channel.
pub(crate) struct HostHandshake {
    device_properties: Vec<u8>,
    try_to_unlock: u8,
    ephemeral_priv: [u8; 32],
    ephemeral_pub: [u8; 32],
    static_priv: [u8; 32],
    static_pub: [u8; 32],
    host_pairing_credential: Option<Vec<u8>>,
    h: [u8; 32],
    ck: [u8; 32],
    masked_static: [u8; 32],
}

impl HostHandshake {
    /// `device_properties` is the serialized `ThpDeviceProperties`
    /// blob received in the `ChannelAllocationResponse` (mixed into
    /// the transcript hash). `static_priv` is the host's persistent
    /// X25519 secret. `host_pairing_credential` is `Some` only when
    /// reconnecting to an already-paired Trezor.
    pub(crate) fn new(
        device_properties: Vec<u8>,
        try_to_unlock: u8,
        static_priv: [u8; 32],
        host_pairing_credential: Option<Vec<u8>>,
    ) -> Self {
        Self::with_ephemeral(
            device_properties,
            try_to_unlock,
            static_priv,
            host_pairing_credential,
            random_scalar(),
        )
    }

    fn with_ephemeral(
        device_properties: Vec<u8>,
        try_to_unlock: u8,
        static_priv: [u8; 32],
        host_pairing_credential: Option<Vec<u8>>,
        ephemeral_priv: [u8; 32],
    ) -> Self {
        Self {
            device_properties,
            try_to_unlock,
            ephemeral_priv,
            ephemeral_pub: public_key(&ephemeral_priv),
            static_priv,
            static_pub: public_key(&static_priv),
            host_pairing_credential,
            h: [0u8; 32],
            ck: [0u8; 32],
            masked_static: [0u8; 32],
        }
    }

    /// HH0: the `HandshakeInitiationRequest` transport payload,
    /// `host_ephemeral_pubkey (32) || try_to_unlock (1)`.
    pub(crate) fn init_request_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(PUBKEY_LEN + 1);
        payload.extend_from_slice(&self.ephemeral_pub);
        payload.push(self.try_to_unlock);
        payload
    }

    /// HH1: consume the `HandshakeInitiationResponse` and produce the
    /// `HandshakeCompletionRequest` transport payload,
    /// `encrypted_host_static_pubkey (48) || encrypted_payload`.
    pub(crate) fn read_init_response(&mut self, resp: &[u8]) -> Result<Vec<u8>, TrezorError> {
        if resp.len() != INIT_RESPONSE_LEN {
            return Err(TrezorError::thp(
                "handshake init response has the wrong size",
            ));
        }
        let trezor_ephemeral_pub = as_array32(&resp[0..PUBKEY_LEN])?;
        let enc_static = &resp[PUBKEY_LEN..PUBKEY_LEN + ENC_STATIC_LEN];
        let tag = &resp[PUBKEY_LEN + ENC_STATIC_LEN..INIT_RESPONSE_LEN];

        let mut h = sha256_concat(&[PROTOCOL_NAME, &self.device_properties]);
        h = sha256_concat(&[&h, &self.ephemeral_pub]);
        h = sha256_concat(&[&h, &[self.try_to_unlock]]);
        h = sha256_concat(&[&h, &trezor_ephemeral_pub]);

        let (ck, k) = hkdf(
            PROTOCOL_NAME,
            &x25519(&self.ephemeral_priv, &trezor_ephemeral_pub),
        );
        let masked_static = as_array32(&aead_decrypt(&k, &IV_ZERO, &h, enc_static)?)?;
        h = sha256_concat(&[&h, enc_static]);

        let (ck, k) = hkdf(&ck, &x25519(&self.ephemeral_priv, &masked_static));
        let empty = aead_decrypt(&k, &IV_ZERO, &h, tag)?;
        if !empty.is_empty() {
            return Err(TrezorError::thp(
                "handshake authentication payload was not empty",
            ));
        }
        h = sha256_concat(&[&h, tag]);

        // Unpaired/paired branch is decided host-side by whether a
        // credential is supplied; either way the static key is
        // already chosen and encrypted here.
        let enc_host_static = aead_encrypt(&k, &IV_ONE, &h, &self.static_pub);
        h = sha256_concat(&[&h, &enc_host_static]);

        let (ck, k) = hkdf(&ck, &x25519(&self.static_priv, &trezor_ephemeral_pub));
        let payload = ThpHandshakeCompletionReqNoisePayload {
            host_pairing_credential: self.host_pairing_credential.clone(),
        }
        .encode_to_vec();
        let enc_payload = aead_encrypt(&k, &IV_ZERO, &h, &payload);
        h = sha256_concat(&[&h, &enc_payload]);

        self.h = h;
        self.ck = ck;
        self.masked_static = masked_static;

        let mut out = Vec::with_capacity(ENC_STATIC_LEN + enc_payload.len());
        out.extend_from_slice(&enc_host_static);
        out.extend_from_slice(&enc_payload);
        Ok(out)
    }

    /// HH2/HH3: consume the `HandshakeCompletionResponse`
    /// (`encrypted_trezor_state`) and derive the session keys.
    pub(crate) fn read_completion_response(
        &mut self,
        resp: &[u8],
    ) -> Result<SessionKeys, TrezorError> {
        let (key_request, key_response) = hkdf(&self.ck, b"");
        let trezor_state = aead_decrypt(&key_response, &IV_ZERO, b"", resp)?;
        Ok(SessionKeys {
            key_request,
            key_response,
            nonce_request: 0,
            nonce_response: 1,
            trezor_state,
            trezor_masked_static_pubkey: self.masked_static,
            handshake_hash: self.h,
            host_static_pubkey: self.static_pub,
        })
    }
}

/// Spec-faithful Trezor-side handshake responder (TH1 / TH2),
/// test-only. Lives here (not in `mod tests`) so the `connection`
/// driver's in-memory mock-device test can reuse it.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) struct TrezorResponder {
        device_properties: Vec<u8>,
        static_priv: [u8; 32],
        static_pub: [u8; 32],
        ephemeral_priv: [u8; 32],
        h: [u8; 32],
        ck: [u8; 32],
        k: [u8; 32],
    }

    /// Mirror of `SessionKeys` derived on the responder side.
    pub(crate) struct ResponderResult {
        pub(crate) response: Vec<u8>,
        pub(crate) host_static_pub: [u8; 32],
        pub(crate) key_request: [u8; 32],
        pub(crate) key_response: [u8; 32],
    }

    impl TrezorResponder {
        pub(crate) fn new(device_properties: Vec<u8>, static_priv: [u8; 32]) -> Self {
            Self {
                device_properties,
                static_priv,
                static_pub: public_key(&static_priv),
                ephemeral_priv: [0u8; 32],
                h: [0u8; 32],
                ck: [0u8; 32],
                k: [0u8; 32],
            }
        }

        // TH1: HandshakeInitiationRequest -> HandshakeInitiationResponse.
        pub(crate) fn handle_init_request(&mut self, req: &[u8]) -> Vec<u8> {
            let host_ephemeral_pub = as_array32(&req[0..PUBKEY_LEN]).unwrap();
            let try_to_unlock = req[PUBKEY_LEN];

            self.ephemeral_priv = random_scalar();
            let ephemeral_pub = public_key(&self.ephemeral_priv);

            let mut h = sha256_concat(&[PROTOCOL_NAME, &self.device_properties]);
            h = sha256_concat(&[&h, &host_ephemeral_pub]);
            h = sha256_concat(&[&h, &[try_to_unlock]]);
            h = sha256_concat(&[&h, &ephemeral_pub]);

            let (ck, k_a) = hkdf(
                PROTOCOL_NAME,
                &x25519(&self.ephemeral_priv, &host_ephemeral_pub),
            );
            let mask = sha256_concat(&[&self.static_pub, &ephemeral_pub]);
            let masked_static = x25519(&mask, &self.static_pub);
            let enc_static = aead_encrypt(&k_a, &IV_ZERO, &h, &masked_static);
            h = sha256_concat(&[&h, &enc_static]);

            let (ck, k_b) = hkdf(
                &ck,
                &x25519(&mask, &x25519(&self.static_priv, &host_ephemeral_pub)),
            );
            let tag = aead_encrypt(&k_b, &IV_ZERO, &h, b"");
            h = sha256_concat(&[&h, &tag]);

            self.h = h;
            self.ck = ck;
            self.k = k_b;

            let mut resp = Vec::with_capacity(INIT_RESPONSE_LEN);
            resp.extend_from_slice(&ephemeral_pub);
            resp.extend_from_slice(&enc_static);
            resp.extend_from_slice(&tag);
            resp
        }

        // TH2: HandshakeCompletionRequest -> HandshakeCompletionResponse.
        pub(crate) fn handle_completion_request(&mut self, req: &[u8]) -> ResponderResult {
            let enc_host_static = &req[0..ENC_STATIC_LEN];
            let enc_payload = &req[ENC_STATIC_LEN..];

            let host_static_pub =
                as_array32(&aead_decrypt(&self.k, &IV_ONE, &self.h, enc_host_static).unwrap())
                    .unwrap();
            let h = sha256_concat(&[&self.h, enc_host_static]);

            let (ck, k_c) = hkdf(&self.ck, &x25519(&self.ephemeral_priv, &host_static_pub));
            let payload_bytes = aead_decrypt(&k_c, &IV_ZERO, &h, enc_payload).unwrap();
            // Decodes (unpaired path: credential absent).
            let _ = ThpHandshakeCompletionReqNoisePayload::decode(payload_bytes.as_slice())
                .expect("completion payload decodes");

            let trezor_state = [0x02u8]; // STATE_UNPAIRED (opaque to the loopback)
            let (key_request, key_response) = hkdf(&ck, b"");
            let response = aead_encrypt(&key_response, &IV_ZERO, b"", &trezor_state);

            ResponderResult {
                response,
                host_static_pub,
                key_request,
                key_response,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TrezorResponder;
    use super::*;

    #[test]
    fn protocol_name_is_32_bytes() {
        assert_eq!(PROTOCOL_NAME.len(), 32);
    }

    #[test]
    fn hkdf_is_deterministic_and_distinct_outputs() {
        let (a, b) = hkdf(PROTOCOL_NAME, b"input");
        let (a2, b2) = hkdf(PROTOCOL_NAME, b"input");
        assert_eq!(a, a2);
        assert_eq!(b, b2);
        assert_ne!(a, b);
    }

    #[test]
    fn aead_round_trips_and_detects_tampering() {
        let key = [7u8; 32];
        let ct = aead_encrypt(&key, &IV_ZERO, b"ad", b"secret");
        assert_eq!(aead_decrypt(&key, &IV_ZERO, b"ad", &ct).unwrap(), b"secret");
        // Wrong AAD fails.
        assert!(aead_decrypt(&key, &IV_ZERO, b"other", &ct).is_err());
        // Empty-plaintext encryption yields a bare 16-byte tag, as
        // the handshake's `tag` field relies on.
        let tag = aead_encrypt(&key, &IV_ZERO, b"ad", b"");
        assert_eq!(tag.len(), TAG_LEN);
        assert!(aead_decrypt(&key, &IV_ZERO, b"ad", &tag)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn host_and_trezor_complete_handshake_and_agree_on_keys() {
        // Serialized ThpDeviceProperties bytes are opaque to the
        // handshake math; any fixed blob both sides share works.
        let device_properties = b"\x0a\x04T3W1\x18\x02\x20\x00".to_vec();
        let host_static = [0x11u8; 32];
        let trezor_static = [0x22u8; 32];

        let mut host = HostHandshake::new(device_properties.clone(), 0x00, host_static, None);
        let mut trezor = TrezorResponder::new(device_properties, trezor_static);

        let req1 = host.init_request_payload();
        let resp1 = trezor.handle_init_request(&req1);
        let req2 = host.read_init_response(&resp1).expect("HH1");
        let trezor_out = trezor.handle_completion_request(&req2);
        let keys = host
            .read_completion_response(&trezor_out.response)
            .expect("HH2/HH3");

        // Both sides derived the same encrypted-session keys.
        assert_eq!(keys.key_request, trezor_out.key_request);
        assert_eq!(keys.key_response, trezor_out.key_response);
        assert_ne!(keys.key_request, keys.key_response);
        // The Trezor recovered the host's real static public key.
        assert_eq!(trezor_out.host_static_pub, public_key(&host_static));
        // Host decrypted the Trezor state byte (proves key_response
        // matches end-to-end).
        assert_eq!(keys.trezor_state, vec![0x02]);
        assert_eq!(keys.nonce_request, 0);
        assert_eq!(keys.nonce_response, 1);
    }

    #[test]
    fn tampered_init_response_is_rejected() {
        let device_properties = b"props".to_vec();
        let mut host = HostHandshake::new(device_properties.clone(), 0, [0x33u8; 32], None);
        let mut trezor = TrezorResponder::new(device_properties, [0x44u8; 32]);
        let req1 = host.init_request_payload();
        let mut resp1 = trezor.handle_init_request(&req1);
        // Flip a byte in the encrypted static pubkey region.
        resp1[PUBKEY_LEN] ^= 0x01;
        assert!(host.read_init_response(&resp1).is_err());
    }
}
