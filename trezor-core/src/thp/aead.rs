//! AES-256-GCM helpers shared by the THP handshake (`noise`) and the
//! encrypted transport session (`session`). The cipher is fixed by the
//! spec's `Noise_XX_25519_AESGCM_SHA256` protocol name.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::error::TrezorError;

/// AES-256-GCM seal. Returns `ciphertext || 16-byte tag`. Infallible
/// for valid key/nonce sizes (enforced by the array types).
pub(crate) fn seal(key: &[u8; 32], iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption is infallible for valid inputs")
}

/// AES-256-GCM open. `ciphertext` is `ciphertext || 16-byte tag`.
/// Returns the plaintext, or a THP error if authentication fails.
pub(crate) fn open(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TrezorError> {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| TrezorError::thp("AES-GCM authentication failed"))
}
