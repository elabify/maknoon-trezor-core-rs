// Trezor Host Protocol (THP v2) — the secure channel that wraps
// every protobuf message exchanged with the device over BLE.
//
// THP is the long pole of this crate and the heart of the spike
// (task #2). It is mandatory on the Trezor BLE link. This module is
// being built bottom-up from the official spec
// (trezor-firmware internal docs, vendored notes
// below) against round-trippable unit tests; the parts that can only
// be confirmed against a real device (exact device_properties bytes,
// timing) are validated in the on-device spike.
//
// Layers, bottom to top:
//
//   1. Framing       Raw BLE reports (244 bytes; USB is 64) carry THP
//                    transport packets: a control byte, the channel
//                    id, and (on the first packet) the length, then
//                    the payload. A transport payload is CRC-32-IEEE
//                    protected and segmented across an initiation
//                    packet + continuation packets. IMPLEMENTED in
//                    `framing` with round-trip tests.
//
//   2. Channel       A `ChannelAllocationRequest`/`Response` over the
//                    broadcast CID 0xFFFF assigns a channel id before
//                    anything else. (next)
//
//   3. Handshake     A bespoke Noise-XX-style handshake:
//                    `Noise_XX_25519_AESGCM_SHA256` (AES-256-GCM, NOT
//                    ChaCha20Poly1305 — confirmed against the spec).
//                    Trezor masks its static pubkey
//                    (X25519(SHA256(static||ephemeral), static)) and
//                    the transcript hash mixes `device_properties`
//                    and a `try_to_unlock` byte at non-standard
//                    positions, so the `snow` crate cannot be used
//                    as-is: the host state machine (HH0..HH3) is
//                    hand-rolled per the spec from x25519-dalek +
//                    aes-gcm + sha2/hmac. (next)
//
//   4. Session       Post-handshake, application messages
//                    (session_id(1) || message_type(2 BE) ||
//                    protobuf) are sealed with AES-256-GCM under the
//                    handshake-derived key_request / key_response and
//                    monotonic per-direction nonces. (next)
//
//   5. Pairing       First connection runs an on-device pairing
//                    (CodeEntry today; QR / NFC defined) that yields a
//                    reconnection credential, persisted host-side
//                    (iOS Keychain) and replayed on later connects to
//                    skip re-pairing. (next)
//
// References: the THP spec under trezor-firmware docs/common/thp; the
// vendored protos under ../proto (pinned, see proto/VENDORED_FROM.txt);
// trezor-connect-rs as a Rust reference only — we own this code.

pub(crate) mod aead;
pub(crate) mod channel;
pub(crate) mod connection;
pub(crate) mod cpace;
pub(crate) mod elligator2;
pub(crate) mod framing;
pub(crate) mod noise;
pub(crate) mod pairing;
pub(crate) mod session;

#[allow(dead_code)] // populated as the channel/handshake layers land.
/// Lifecycle of a THP channel, from raw link up to an encrypted,
/// (optionally) paired session ready to carry protobuf traffic.
/// Names follow the host state machine in the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelState {
    /// No channel id yet; must run channel allocation first.
    Unallocated,
    /// Channel id assigned; Noise handshake not started.
    Allocated,
    /// Noise handshake in progress (HH0..HH3).
    Handshaking,
    /// Encrypted session established; not yet paired.
    Established,
    /// Paired (credential issued or accepted); ready for signing.
    Paired,
}
