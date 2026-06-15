// trezor-core: cross-platform Trezor hardware-wallet signing client.
//
// Unlike the per-chain ledger-*-rs crates (one APDU dialect per
// Ledger app), Trezor speaks ONE protocol for everything: the Trezor
// Host Protocol (THP v2) carries a single trezor-common protobuf
// message set across Bitcoin, Ethereum, Solana and Tron. So this is
// a single unified crate, with chains behind cargo features.
//
// Layering mirrors the ledger crates, shifted up one level because
// THP is heavier than a bare APDU:
//
//   - A foreign callback interface (Transport) so iOS / Android code
//     can inject their raw BLE byte transport. The host does ONLY
//     GATT write / notify of raw chunks; everything above the wire
//     lives here.
//   - The THP v2 channel: packet framing, channel allocation, the
//     Noise XX handshake, the ChaCha20Poly1305 encrypted session,
//     and pairing-credential issue/reconnect. (see `thp`)
//   - Protobuf message encode/decode (trezor-common via prost) and
//     per-chain signing logic. (see `client` + `chains`, landing
//     with the THP spike, task #2)
//   - UniFFI-friendly value types (records / enums) that round-trip
//     cleanly through Swift and Kotlin, with return shapes identical
//     to the ledger crates so the Swift HardwareWallet conformer
//     maps 1:1.
//
// Public API surface is documented in client.rs.

mod bip32;
mod chains;
mod client;
mod error;
mod proto;
mod thp;
mod transport;
mod types;

pub use client::TrezorClient;
pub use error::TrezorError;
pub use thp::pairing::PairingCodeProvider;
pub use transport::{TrezorTransport, TrezorTransportError};
pub use types::{
    PairedSession, PassphraseSpec, Secp256k1Signature, ThpProbeResult, TrezorFeatures,
};

uniffi::setup_scaffolding!();
