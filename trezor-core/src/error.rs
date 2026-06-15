use thiserror::Error;

/// Errors surfaced from the public API. Designed for clean
/// marshalling through UniFFI: each variant carries a string so
/// Swift / Kotlin callers can show or log a useful message without
/// inspecting the variant. Shaped to map onto the Swift
/// `HardwareWalletError` cases (`userCancelled`, `transport`,
/// `notImplemented`) the way the ledger crates' `LedgerError` does.
#[derive(Debug, Error, uniffi::Error)]
pub enum TrezorError {
    /// The injected Transport failed (BLE disconnect, timeout,
    /// device out of range, etc.). The host platform owns transport
    /// and supplies the description.
    #[error("transport error: {reason}")]
    Transport { reason: String },

    /// The Trezor Host Protocol channel / handshake failed: channel
    /// allocation, Noise XX handshake, AEAD decrypt, or a malformed
    /// THP frame. Distinct from `Transport` (the link is up) and
    /// from `DeviceRejected` (the device spoke, and said no).
    #[error("THP channel error: {reason}")]
    Thp { reason: String },

    /// The device returned a protobuf `Failure` message. `code` is
    /// the trezor-common `FailureType` (e.g. 4 = ActionCancelled,
    /// 2 = ProcessError); preserved for diagnostics. User-cancel
    /// (`ActionCancelled` / `PinCancelled`) is surfaced as
    /// `UserCanceled` instead.
    #[error("device rejected (failure {code}): {reason}")]
    DeviceRejected { code: i32, reason: String },

    /// Pairing is required or failed: no stored credential and the
    /// user must complete the on-device pairing (QR / code), or a
    /// supplied credential was rejected.
    #[error("pairing required: {reason}")]
    Pairing { reason: String },

    /// Inputs couldn't be parsed or are malformed for signing
    /// (bad PSBT, bad derivation path, bad envelope).
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },

    /// Anything unexpected in the protocol exchange not covered by
    /// the more specific variants above.
    #[error("protocol error: {reason}")]
    Protocol { reason: String },

    /// The device's transport layer is busy (e.g. still tearing down a
    /// previous channel after a rapid reconnect). Per the spec the host
    /// backs off and retries; surfaced as its own variant so the host
    /// can recognise and retry it rather than failing the operation.
    #[error("device transport is busy; back off and retry")]
    TransportBusy,

    /// The user pressed reject / cancelled on the device. Special-
    /// cased because UI typically wants to distinguish "user said
    /// no" from "something broke." Maps to
    /// `HardwareWalletError.userCancelled` on the Swift side.
    #[error("user canceled on device")]
    UserCanceled,

    /// A surface area that is declared but not yet wired up. Every
    /// public method returns this until the THP spike (task #2) and
    /// the per-chain work (task #4) land. `feature` names what is
    /// missing so the Swift caller can route the user back cleanly.
    #[error("not yet implemented: {feature}")]
    NotImplemented { feature: String },
}

impl TrezorError {
    pub(crate) fn not_implemented(feature: impl Into<String>) -> Self {
        TrezorError::NotImplemented {
            feature: feature.into(),
        }
    }

    pub(crate) fn thp(reason: impl Into<String>) -> Self {
        TrezorError::Thp {
            reason: reason.into(),
        }
    }
}

/// A failure from the host's BLE transport maps to a transport-level
/// `TrezorError` (the link broke), distinct from a `Thp` protocol
/// fault (the link is up but the exchange was malformed).
impl From<crate::transport::TrezorTransportError> for TrezorError {
    fn from(e: crate::transport::TrezorTransportError) -> Self {
        TrezorError::Transport {
            reason: e.to_string(),
        }
    }
}
