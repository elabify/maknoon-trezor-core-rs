use thiserror::Error;

/// Errors raised by the foreign Transport implementation. The host
/// platform (Swift / Kotlin) builds these from its own BLE stack
/// errors. The Rust side never constructs them. Named with a vendor
/// prefix so it never collides with the ledger crates' `TransportError`
/// when both UniFFI bindings are compiled into the same app module.
#[derive(Debug, Error, uniffi::Error)]
pub enum TrezorTransportError {
    #[error("transport disconnected: {reason}")]
    Disconnected { reason: String },
    #[error("transport timed out: {reason}")]
    Timeout { reason: String },
    #[error("transport I/O error: {reason}")]
    Io { reason: String },
}

/// Foreign callback interface implemented by the host platform.
///
/// Trezor's transport seam is deliberately lower-level than the
/// ledger crates' APDU `exchange`: the host does ONLY raw BLE byte
/// I/O of fixed-size reports, and the THP v2 state machine (framing,
/// channel allocation, Noise XX handshake, ChaCha20Poly1305 session)
/// lives in Rust (see `thp`). That keeps the handshake crypto in
/// vetted Rust crates and reused verbatim by the Android build.
///
/// The host implements:
///
///   - BLE GATT writes to the Trezor write characteristic
///     (`8c00...0002`) and notify subscription on the notify
///     characteristic (`8c00...0003`). UUIDs are verified against a
///     real device in the THP spike (task #2).
///   - Nothing else: no framing, no chunking logic, no keep-alive
///     interpretation. THP packets are a fixed report size (BLE),
///     and the Rust `thp` layer splits / reassembles THP messages
///     across them.
///
/// `write_chunk` sends one report to the device. `read_chunk` awaits
/// and returns the next report the device notifies. Both surface
/// transport faults as `TrezorTransportError`.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait TrezorTransport: Send + Sync {
    /// Write one raw report to the device's write characteristic.
    async fn write_chunk(&self, data: Vec<u8>) -> Result<(), TrezorTransportError>;

    /// Await and return the next raw report from the device's
    /// notify characteristic.
    async fn read_chunk(&self) -> Result<Vec<u8>, TrezorTransportError>;
}
