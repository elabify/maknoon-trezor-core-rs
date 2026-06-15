/// Selects which wallet a seed-deriving call operates on: the
/// device's standard wallet, or a BIP39 passphrase ("hidden") wallet
/// with the passphrase entered on the device or supplied by the host.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PassphraseSpec {
    /// No passphrase — the device's standard wallet.
    Standard,
    /// Enter the passphrase on the Trezor screen; the host never sees it.
    OnDevice,
    /// Host-supplied passphrase (cached host-side).
    Host { passphrase: String },
}

/// A secp256k1 signature returned by the device, split into the
/// recovery parity bit plus the 32-byte R / S components.
///
/// Used by the Ethereum and Tron signing paths. The Swift
/// `HardwareWallet` protocol expects `(v: UInt8, r: Data, s: Data)`;
/// the conformer maps this record straight onto that tuple, matching
/// the shape the ledger-eth / ledger-tron crates return.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Secp256k1Signature {
    /// Recovery id / parity bit (0 or 1). Callers add any chain-
    /// specific offset (e.g. EIP-155) host-side, exactly as with
    /// the ledger crates.
    pub v: u8,
    /// 32-byte big-endian R component.
    pub r: Vec<u8>,
    /// 32-byte big-endian S component.
    pub s: Vec<u8>,
}

/// Read-only result of `TrezorClient::thp_probe()`: the channel
/// allocation's device properties plus the post-handshake Trezor
/// state. It exercises GATT + framing + channel allocation + the full
/// Noise handshake against a real device with no seed access, no
/// pairing, and no signing, so it is the safe first on-device test.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ThpProbeResult {
    /// Internal model string from `ThpDeviceProperties` (e.g. "T3W1").
    pub internal_model: String,
    /// THP protocol major version advertised by the device.
    pub protocol_version_major: u32,
    /// THP protocol minor version advertised by the device.
    pub protocol_version_minor: u32,
    /// Supported pairing methods (`ThpPairingMethod` enum values:
    /// 1=SkipPairing, 2=CodeEntry, 3=QrCode, 4=NFC).
    pub pairing_methods: Vec<i32>,
    /// Raw decrypted Trezor state byte(s) from the handshake
    /// completion (unpaired vs paired). Interpretation is confirmed
    /// on-device; surfaced raw so the host can log it.
    pub trezor_state: Vec<u8>,
}

/// Result of `TrezorClient::establish_paired_session`: the device
/// identity read once the channel reaches ENCRYPTED_TRANSPORT, plus
/// the reconnection credential to persist (so the next connect skips
/// the on-device pairing).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PairedSession {
    /// Stable device id from `Features` (persist as the device serial).
    pub device_id: String,
    /// Marketing model string (e.g. "T3W1").
    pub model: String,
    /// Firmware "major.minor.patch".
    pub firmware_version: String,
    /// Whether the device holds a seed.
    pub initialized: bool,
    /// THP reconnection credential; store keyed by the device and
    /// replay on the next connect to skip CodeEntry pairing.
    pub credential: Vec<u8>,
}

/// Stable device identity read during `identify()` from the THP
/// `Features` message. `device_id` is what gets persisted as
/// `RegisteredDevice.serial` on the Swift side, so Maknoon
/// recognises the same physical device on every reconnect.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TrezorFeatures {
    /// Stable per-device identifier. Persisted as the device serial.
    pub device_id: String,
    /// Marketing model string reported by the device (e.g. "T3W1").
    /// Surfaced for diagnostics only; never shown as a version in
    /// user-facing copy (the vendor label is just "Trezor").
    pub model: String,
    /// Firmware version "major.minor.patch", for the Tron-firmware
    /// floor check and diagnostics.
    pub firmware_version: String,
    /// Whether the device is initialized with a seed. A false here
    /// means the user must finish device setup before pairing.
    pub initialized: bool,
}
