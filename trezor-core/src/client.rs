use std::sync::Arc;

use tokio::sync::Mutex;

use crate::chains;
use crate::error::TrezorError;
use crate::thp::connection::{Connection, SEEDED_SESSION_ID};
use crate::thp::framing::BLE_PACKET_SIZE;
use crate::thp::pairing::{self, PairingCodeProvider};
use crate::thp::session::Session;
use crate::transport::TrezorTransport;
use crate::types::{
    PairedSession, PassphraseSpec, Secp256k1Signature, ThpProbeResult, TrezorFeatures,
};

/// Top-level client for talking to a Trezor over an injected BLE
/// transport. One client per device session: construct it, then call
/// any of the identity / per-chain methods. The client owns the THP
/// v2 channel (handshake + encrypted session + pairing credential)
/// and the trezor-common protobuf exchange; the host supplies only
/// raw BLE byte I/O via `TrezorTransport`.
///
/// Method surface and return shapes intentionally match the Swift
/// `HardwareWallet` protocol 1:1 (and the ledger crates' shapes), so
/// the `TrezorBLE` conformer is a thin delegation layer.
///
/// EVERY method below currently returns
/// `TrezorError::NotImplemented`. The bodies are filled in by the
/// THP spike (task #2, identity + transport) and the per-chain work
/// (task #4). The surface is declared now so the Swift side can be
/// wired and the UniFFI bindings generated against a stable API.
fn to_array32(v: &[u8]) -> Result<[u8; 32], TrezorError> {
    <[u8; 32]>::try_from(v).map_err(|_| TrezorError::thp("expected a 32-byte host static key"))
}

/// Resolve a seed-deriving op's `address_n`: parse the caller's custom
/// path string when present, else fall back to the chain's standard
/// path for `account`. Parse errors surface before any device I/O.
fn resolve_path(path: Option<String>, fallback: Vec<u32>) -> Result<Vec<u32>, TrezorError> {
    match path {
        Some(p) => crate::bip32::parse_path(&p),
        None => Ok(fallback),
    }
}

/// Reconnect to an already-paired device using its stored credential
/// (no on-device code entry), returning a connection in
/// ENCRYPTED_TRANSPORT ready for application messages. Free function
/// (not a `#[uniffi::export]` method) since it deals in non-FFI types.
async fn open_paired_connection(
    transport: Arc<dyn TrezorTransport>,
    host_static_priv: [u8; 32],
    credential: Vec<u8>,
) -> Result<Connection, TrezorError> {
    let mut conn = Connection::new(transport, BLE_PACKET_SIZE);
    let allocation = conn.allocate().await?;
    let keys = conn
        .handshake(
            allocation.device_properties_raw,
            host_static_priv,
            Some(credential),
        )
        .await?;
    if keys.trezor_state.first().copied() == Some(0x00) {
        return Err(TrezorError::Pairing {
            reason: "stored credential was rejected; re-pair the Trezor".to_string(),
        });
    }
    conn.set_session(Session::from_handshake(&keys));
    pairing::end_request(&mut conn).await?;
    Ok(conn)
}

/// Borrow the pinned paired+seeded connection, opening one into the
/// slot if empty. Reused across pinned ops; the caller clears the slot
/// on error so the next op reconnects fresh.
async fn ensure_conn<'a>(
    slot: &'a mut Option<Connection>,
    transport: &Arc<dyn TrezorTransport>,
    host_static_priv: &[u8],
    credential: Vec<u8>,
    passphrase: &PassphraseSpec,
) -> Result<&'a mut Connection, TrezorError> {
    let (pp, on_device) = match passphrase {
        PassphraseSpec::Standard => (None, false),
        PassphraseSpec::OnDevice => (None, true),
        PassphraseSpec::Host { passphrase } => (Some(passphrase.clone()), false),
    };
    // A pinned connection is reusable only if its seeded session was
    // created with the SAME wallet. Otherwise drop it and reconnect:
    // e.g. `identify` seeds the standard session into the slot, so a
    // following hidden-wallet op must not reuse it (it would derive the
    // standard address). Reconnecting fresh is cheap and provably opens
    // the right seed; only triggered when the wallet actually changes.
    let wallet_changed = slot
        .as_ref()
        .map(|conn| conn.seeded_key() != Some((pp.clone(), on_device)))
        .unwrap_or(false);
    if wallet_changed {
        *slot = None;
    }
    if slot.is_none() {
        let hsp = to_array32(host_static_priv)?;
        let mut conn = open_paired_connection(transport.clone(), hsp, credential).await?;
        conn.create_seeded_session(pp, on_device).await?;
        *slot = Some(conn);
    }
    Ok(slot.as_mut().expect("connection just established"))
}

#[derive(uniffi::Object)]
pub struct TrezorClient {
    transport: Arc<dyn TrezorTransport>,
    /// A pinned, paired+seeded connection reused across operations
    /// while the host keeps a session open (Swift beginSession/
    /// endSession). `None` means each op opens a one-shot connection.
    /// A failed op clears this so the next op reconnects fresh.
    pinned: Mutex<Option<Connection>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl TrezorClient {
    /// Construct a new client backed by the given transport.
    /// Transport ownership is shared via `Arc`. Typical lifecycle is
    /// one client per device session.
    #[uniffi::constructor]
    pub fn new(transport: Arc<dyn TrezorTransport>) -> Arc<Self> {
        Arc::new(Self {
            transport,
            pinned: Mutex::new(None),
        })
    }

    /// Read-only THP bring-up probe: allocate a channel and run the
    /// Noise handshake, returning the device properties + post-
    /// handshake state. No seed access, no pairing, no signing — the
    /// safe first thing to run against a real device (exercises GATT,
    /// framing, channel allocation, and the full handshake). The
    /// `get*`/`sign*` methods below stay stubbed until the session +
    /// pairing layers land (task #2).
    pub async fn thp_probe(&self) -> Result<ThpProbeResult, TrezorError> {
        let mut conn = Connection::new(self.transport.clone(), BLE_PACKET_SIZE);
        let allocation = conn.allocate().await?;
        let mut host_static = [0u8; 32];
        getrandom::getrandom(&mut host_static)
            .map_err(|e| TrezorError::thp(format!("RNG failure: {e}")))?;
        let keys = conn
            .handshake(allocation.device_properties_raw.clone(), host_static, None)
            .await?;
        let props = allocation.device_properties;
        Ok(ThpProbeResult {
            internal_model: props.internal_model,
            protocol_version_major: props.protocol_version_major,
            protocol_version_minor: props.protocol_version_minor,
            pairing_methods: props.pairing_methods,
            trezor_state: keys.trezor_state,
        })
    }

    /// Establish a paired, encrypted session: allocate a channel, run
    /// the handshake, complete CodeEntry pairing (prompting the host
    /// for the on-device code via `code_provider`) unless a valid
    /// `stored_credential` lets us skip it, then read `Features`.
    /// Returns the device identity + the reconnection credential to
    /// persist. This is the gateway to all seed operations.
    pub async fn establish_paired_session(
        &self,
        host_static_priv: Vec<u8>,
        host_name: String,
        app_name: String,
        stored_credential: Option<Vec<u8>>,
        code_provider: Arc<dyn PairingCodeProvider>,
    ) -> Result<PairedSession, TrezorError> {
        let host_static = to_array32(&host_static_priv)?;
        let mut conn = Connection::new(self.transport.clone(), BLE_PACKET_SIZE);
        let allocation = conn.allocate().await?;

        let keys = conn
            .handshake(
                allocation.device_properties_raw.clone(),
                host_static,
                stored_credential.clone(),
            )
            .await?;

        let handshake_hash = keys.handshake_hash;
        let host_static_pubkey = keys.host_static_pubkey;
        // The real device reports trezor_state 0x00 when unpaired.
        let already_paired =
            stored_credential.is_some() && keys.trezor_state.first().copied() != Some(0x00);
        conn.set_session(Session::from_handshake(&keys));

        let credential = if already_paired {
            stored_credential.unwrap_or_default()
        } else {
            pairing::run_codeentry_pairing(
                &mut conn,
                &handshake_hash,
                &host_static_pubkey,
                host_name,
                app_name,
                code_provider,
            )
            .await?
        };

        pairing::end_request(&mut conn).await?;
        let features = pairing::get_features(&mut conn).await?;
        Ok(PairedSession {
            device_id: features.device_id.unwrap_or_default(),
            model: features.model.unwrap_or_default(),
            firmware_version: format!(
                "{}.{}.{}",
                features.major_version, features.minor_version, features.patch_version
            ),
            initialized: features.initialized.unwrap_or(false),
            credential,
        })
    }

    /// Stable device identity via a credential-reconnected session (no
    /// code entry): returns the `Features.device_id`. This MUST be the
    /// same value `establish_paired_session` returns as the serial, so
    /// the host's device-match checks (identity unlock, wallet
    /// discovery/send) recognise the same physical device. Backs the
    /// Swift `identifyDevice()`.
    pub async fn identify_paired(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
    ) -> Result<String, TrezorError> {
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &PassphraseSpec::Standard,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        match pairing::get_features(conn).await {
            Ok(features) => features
                .device_id
                .ok_or_else(|| TrezorError::thp("device returned no device_id")),
            Err(e) => {
                *guard = None;
                Err(e)
            }
        }
    }

    /// Identity-sandwich attestor: the compressed secp256k1 public key
    /// at m/44'/60'/0'/0/0, fetched over a credential-reconnected
    /// session (no code entry). Backs the Swift `pair()`.
    pub async fn get_attestor_pubkey(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
    ) -> Result<Vec<u8>, TrezorError> {
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &PassphraseSpec::Standard,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::ethereum::get_public_key(
            conn,
            SEEDED_SESSION_ID,
            &chains::ethereum::account_path(0),
        )
        .await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    /// Sign an arbitrary message with the attestor key (EIP-191),
    /// returning `R || S`. Backs the Swift `signMessage()` used by the
    /// identity-sandwich attestation + AES-GCM wrap.
    pub async fn sign_message_eth(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, TrezorError> {
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &PassphraseSpec::Standard,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::ethereum::sign_message(
            conn,
            SEEDED_SESSION_ID,
            &chains::ethereum::account_path(0),
            &message,
        )
        .await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    // ---- Identity (registration + identity sandwich) ----

    /// Lightweight registration handshake: allocate a THP channel,
    /// run the Noise XX handshake, read the device `Features`, and
    /// return the stable identity. The returned `device_id` is
    /// persisted as `RegisteredDevice.serial`.
    pub async fn identify(&self) -> Result<TrezorFeatures, TrezorError> {
        Err(TrezorError::not_implemented("identify (THP handshake)"))
    }

    /// Pair (or re-pair) with the device, returning the compressed
    /// secp256k1 public key used as the identity-sandwich attestor.
    /// Establishes (or restores, via a stored credential) the THP
    /// session.
    pub async fn pair(&self) -> Result<Vec<u8>, TrezorError> {
        Err(TrezorError::not_implemented(
            "pair (secp256k1 attestor pubkey)",
        ))
    }

    /// Sign an arbitrary message with the device's secp256k1 key,
    /// returning `R || S` (64 bytes). Backs both identity-sandwich
    /// attestation and the deterministic AES-GCM wrap challenge, so
    /// the digest convention MUST match what the attestation
    /// verifier reconstructs (resolved in task #2) and the signature
    /// MUST be RFC6979-deterministic.
    pub async fn sign_message(&self, message: Vec<u8>) -> Result<Vec<u8>, TrezorError> {
        let _ = message;
        Err(TrezorError::not_implemented(
            "sign_message (secp256k1 R||S)",
        ))
    }

    // ---- Bitcoin ----

    /// BIP84 account-level xpub for `account` on the given network
    /// (coin type 0 mainnet / 1 testnet), to build a watch-only BDK
    /// descriptor host-side. `passphrase` selects the standard or a
    /// hidden wallet (a hidden wallet has its own xpub).
    pub async fn get_bitcoin_account_xpub(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        account: u32,
        network_coin_type: u32,
        path: Option<String>,
    ) -> Result<String, TrezorError> {
        // A custom path selects the script type (BIP44/49/84) from its
        // purpose; else the standard BIP84 account path.
        let address_n = resolve_path(
            path,
            chains::bitcoin::account_path(account, network_coin_type),
        )?;
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::bitcoin::get_account_xpub(
            conn,
            SEEDED_SESSION_ID,
            &address_n,
            network_coin_type,
        )
        .await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    /// 4-byte BIP32 master fingerprint (return as bytes; host hex-
    /// encodes), required alongside the account xpub for a valid BDK
    /// watch-only descriptor. Depends on the seed, so `passphrase` must
    /// match the wallet the xpub was fetched for.
    pub async fn get_bitcoin_master_fingerprint(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
    ) -> Result<Vec<u8>, TrezorError> {
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::bitcoin::get_master_fingerprint(conn, SEEDED_SESSION_ID).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    /// Sign a Bitcoin PSBT. Drives Trezor's `SignTx` streaming
    /// exchange (TxRequest / TxAck) from the parsed PSBT and merges
    /// the returned signatures back in, returning the signed PSBT
    /// base64 with `partial_sigs` populated. Same input/return
    /// contract as `ledger-btc-core::sign_psbt` so the host's BDK
    /// finalize + broadcast path is reused unchanged. Per-input/output
    /// script types (BIP84 native / BIP49 nested SegWit) are derived
    /// from the PSBT's own bip32 paths; legacy BIP44 signing is not yet
    /// supported (it needs previous-tx streaming).
    #[allow(clippy::too_many_arguments)] // mirrors the ledger sign_psbt contract
    pub async fn sign_psbt(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        psbt_base64: String,
        fingerprint_hex: String,
        account_xpub: String,
        account: u32,
        coin_type: u32,
        path: Option<String>,
    ) -> Result<String, TrezorError> {
        // The spend paths + script types come from the PSBT's own
        // bip32_derivation, so the fingerprint/xpub/account/path args
        // (kept for ledger-contract parity) are not needed to drive the
        // SignTx exchange.
        let _ = (fingerprint_hex, account_xpub, account, path);
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::bitcoin::sign_psbt(conn, SEEDED_SESSION_ID, &psbt_base64, coin_type).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    /// Sign an arbitrary message with the Bitcoin key at `address_n` (a full
    /// BIP32 path, e.g. m/84'/0'/0'/0/0). Returns the address the device
    /// signed for plus the 65-byte Electrum "Bitcoin Signed Message"
    /// signature. The user confirms the message on-device.
    pub async fn sign_bitcoin_message(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        address_n: Vec<u32>,
        message: Vec<u8>,
        coin_type: u32,
    ) -> Result<chains::bitcoin::BitcoinMessageSignature, TrezorError> {
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::bitcoin::sign_message(conn, SEEDED_SESSION_ID, &address_n, &message, coin_type).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    // ---- Ethereum ----

    /// EIP-55 checksummed `0x...` address for BIP44 account
    /// m/44'/60'/<account>'/0/0.
    pub async fn get_ethereum_address(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        account: u32,
        path: Option<String>,
    ) -> Result<String, TrezorError> {
        let address_n = resolve_path(path, chains::ethereum::account_path(account))?;
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::ethereum::get_address(conn, SEEDED_SESSION_ID, &address_n).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    /// Sign an EIP-1559 transaction. `envelope` is the 0x02-prefixed
    /// unsigned RLP blob; `passphrase` selects the standard or a hidden
    /// (passphrase) wallet, exactly as `get_ethereum_address`. Returns
    /// parity-bit V plus 32-byte R / S. (Trezor renders token transfers
    /// from its own token definitions; there is no Ledger-CAL
    /// descriptor argument.)
    pub async fn sign_ethereum_tx(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        envelope: Vec<u8>,
        account: u32,
        path: Option<String>,
    ) -> Result<Secp256k1Signature, TrezorError> {
        let address_n = resolve_path(path, chains::ethereum::account_path(account))?;
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r =
            chains::ethereum::sign_eip1559(conn, SEEDED_SESSION_ID, &address_n, &envelope).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    /// EIP-191 `personal_sign` for the user's Ethereum account
    /// (m/44'/60'/<account>'/0/0, or a custom `path`). Returns the full
    /// 65-byte R||S||V signature so a verifier can ecrecover off-device.
    /// `passphrase` selects the standard or a hidden wallet; the user
    /// confirms the message on-device.
    pub async fn sign_ethereum_message(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        account: u32,
        message: Vec<u8>,
        path: Option<String>,
    ) -> Result<Vec<u8>, TrezorError> {
        let address_n = resolve_path(path, chains::ethereum::account_path(account))?;
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r =
            chains::ethereum::sign_message_full(conn, SEEDED_SESSION_ID, &address_n, &message).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    // ---- Solana ----

    /// Base58 ed25519 address for SLIP-0010 account
    /// m/44'/501'/<account>'/0'. `passphrase` selects the standard or a
    /// hidden wallet (a hidden wallet has its own address).
    pub async fn get_solana_address(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        account: u32,
        path: Option<String>,
    ) -> Result<String, TrezorError> {
        let address_n = resolve_path(path, chains::solana::account_path(account))?;
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::solana::get_address(conn, SEEDED_SESSION_ID, &address_n).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    /// Sign a Solana transaction. `unsigned_tx` is the serialized
    /// message bytes; returns the 64-byte ed25519 signature.
    pub async fn sign_solana_tx(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        unsigned_tx: Vec<u8>,
        account: u32,
        path: Option<String>,
    ) -> Result<Vec<u8>, TrezorError> {
        let address_n = resolve_path(path, chains::solana::account_path(account))?;
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r = chains::solana::sign_tx(conn, SEEDED_SESSION_ID, &address_n, &unsigned_tx).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    /// Sign a Solana off-chain message (OCMS) for BIP44 account
    /// m/44'/501'/<account>'/0'. `envelope` is the full serialized
    /// off-chain-message built host-side by ledger-sol-core's
    /// `sol_offchain_envelope` (with this account's pubkey in the signers
    /// list). Returns the 64-byte ed25519 signature. `passphrase` selects the
    /// standard or a hidden wallet.
    pub async fn sign_solana_message(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        envelope: Vec<u8>,
        account: u32,
        path: Option<String>,
    ) -> Result<Vec<u8>, TrezorError> {
        let address_n = resolve_path(path, chains::solana::account_path(account))?;
        let mut guard = self.pinned.lock().await;
        let conn = match ensure_conn(
            &mut guard,
            &self.transport,
            &host_static_priv,
            credential,
            &passphrase,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        let r =
            chains::solana::sign_message(conn, SEEDED_SESSION_ID, &address_n, &envelope).await;
        if r.is_err() {
            *guard = None;
        }
        r
    }

    // ---- Tron (Trezor firmware gained TRX/TRC-20 support in the
    // March 2026 update; the chain impl module is `feature = "tron"`,
    // on by default) ----

    /// Base58check `T...` address for BIP44 account
    /// m/44'/195'/<account>'/0/0. `passphrase` selects the standard or
    /// a hidden wallet.
    pub async fn get_tron_address(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        account: u32,
        path: Option<String>,
    ) -> Result<String, TrezorError> {
        #[cfg(feature = "tron")]
        {
            let address_n = resolve_path(path, chains::tron::account_path(account))?;
            let mut guard = self.pinned.lock().await;
            let conn = match ensure_conn(
                &mut guard,
                &self.transport,
                &host_static_priv,
                credential,
                &passphrase,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    *guard = None;
                    return Err(e);
                }
            };
            let r = chains::tron::get_address(conn, SEEDED_SESSION_ID, &address_n).await;
            if r.is_err() {
                *guard = None;
            }
            r
        }
        #[cfg(not(feature = "tron"))]
        {
            let _ = (host_static_priv, credential, passphrase, account, path);
            Err(TrezorError::not_implemented("tron feature disabled"))
        }
    }

    /// Uncompressed 65-byte secp256k1 public key for the Tron BIP44
    /// account. Trezor's Tron protocol exposes no public-key message
    /// (signing is structured and the signature is recoverable, so
    /// broadcast never needs it); kept on the surface for ledger parity.
    pub async fn get_tron_pubkey(&self, account: u32) -> Result<Vec<u8>, TrezorError> {
        let _ = account;
        Err(TrezorError::not_implemented(
            "get_tron_pubkey (Trezor Tron has no public-key message)",
        ))
    }

    /// Sign a Tron transaction. `raw_tx_proto` is the network-built
    /// `Transaction.raw_data` protobuf; returns the recoverable
    /// signature split into (v, r, s) so the host rebuilds r||s||v.
    pub async fn sign_tron_tx(
        &self,
        host_static_priv: Vec<u8>,
        credential: Vec<u8>,
        passphrase: PassphraseSpec,
        raw_tx_proto: Vec<u8>,
        account: u32,
        path: Option<String>,
    ) -> Result<Secp256k1Signature, TrezorError> {
        #[cfg(feature = "tron")]
        {
            let address_n = resolve_path(path, chains::tron::account_path(account))?;
            let mut guard = self.pinned.lock().await;
            let conn = match ensure_conn(
                &mut guard,
                &self.transport,
                &host_static_priv,
                credential,
                &passphrase,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    *guard = None;
                    return Err(e);
                }
            };
            let r = chains::tron::sign_tx(conn, SEEDED_SESSION_ID, &address_n, &raw_tx_proto).await;
            if r.is_err() {
                *guard = None;
            }
            r
        }
        #[cfg(not(feature = "tron"))]
        {
            let _ = (
                host_static_priv,
                credential,
                passphrase,
                raw_tx_proto,
                account,
                path,
            );
            Err(TrezorError::not_implemented("tron feature disabled"))
        }
    }
}
