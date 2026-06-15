//! THP CodeEntry pairing + the credential / end / Features steps that
//! bring a freshly-handshaked channel to ENCRYPTED_TRANSPORT.
//!
//! Host state machine HP0..HP5 + credential phase, per the spec. The
//! CPace crypto is in `cpace` (Elligator2 vector-checked against the
//! device); this module is the message choreography over `transceive`.

#![allow(dead_code)] // wired into TrezorClient::establish_paired_session (task #7).

use std::sync::Arc;

use prost::Message as _;
use sha2::{Digest, Sha256};

use crate::error::TrezorError;
use crate::proto::hw::trezor::messages::management::{Features, GetFeatures};
use crate::proto::hw::trezor::messages::thp::{
    ThpCodeEntryChallenge, ThpCodeEntryCommitment, ThpCodeEntryCpaceHostTag,
    ThpCodeEntryCpaceTrezor, ThpCodeEntrySecret, ThpCredentialRequest, ThpCredentialResponse,
    ThpPairingRequest, ThpSelectMethod,
};
use crate::thp::connection::Connection;
use crate::thp::cpace;

// ThpMessageType wire numbers (messages-thp.proto) + management ones.
const T_PAIRING_REQUEST: u16 = 1008;
const T_PAIRING_REQUEST_APPROVED: u16 = 1009;
const T_SELECT_METHOD: u16 = 1010;
const T_CREDENTIAL_REQUEST: u16 = 1016;
const T_CREDENTIAL_RESPONSE: u16 = 1017;
const T_END_REQUEST: u16 = 1018;
const T_END_RESPONSE: u16 = 1019;
const T_CODE_ENTRY_COMMITMENT: u16 = 1024;
const T_CODE_ENTRY_CHALLENGE: u16 = 1025;
const T_CODE_ENTRY_CPACE_TREZOR: u16 = 1026;
const T_CODE_ENTRY_CPACE_HOST_TAG: u16 = 1027;
const T_CODE_ENTRY_SECRET: u16 = 1028;
const MGMT_GET_FEATURES: u16 = 55;
const MGMT_FEATURES: u16 = 17;

const PAIRING_METHOD_CODE_ENTRY: i32 = 2;

/// Foreign callback: the host UI supplies the 6-digit pairing code the
/// user reads off the Trezor screen. An empty / unparsable string is
/// treated as cancellation.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PairingCodeProvider: Send + Sync {
    async fn request_code(&self) -> String;
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("platform RNG");
    b
}

fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("platform RNG");
    b
}

fn as32(v: &[u8]) -> Result<[u8; 32], TrezorError> {
    <[u8; 32]>::try_from(v).map_err(|_| TrezorError::thp("expected a 32-byte field from device"))
}

fn expect_type(actual: u16, expected: u16, what: &str) -> Result<(), TrezorError> {
    if actual == expected {
        Ok(())
    } else {
        Err(TrezorError::thp(format!(
            "expected {what} ({expected}), got message type {actual}"
        )))
    }
}

/// Run CodeEntry pairing on an already-handshaked connection (session
/// installed via `Connection::set_session`). Returns the issued
/// reconnection credential to persist for the next connect.
pub(crate) async fn run_codeentry_pairing(
    conn: &mut Connection,
    handshake_hash: &[u8; 32],
    host_static_pubkey: &[u8; 32],
    host_name: String,
    app_name: String,
    code_provider: Arc<dyn PairingCodeProvider>,
) -> Result<Vec<u8>, TrezorError> {
    // HP0 -> HP1: request pairing; the user approves on the device
    // (transceive auto-ACKs the ButtonRequest and waits for the tap).
    let (rt, _) = conn
        .transceive(
            T_PAIRING_REQUEST,
            &ThpPairingRequest {
                host_name,
                app_name,
            }
            .encode_to_vec(),
        )
        .await?;
    expect_type(rt, T_PAIRING_REQUEST_APPROVED, "ThpPairingRequestApproved")?;

    // HP1 -> HP2: select CodeEntry; receive the commitment.
    let (rt, rp) = conn
        .transceive(
            T_SELECT_METHOD,
            &ThpSelectMethod {
                selected_pairing_method: PAIRING_METHOD_CODE_ENTRY,
            }
            .encode_to_vec(),
        )
        .await?;
    expect_type(rt, T_CODE_ENTRY_COMMITMENT, "ThpCodeEntryCommitment")?;
    let commitment = ThpCodeEntryCommitment::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("commitment decode: {e}")))?
        .commitment;

    // HP2 -> HP3a: send a random challenge; receive Trezor's CPace key.
    let challenge = random16();
    let (rt, rp) = conn
        .transceive(
            T_CODE_ENTRY_CHALLENGE,
            &ThpCodeEntryChallenge {
                challenge: challenge.to_vec(),
            }
            .encode_to_vec(),
        )
        .await?;
    expect_type(rt, T_CODE_ENTRY_CPACE_TREZOR, "ThpCodeEntryCpaceTrezor")?;
    let cpace_trezor_pub = as32(
        &ThpCodeEntryCpaceTrezor::decode(rp.as_slice())
            .map_err(|e| TrezorError::thp(format!("cpace-trezor decode: {e}")))?
            .cpace_trezor_public_key,
    )?;

    // HP4: the device now displays the 6-digit code; ask the host UI.
    let code_str = code_provider.request_code().await;
    let code_num: u32 = code_str.trim().parse().map_err(|_| TrezorError::Pairing {
        reason: "no valid pairing code was entered".to_string(),
    })?;
    let code = cpace::format_code(code_num);

    let host_priv = random32();
    let host = cpace::host_cpace(&code, handshake_hash, &cpace_trezor_pub, &host_priv);

    // HP4 -> HP5: send our CPace public key + tag; receive the secret.
    // If the code was wrong the device rejects with a Failure here.
    let (rt, rp) = conn
        .transceive(
            T_CODE_ENTRY_CPACE_HOST_TAG,
            &ThpCodeEntryCpaceHostTag {
                cpace_host_public_key: host.host_public.to_vec(),
                tag: host.tag.to_vec(),
            }
            .encode_to_vec(),
        )
        .await?;
    expect_type(rt, T_CODE_ENTRY_SECRET, "ThpCodeEntrySecret")?;
    let secret = ThpCodeEntrySecret::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("secret decode: {e}")))?
        .secret;

    // Confirm the device committed to this secret earlier (detects a
    // device-side MITM).
    let commitment_check: [u8; 32] = Sha256::digest(&secret).into();
    if commitment_check.as_slice() != commitment.as_slice() {
        return Err(TrezorError::Pairing {
            reason: "device secret does not match its commitment".to_string(),
        });
    }

    // Credential phase: request a reconnection credential.
    let (rt, rp) = conn
        .transceive(
            T_CREDENTIAL_REQUEST,
            &ThpCredentialRequest {
                host_static_public_key: host_static_pubkey.to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await?;
    expect_type(rt, T_CREDENTIAL_RESPONSE, "ThpCredentialResponse")?;
    let credential = ThpCredentialResponse::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("credential decode: {e}")))?
        .credential;

    Ok(credential)
}

/// Transition the channel into ENCRYPTED_TRANSPORT (`ThpEndRequest`).
pub(crate) async fn end_request(conn: &mut Connection) -> Result<(), TrezorError> {
    let (rt, _) = conn.transceive(T_END_REQUEST, &[]).await?;
    expect_type(rt, T_END_RESPONSE, "ThpEndResponse")
}

/// Read the device `Features` (device_id, model, version, initialized).
/// Runs on the seedless management session (id 0).
pub(crate) async fn get_features(conn: &mut Connection) -> Result<Features, TrezorError> {
    let (rt, rp) = conn
        .transceive_on(
            0,
            MGMT_GET_FEATURES,
            &GetFeatures::default().encode_to_vec(),
        )
        .await?;
    expect_type(rt, MGMT_FEATURES, "Features")?;
    Features::decode(rp.as_slice()).map_err(|e| TrezorError::thp(format!("features decode: {e}")))
}
