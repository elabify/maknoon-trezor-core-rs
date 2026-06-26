//! Bitcoin-app messages over a paired THP session. This stage covers
//! the watch-only inputs the host's BDK descriptor needs: the BIP84
//! account-level xpub and the master root fingerprint. PSBT signing
//! (the `SignTx` streaming state machine) lands in a following stage;
//! its message constants are reserved here so the contract is visible.
//!
//! Maknoon is BIP84 native-segwit only (wpkh), matching the ledger
//! path: account path m/84'/coin'/account', SPENDWITNESS script type,
//! and a standard xpub/tpub prefix (ignore_xpub_magic) so the host can
//! build `wpkh([fp/84'/coin'/account']xpub/**)` unchanged.

#![allow(dead_code)] // some proto fields/consts are referenced only on one path.

use std::collections::BTreeMap;
use std::str::FromStr;

use prost::Message as _;

use bitcoin::bip32::DerivationPath;
use bitcoin::ecdsa;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature as SecpSignature;
use bitcoin::{Address, EcdsaSighashType, Network, PublicKey as BtcPublicKey};

use crate::error::TrezorError;
use crate::proto::hw::trezor::messages::bitcoin as btc;
use crate::proto::hw::trezor::messages::bitcoin::tx_request::RequestType;
use crate::proto::hw::trezor::messages::bitcoin::{
    GetPublicKey, InputScriptType, MessageSignature, OutputScriptType, PublicKey, SignMessage,
};
use crate::thp::connection::Connection;

const BTC_GET_PUBLIC_KEY: u16 = 11;
const BTC_PUBLIC_KEY: u16 = 12;
const BTC_SIGN_TX: u16 = 15;
const BTC_TX_REQUEST: u16 = 21;
// TxAckInput / TxAckOutput are wire-aliased to TxAck (message type 22).
const BTC_TX_ACK: u16 = 22;
const BTC_SIGN_MESSAGE: u16 = 38;
const BTC_MESSAGE_SIGNATURE: u16 = 40;

/// BIP84 account path m/84'/coin'/account' (all hardened).
pub(crate) fn account_path(account: u32, coin_type: u32) -> Vec<u32> {
    vec![
        0x8000_0000 | 84,
        0x8000_0000 | coin_type,
        0x8000_0000 | account,
    ]
}

/// Trezor coin name for a BIP44 coin type. Maknoon only ships mainnet
/// (0) and testnet (1); anything else falls back to mainnet so a
/// mis-set network never silently signs on a surprise chain.
fn coin_name(coin_type: u32) -> &'static str {
    match coin_type {
        1 => "Testnet",
        _ => "Bitcoin",
    }
}

/// Map a path's purpose (its first hardened component) to the input
/// script type: 44 legacy P2PKH, 49 nested SegWit, 84 native SegWit.
/// Anything else (incl. an empty path) defaults to native SegWit, the
/// app's standard. Taproot (86) is intentionally not supported.
fn script_type_for_path(address_n: &[u32]) -> InputScriptType {
    match address_n.first().map(|p| p & !0x8000_0000) {
        Some(44) => InputScriptType::Spendaddress,
        Some(49) => InputScriptType::Spendp2shwitness,
        _ => InputScriptType::Spendwitness,
    }
}

/// Result of a Bitcoin message signature: the address the device signed
/// for and the 65-byte Electrum "Bitcoin Signed Message" signature
/// (header || r || s; the device sets the address-type header byte).
#[derive(uniffi::Record)]
pub struct BitcoinMessageSignature {
    pub address: String,
    pub signature: Vec<u8>,
}

/// Sign an arbitrary message with the key at `address_n` (a full BIP32
/// path), in the standard "Bitcoin Signed Message" format. The device
/// shows the message + address and the user confirms on-device (the
/// connection auto-ACKs the ButtonRequest). The script type is derived
/// from the path's purpose so the signature binds to the matching
/// legacy/nested/native address, exactly like Electrum.
pub(crate) async fn sign_message(
    conn: &mut Connection,
    session_id: u8,
    address_n: &[u32],
    message: &[u8],
    coin_type: u32,
) -> Result<BitcoinMessageSignature, TrezorError> {
    let (rt, rp) = conn
        .transceive_on(
            session_id,
            BTC_SIGN_MESSAGE,
            &SignMessage {
                address_n: address_n.to_vec(),
                message: message.to_vec(),
                coin_name: Some(coin_name(coin_type).to_string()),
                script_type: Some(script_type_for_path(address_n) as i32),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await?;
    if rt != BTC_MESSAGE_SIGNATURE {
        return Err(TrezorError::thp(format!(
            "expected MessageSignature ({BTC_MESSAGE_SIGNATURE}), got message type {rt}"
        )));
    }
    let ms = MessageSignature::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("MessageSignature decode: {e}")))?;
    Ok(BitcoinMessageSignature {
        address: ms.address,
        signature: ms.signature,
    })
}

/// Account-level xpub (standard xpub/tpub prefix) at `address_n` for
/// building a watch-only BDK descriptor host-side. The script type is
/// derived from the path purpose so BIP44/49/84 accounts each get the
/// right xpub.
pub(crate) async fn get_account_xpub(
    conn: &mut Connection,
    session_id: u8,
    address_n: &[u32],
    coin_type: u32,
) -> Result<String, TrezorError> {
    let msg = GetPublicKey {
        address_n: address_n.to_vec(),
        ecdsa_curve_name: None,
        show_display: Some(false),
        coin_name: Some(coin_name(coin_type).to_string()),
        script_type: Some(script_type_for_path(address_n) as i32),
        // Use the xpub/tpub prefix (not SLIP-0132 zpub/vpub) so the
        // host's descriptor parser accepts it unchanged.
        ignore_xpub_magic: Some(true),
    };
    let (rt, rp) = conn
        .transceive_on(session_id, BTC_GET_PUBLIC_KEY, &msg.encode_to_vec())
        .await?;
    if rt != BTC_PUBLIC_KEY {
        return Err(TrezorError::thp(format!(
            "expected PublicKey ({BTC_PUBLIC_KEY}), got message type {rt}"
        )));
    }
    let pk = PublicKey::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("PublicKey decode: {e}")))?;
    if pk.xpub.is_empty() {
        return Err(TrezorError::thp("PublicKey carried an empty xpub"));
    }
    Ok(pk.xpub)
}

/// 4-byte big-endian BIP32 master root fingerprint. The host hex-
/// encodes it for the descriptor key-origin. It depends on the seed
/// (so a passphrase wallet has its own), which is why the seeded
/// session matters; the path itself is irrelevant since
/// `root_fingerprint` always describes the master node.
pub(crate) async fn get_master_fingerprint(
    conn: &mut Connection,
    session_id: u8,
) -> Result<Vec<u8>, TrezorError> {
    let msg = GetPublicKey {
        address_n: account_path(0, 0),
        ecdsa_curve_name: None,
        show_display: Some(false),
        coin_name: Some("Bitcoin".to_string()),
        script_type: Some(InputScriptType::Spendwitness as i32),
        ignore_xpub_magic: Some(true),
    };
    let (rt, rp) = conn
        .transceive_on(session_id, BTC_GET_PUBLIC_KEY, &msg.encode_to_vec())
        .await?;
    if rt != BTC_PUBLIC_KEY {
        return Err(TrezorError::thp(format!(
            "expected PublicKey ({BTC_PUBLIC_KEY}), got message type {rt}"
        )));
    }
    let pk = PublicKey::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("PublicKey decode: {e}")))?;
    let fp = pk
        .root_fingerprint
        .ok_or_else(|| TrezorError::thp("PublicKey missing root_fingerprint"))?;
    Ok(fp.to_be_bytes().to_vec())
}

/// Sign a PSBT by driving Trezor's `SignTx` streaming exchange. Parses
/// the unsigned PSBT, answers each `TxRequest` with the matching item,
/// collects the per-input signatures, merges them in as `partial_sigs`,
/// and returns the signed PSBT base64. The host's BDK path finalizes +
/// broadcasts, identical to the ledger contract.
///
/// Modern Trezor firmware verifies every input's amount against its
/// previous transaction even for SegWit (the SegWit fee-attack
/// mitigation), so it requests `TXMETA` + previous `TXINPUT`/`TXOUTPUT`
/// (with `details.tx_hash` set) for each input. We answer those from the
/// PSBT's `non_witness_utxo` (the full prev tx; present because the send
/// sync uses `fetchPrevTxouts: true`). BIP84/49/44 are all supported;
/// RBF-origin / extra-data requests (which we never produce) error.
pub(crate) async fn sign_psbt(
    conn: &mut Connection,
    session_id: u8,
    psbt_base64: &str,
    coin_type: u32,
) -> Result<String, TrezorError> {
    let mut psbt =
        Psbt::from_str(psbt_base64).map_err(|e| TrezorError::thp(format!("PSBT parse: {e}")))?;
    let network = if coin_type == 1 {
        Network::Testnet
    } else {
        Network::Bitcoin
    };

    let sign_tx = btc::SignTx {
        outputs_count: psbt.unsigned_tx.output.len() as u32,
        inputs_count: psbt.unsigned_tx.input.len() as u32,
        coin_name: Some(coin_name(coin_type).to_string()),
        version: Some(psbt.unsigned_tx.version.0 as u32),
        lock_time: Some(psbt.unsigned_tx.lock_time.to_consensus_u32()),
        serialize: Some(true),
        ..Default::default()
    };

    let (mut rt, mut rp) = conn
        .transceive_on(session_id, BTC_SIGN_TX, &sign_tx.encode_to_vec())
        .await?;

    // input index -> DER signature (no trailing sighash byte)
    let mut sigs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();

    loop {
        if rt != BTC_TX_REQUEST {
            return Err(TrezorError::thp(format!(
                "expected TxRequest ({BTC_TX_REQUEST}), got message type {rt}"
            )));
        }
        let req = btc::TxRequest::decode(rp.as_slice())
            .map_err(|e| TrezorError::thp(format!("TxRequest decode: {e}")))?;

        // The device dribbles signatures back as it finishes each input.
        if let Some(ser) = req.serialized.as_ref() {
            if let (Some(idx), Some(sig)) = (ser.signature_index, ser.signature.as_ref()) {
                sigs.insert(idx, sig.clone());
            }
        }

        let request_index = req
            .details
            .as_ref()
            .and_then(|d| d.request_index)
            .unwrap_or(0) as usize;
        // When `tx_hash` is set the request is about a PREVIOUS tx (the
        // device verifies input amounts), not the tx being signed.
        let tx_hash = req.details.as_ref().and_then(|d| d.tx_hash.clone());
        let rtype = req.request_type.unwrap_or(RequestType::Txfinished as i32);

        let ack = match RequestType::try_from(rtype) {
            Ok(RequestType::Txfinished) => break,
            Ok(RequestType::Txinput) => match &tx_hash {
                Some(h) => build_prev_input_ack(&psbt, h, request_index)?.encode_to_vec(),
                None => build_input_ack(&psbt, request_index)?.encode_to_vec(),
            },
            Ok(RequestType::Txoutput) => match &tx_hash {
                Some(h) => build_prev_output_ack(&psbt, h, request_index)?.encode_to_vec(),
                None => build_output_ack(&psbt, request_index, network)?.encode_to_vec(),
            },
            Ok(RequestType::Txmeta) => {
                let h = tx_hash
                    .as_deref()
                    .ok_or_else(|| TrezorError::thp("TXMETA request without a tx_hash"))?;
                build_prev_meta_ack(&psbt, h)?.encode_to_vec()
            }
            other => {
                return Err(TrezorError::thp(format!(
                    "Trezor requested unsupported tx item {other:?} (request_type {rtype}); \
                     RBF-origin / extra-data streaming is not supported"
                )));
            }
        };
        let next = conn.transceive(BTC_TX_ACK, &ack).await?;
        rt = next.0;
        rp = next.1;
    }

    // Merge each signature into the PSBT as a partial_sig, keyed by the
    // compressed pubkey from that input's bip32 derivation. The device
    // returns a bare DER signature, so we append SIGHASH_ALL via the
    // `ecdsa::Signature` wrapper; BDK then finalizes the witness.
    for (idx, der) in sigs {
        let input = psbt
            .inputs
            .get_mut(idx as usize)
            .ok_or_else(|| TrezorError::thp(format!("signature for unknown input {idx}")))?;
        let secp_pub = *input
            .bip32_derivation
            .keys()
            .next()
            .ok_or_else(|| TrezorError::thp(format!("input {idx} missing bip32_derivation")))?;
        let sig = SecpSignature::from_der(&der)
            .map_err(|e| TrezorError::thp(format!("device signature parse: {e}")))?;
        input.partial_sigs.insert(
            BtcPublicKey::new(secp_pub),
            ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            },
        );
    }

    Ok(psbt.to_string())
}

/// Render a derivation path as Trezor's `address_n` (each child as a
/// raw u32 including the hardened high bit).
fn path_to_vec(path: &DerivationPath) -> Vec<u32> {
    path.into_iter().map(|c| u32::from(*c)).collect()
}

/// Build the `TxAckInput` for input `i`. BIP84 native SegWit: the
/// device only needs the spend path, amount, and outpoint; `prev_hash`
/// is the display-order txid (firmware reverses it back to consensus
/// order on serialization).
fn build_input_ack(psbt: &Psbt, i: usize) -> Result<btc::TxAckInput, TrezorError> {
    let txin = psbt
        .unsigned_tx
        .input
        .get(i)
        .ok_or_else(|| TrezorError::thp(format!("TxRequest input index {i} out of range")))?;
    let pin = psbt
        .inputs
        .get(i)
        .ok_or_else(|| TrezorError::thp(format!("PSBT input {i} missing")))?;
    // Amount comes from the witness UTXO (SegWit) or, for a legacy
    // input, the matching output of the full previous tx.
    let amount = if let Some(utxo) = pin.witness_utxo.as_ref() {
        utxo.value.to_sat()
    } else if let Some(prev) = pin.non_witness_utxo.as_ref() {
        prev.output
            .get(txin.previous_output.vout as usize)
            .ok_or_else(|| TrezorError::thp(format!("PSBT input {i} prev output out of range")))?
            .value
            .to_sat()
    } else {
        return Err(TrezorError::thp(format!(
            "PSBT input {i} has neither witness_utxo nor non_witness_utxo"
        )));
    };
    let (_pubkey, (_fp, path)) = pin
        .bip32_derivation
        .iter()
        .next()
        .ok_or_else(|| TrezorError::thp(format!("PSBT input {i} missing bip32_derivation")))?;
    let address_n = path_to_vec(path);

    let mut prev_hash = txin
        .previous_output
        .txid
        .to_raw_hash()
        .to_byte_array()
        .to_vec();
    prev_hash.reverse();

    let input = btc::TxInput {
        script_type: Some(script_type_for_path(&address_n) as i32),
        address_n,
        prev_hash,
        prev_index: txin.previous_output.vout,
        sequence: Some(txin.sequence.0),
        amount,
        ..Default::default()
    };
    Ok(btc::TxAckInput {
        tx: btc::tx_ack_input::TxAckInputWrapper { input },
    })
}

/// Build the `TxAckOutput` for output `i`. A change output (one we have
/// a derivation for in the PSBT) is sent as `address_n` +
/// `PAYTOWITNESS` so the device derives + verifies it; an external
/// recipient is sent as its address string.
fn build_output_ack(
    psbt: &Psbt,
    i: usize,
    network: Network,
) -> Result<btc::TxAckOutput, TrezorError> {
    let txout = psbt
        .unsigned_tx
        .output
        .get(i)
        .ok_or_else(|| TrezorError::thp(format!("TxRequest output index {i} out of range")))?;
    let amount = txout.value.to_sat();

    let change = psbt
        .outputs
        .get(i)
        .filter(|po| !po.bip32_derivation.is_empty());

    let output = if let Some(po) = change {
        let (_pubkey, (_fp, path)) = po
            .bip32_derivation
            .iter()
            .next()
            .expect("non-empty bip32_derivation");
        let address_n = path_to_vec(path);
        let script_type = match script_type_for_path(&address_n) {
            InputScriptType::Spendp2shwitness => OutputScriptType::Paytop2shwitness,
            InputScriptType::Spendaddress => OutputScriptType::Paytoaddress,
            _ => OutputScriptType::Paytowitness,
        };
        btc::TxOutput {
            address_n,
            amount,
            script_type: Some(script_type as i32),
            ..Default::default()
        }
    } else {
        let addr = Address::from_script(&txout.script_pubkey, network)
            .map_err(|e| TrezorError::thp(format!("output {i} address from script: {e}")))?;
        btc::TxOutput {
            address: Some(addr.to_string()),
            amount,
            script_type: Some(OutputScriptType::Paytoaddress as i32),
            ..Default::default()
        }
    };
    Ok(btc::TxAckOutput {
        tx: btc::tx_ack_output::TxAckOutputWrapper { output },
    })
}

/// Find the full previous transaction the device is asking about,
/// identified by `tx_hash` (display order), among the PSBT inputs'
/// `non_witness_utxo`. The send sync uses `fetchPrevTxouts: true`, so
/// these are present; a missing one is a clear error.
fn find_prev_tx<'a>(
    psbt: &'a Psbt,
    tx_hash: &[u8],
) -> Result<&'a bitcoin::Transaction, TrezorError> {
    for pin in &psbt.inputs {
        if let Some(prev) = pin.non_witness_utxo.as_ref() {
            let mut txid = prev.compute_txid().to_raw_hash().to_byte_array().to_vec();
            txid.reverse();
            if txid == tx_hash {
                return Ok(prev);
            }
        }
    }
    Err(TrezorError::thp(
        "Trezor asked for a previous transaction the PSBT doesn't carry; \
         re-sync the wallet (it must include full previous transactions)",
    ))
}

/// `TxAckPrevMeta` for the previous tx the device is verifying.
fn build_prev_meta_ack(psbt: &Psbt, tx_hash: &[u8]) -> Result<btc::TxAckPrevMeta, TrezorError> {
    let prev = find_prev_tx(psbt, tx_hash)?;
    Ok(btc::TxAckPrevMeta {
        tx: btc::PrevTx {
            version: prev.version.0 as u32,
            lock_time: prev.lock_time.to_consensus_u32(),
            inputs_count: prev.input.len() as u32,
            outputs_count: prev.output.len() as u32,
            ..Default::default()
        },
    })
}

/// `TxAckPrevInput` for input `i` of the previous tx `tx_hash`.
fn build_prev_input_ack(
    psbt: &Psbt,
    tx_hash: &[u8],
    i: usize,
) -> Result<btc::TxAckPrevInput, TrezorError> {
    let prev = find_prev_tx(psbt, tx_hash)?;
    let txin = prev
        .input
        .get(i)
        .ok_or_else(|| TrezorError::thp(format!("prev tx input index {i} out of range")))?;
    let mut prev_hash = txin
        .previous_output
        .txid
        .to_raw_hash()
        .to_byte_array()
        .to_vec();
    prev_hash.reverse();
    let input = btc::PrevInput {
        prev_hash,
        prev_index: txin.previous_output.vout,
        script_sig: txin.script_sig.as_bytes().to_vec(),
        sequence: txin.sequence.0,
        ..Default::default()
    };
    Ok(btc::TxAckPrevInput {
        tx: btc::tx_ack_prev_input::TxAckPrevInputWrapper { input },
    })
}

/// `TxAckPrevOutput` for output `i` of the previous tx `tx_hash`.
fn build_prev_output_ack(
    psbt: &Psbt,
    tx_hash: &[u8],
    i: usize,
) -> Result<btc::TxAckPrevOutput, TrezorError> {
    let prev = find_prev_tx(psbt, tx_hash)?;
    let txout = prev
        .output
        .get(i)
        .ok_or_else(|| TrezorError::thp(format!("prev tx output index {i} out of range")))?;
    let output = btc::PrevOutput {
        amount: txout.value.to_sat(),
        script_pubkey: txout.script_pubkey.as_bytes().to_vec(),
        ..Default::default()
    };
    Ok(btc::TxAckPrevOutput {
        tx: btc::tx_ack_prev_output::TxAckPrevOutputWrapper { output },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_path_is_bip84_hardened() {
        // m/84'/0'/0' and m/84'/1'/2'
        assert_eq!(
            account_path(0, 0),
            vec![0x8000_0000 + 84, 0x8000_0000, 0x8000_0000]
        );
        assert_eq!(
            account_path(2, 1),
            vec![0x8000_0000 + 84, 0x8000_0000 + 1, 0x8000_0000 + 2]
        );
    }

    #[test]
    fn script_type_follows_purpose() {
        let h = 0x8000_0000u32;
        assert_eq!(
            script_type_for_path(&[h | 44, h, h]),
            InputScriptType::Spendaddress
        );
        assert_eq!(
            script_type_for_path(&[h | 49, h, h]),
            InputScriptType::Spendp2shwitness
        );
        assert_eq!(
            script_type_for_path(&[h | 84, h, h]),
            InputScriptType::Spendwitness
        );
        // Unknown / empty -> native segwit default.
        assert_eq!(
            script_type_for_path(&[h | 86, h, h]),
            InputScriptType::Spendwitness
        );
        assert_eq!(script_type_for_path(&[]), InputScriptType::Spendwitness);
    }

    #[test]
    fn coin_name_maps_mainnet_and_testnet() {
        assert_eq!(coin_name(0), "Bitcoin");
        assert_eq!(coin_name(1), "Testnet");
        assert_eq!(coin_name(99), "Bitcoin");
    }

    // Locks the load-bearing PSBT -> SignTx mapping: prev_hash byte
    // order, amounts from the witness UTXO, SPENDWITNESS, and change
    // (address_n + PAYTOWITNESS) vs external (address + PAYTOADDRESS).
    #[test]
    fn maps_bip84_input_and_outputs() {
        use bitcoin::absolute::LockTime;
        use bitcoin::bip32::{DerivationPath, Fingerprint};
        use bitcoin::secp256k1::{PublicKey as SecpPub, Secp256k1, SecretKey};
        use bitcoin::transaction::Version;
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        use std::str::FromStr;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let pk = SecpPub::from_secret_key(&secp, &sk);
        let btc_pk = BtcPublicKey::new(pk);
        let wpkh = ScriptBuf::new_p2wpkh(&btc_pk.wpubkey_hash().unwrap());

        let txid =
            Txid::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .unwrap();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 7 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: wpkh.clone(),
                },
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: wpkh.clone(),
                },
            ],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let fp = Fingerprint::from([0u8; 4]);
        let in_path = DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap();
        let change_path = DerivationPath::from_str("m/84'/1'/0'/1/0").unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(60_000),
            script_pubkey: wpkh.clone(),
        });
        psbt.inputs[0]
            .bip32_derivation
            .insert(pk, (fp, in_path.clone()));
        // Only output 1 is ours -> it is treated as change.
        psbt.outputs[1]
            .bip32_derivation
            .insert(pk, (fp, change_path.clone()));

        let input = build_input_ack(&psbt, 0).unwrap().tx.input;
        assert_eq!(input.amount, 60_000);
        assert_eq!(input.prev_index, 7);
        assert_eq!(input.sequence, Some(0xffff_fffd));
        assert_eq!(
            input.script_type,
            Some(InputScriptType::Spendwitness as i32)
        );
        assert_eq!(input.address_n, path_to_vec(&in_path));
        let mut expect_prev = txid.to_raw_hash().to_byte_array().to_vec();
        expect_prev.reverse();
        assert_eq!(
            input.prev_hash, expect_prev,
            "prev_hash must be display order"
        );

        let out0 = build_output_ack(&psbt, 0, Network::Testnet)
            .unwrap()
            .tx
            .output;
        assert_eq!(out0.amount, 50_000);
        assert_eq!(
            out0.script_type,
            Some(OutputScriptType::Paytoaddress as i32)
        );
        assert!(out0.address.is_some());
        assert!(out0.address_n.is_empty());

        let out1 = build_output_ack(&psbt, 1, Network::Testnet)
            .unwrap()
            .tx
            .output;
        assert_eq!(out1.amount, 10_000);
        assert_eq!(
            out1.script_type,
            Some(OutputScriptType::Paytowitness as i32)
        );
        assert_eq!(out1.address, None);
        assert_eq!(out1.address_n, path_to_vec(&change_path));
    }
}
