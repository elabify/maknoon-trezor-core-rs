//! Tron-app messages over a paired THP session. Unlike Ledger (which
//! signs the raw-tx hash), Trezor's Tron flow is STRUCTURED: the host
//! sends `TronSignTx` with the contract-agnostic header, the device
//! replies `TronContractRequest`, the host sends the specific contract
//! message, and the device returns `TronSignature`.
//!
//! The host (iOS) still hands us the network-built `raw_data` protobuf
//! (same `signTronTransaction(rawTxProto, ...)` contract as Ledger), so
//! we decode it with the vendored `TronRawTransaction` type and lift
//! out the header + the single contract. The contract `parameter.value`
//! is a native Tron protobuf whose field numbers match Trezor's
//! `TronTransferContract` / `TronTriggerSmartContract`, so it decodes
//! straight into the Trezor message (addresses + amounts pass through
//! verbatim). BIP44 path m/44'/195'/account'/0/0 (secp256k1).

use prost::Message as _;

use crate::error::TrezorError;
use crate::proto::hw::trezor::messages::tron::tron_raw_transaction::tron_raw_contract::TronRawContractType;
use crate::proto::hw::trezor::messages::tron::{
    TronAddress, TronGetAddress, TronRawTransaction, TronSignTx, TronSignature,
    TronTransferContract, TronTriggerSmartContract,
};
use crate::thp::connection::Connection;
use crate::types::Secp256k1Signature;

const TRON_GET_ADDRESS: u16 = 2200;
const TRON_ADDRESS: u16 = 2201;
const TRON_SIGN_TX: u16 = 2202;
const TRON_SIGNATURE: u16 = 2203;
const TRON_CONTRACT_REQUEST: u16 = 2204;
const TRON_TRANSFER_CONTRACT: u16 = 2205;
const TRON_TRIGGER_SMART_CONTRACT: u16 = 2206;

/// BIP44 path m/44'/195'/account'/0/0 (account hardened, change/index
/// not).
pub(crate) fn account_path(account: u32) -> Vec<u32> {
    vec![
        0x8000_0000 | 44,
        0x8000_0000 | 195,
        0x8000_0000 | account,
        0,
        0,
    ]
}

/// Base58Check `T...` address at `path` on the given seeded session.
pub(crate) async fn get_address(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
) -> Result<String, TrezorError> {
    let msg = TronGetAddress {
        address_n: path.to_vec(),
        show_display: Some(false),
        chunkify: None,
    };
    let (rt, rp) = conn
        .transceive_on(session_id, TRON_GET_ADDRESS, &msg.encode_to_vec())
        .await?;
    if rt != TRON_ADDRESS {
        return Err(TrezorError::thp(format!(
            "expected TronAddress ({TRON_ADDRESS}), got message type {rt}"
        )));
    }
    let addr = TronAddress::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("TronAddress decode: {e}")))?
        .address;
    if addr.is_empty() {
        return Err(TrezorError::thp("TronAddress carried an empty address"));
    }
    Ok(addr)
}

/// Sign a Tron transaction. `raw_tx_proto` is the network-built
/// `Transaction.raw_data` protobuf; we decode it, drive the structured
/// SignTx exchange, and return the recoverable signature split into
/// (v, r, s) so the host reassembles the canonical r||s||v exactly.
pub(crate) async fn sign_tx(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
    raw_tx_proto: &[u8],
) -> Result<Secp256k1Signature, TrezorError> {
    let raw = TronRawTransaction::decode(raw_tx_proto)
        .map_err(|e| TrezorError::thp(format!("Tron raw_data decode: {e}")))?;
    let contract = raw
        .contract
        .first()
        .ok_or_else(|| TrezorError::thp("Tron transaction has no contract"))?;

    let sign_tx = TronSignTx {
        address_n: path.to_vec(),
        ref_block_bytes: raw.ref_block_bytes.clone(),
        ref_block_hash: raw.ref_block_hash.clone(),
        expiration: raw.expiration,
        data: raw.data.clone(),
        timestamp: raw.timestamp,
        fee_limit: raw.fee_limit,
    };

    // Resolve the contract message before opening the exchange so an
    // unsupported type fails fast (before the device prompts).
    let value = contract.parameter.value.as_slice();
    let (contract_type, contract_body) = match TronRawContractType::try_from(contract.r#type) {
        Ok(TronRawContractType::TransferContract) => {
            let c = TronTransferContract::decode(value)
                .map_err(|e| TrezorError::thp(format!("TronTransferContract decode: {e}")))?;
            (TRON_TRANSFER_CONTRACT, c.encode_to_vec())
        }
        Ok(TronRawContractType::TriggerSmartContract) => {
            let c = TronTriggerSmartContract::decode(value)
                .map_err(|e| TrezorError::thp(format!("TronTriggerSmartContract decode: {e}")))?;
            (TRON_TRIGGER_SMART_CONTRACT, c.encode_to_vec())
        }
        other => {
            return Err(TrezorError::thp(format!(
                "unsupported Tron contract {other:?}; only TRX transfer and TRC-20 \
                 (TriggerSmartContract) are supported"
            )));
        }
    };

    let (rt, _rp) = conn
        .transceive_on(session_id, TRON_SIGN_TX, &sign_tx.encode_to_vec())
        .await?;
    if rt != TRON_CONTRACT_REQUEST {
        return Err(TrezorError::thp(format!(
            "expected TronContractRequest ({TRON_CONTRACT_REQUEST}), got message type {rt}"
        )));
    }

    let (rt2, rp2) = conn.transceive(contract_type, &contract_body).await?;
    if rt2 != TRON_SIGNATURE {
        return Err(TrezorError::thp(format!(
            "expected TronSignature ({TRON_SIGNATURE}), got message type {rt2}"
        )));
    }
    let sig = TronSignature::decode(rp2.as_slice())
        .map_err(|e| TrezorError::thp(format!("TronSignature decode: {e}")))?
        .signature;
    if sig.len() != 65 {
        return Err(TrezorError::thp(format!(
            "Tron signature was {} bytes, expected 65 (r||s||v)",
            sig.len()
        )));
    }
    // Tron's recoverable signature is r(32)||s(32)||v(1). Split it so
    // the host rebuilds the identical r||s||v for broadcast.
    Ok(Secp256k1Signature {
        v: sig[64],
        r: sig[0..32].to_vec(),
        s: sig[32..64].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_path_is_bip44() {
        // m/44'/195'/0'/0/0
        assert_eq!(
            account_path(0),
            vec![0x8000_0000 + 44, 0x8000_0000 + 195, 0x8000_0000, 0, 0]
        );
    }

    // Decode a hand-built raw_data with one TransferContract and assert
    // the header + contract lift out correctly, exercising the nested
    // TronRawContract / TronRawParameter decode path.
    #[test]
    fn lifts_transfer_contract_from_raw_data() {
        use crate::proto::hw::trezor::messages::tron::tron_raw_transaction::{
            tron_raw_contract::{TronRawContractType, TronRawParameter},
            TronRawContract,
        };

        let transfer = TronTransferContract {
            owner_address: vec![0x41; 21],
            to_address: vec![0x41; 21],
            amount: 1_000_000,
        };
        let raw = TronRawTransaction {
            ref_block_bytes: vec![0x12, 0x34],
            ref_block_hash: vec![0xaa; 8],
            expiration: 111,
            data: None,
            timestamp: 222,
            fee_limit: None,
            contract: vec![TronRawContract {
                r#type: TronRawContractType::TransferContract as i32,
                parameter: TronRawParameter {
                    type_url: "type.googleapis.com/protocol.TransferContract".to_string(),
                    value: transfer.encode_to_vec(),
                },
            }],
        };
        let bytes = raw.encode_to_vec();

        let decoded = TronRawTransaction::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.ref_block_bytes, vec![0x12, 0x34]);
        assert_eq!(decoded.expiration, 111);
        let c = decoded.contract.first().unwrap();
        assert_eq!(
            TronRawContractType::try_from(c.r#type),
            Ok(TronRawContractType::TransferContract)
        );
        let tc = TronTransferContract::decode(c.parameter.value.as_slice()).unwrap();
        assert_eq!(tc.amount, 1_000_000);
        assert_eq!(tc.owner_address, vec![0x41; 21]);
    }
}
