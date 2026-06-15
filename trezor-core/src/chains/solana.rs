//! Solana-app messages over a paired THP session: fetch the ed25519
//! address (base58) and sign a serialized message. SLIP-0010 path
//! m/44'/501'/account'/0', matching the ledger path. The address IS
//! the 32-byte ed25519 public key; signing returns the 64-byte
//! signature the host prepends to the serialized transaction.

use prost::Message as _;

use crate::error::TrezorError;
use crate::proto::hw::trezor::messages::solana::{
    SolanaAddress, SolanaGetAddress, SolanaSignTx, SolanaTxSignature,
};
use crate::thp::connection::Connection;

const SOL_GET_ADDRESS: u16 = 902;
const SOL_ADDRESS: u16 = 903;
const SOL_SIGN_TX: u16 = 904;
const SOL_TX_SIGNATURE: u16 = 905;

/// SLIP-0010 path m/44'/501'/account'/0' (all hardened).
pub(crate) fn account_path(account: u32) -> Vec<u32> {
    vec![
        0x8000_0000 | 44,
        0x8000_0000 | 501,
        0x8000_0000 | account,
        0x8000_0000,
    ]
}

/// Base58 ed25519 address at `path` on the given seeded session.
pub(crate) async fn get_address(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
) -> Result<String, TrezorError> {
    let msg = SolanaGetAddress {
        address_n: path.to_vec(),
        show_display: Some(false),
        chunkify: None,
    };
    let (rt, rp) = conn
        .transceive_on(session_id, SOL_GET_ADDRESS, &msg.encode_to_vec())
        .await?;
    if rt != SOL_ADDRESS {
        return Err(TrezorError::thp(format!(
            "expected SolanaAddress ({SOL_ADDRESS}), got message type {rt}"
        )));
    }
    let addr = SolanaAddress::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("SolanaAddress decode: {e}")))?
        .address;
    if addr.is_empty() {
        return Err(TrezorError::thp("SolanaAddress carried an empty address"));
    }
    Ok(addr)
}

/// Sign a serialized Solana message at `account`, returning the 64-byte
/// ed25519 signature. `serialized_tx` is the unsigned message (the
/// bytes that get signed), not the full transaction wrapper.
pub(crate) async fn sign_tx(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
    serialized_tx: &[u8],
) -> Result<Vec<u8>, TrezorError> {
    let msg = SolanaSignTx {
        address_n: path.to_vec(),
        serialized_tx: serialized_tx.to_vec(),
        additional_info: None,
        payment_req: None,
    };
    let (rt, rp) = conn
        .transceive_on(session_id, SOL_SIGN_TX, &msg.encode_to_vec())
        .await?;
    if rt != SOL_TX_SIGNATURE {
        return Err(TrezorError::thp(format!(
            "expected SolanaTxSignature ({SOL_TX_SIGNATURE}), got message type {rt}"
        )));
    }
    let sig = SolanaTxSignature::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("SolanaTxSignature decode: {e}")))?
        .signature;
    if sig.len() != 64 {
        return Err(TrezorError::thp(format!(
            "Solana signature was {} bytes, expected 64",
            sig.len()
        )));
    }
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_path_is_slip10_hardened() {
        // m/44'/501'/0'/0' and m/44'/501'/3'/0'
        assert_eq!(
            account_path(0),
            vec![
                0x8000_0000 + 44,
                0x8000_0000 + 501,
                0x8000_0000,
                0x8000_0000
            ]
        );
        assert_eq!(
            account_path(3),
            vec![
                0x8000_0000 + 44,
                0x8000_0000 + 501,
                0x8000_0000 + 3,
                0x8000_0000
            ]
        );
    }
}
