//! Ethereum-app messages over a paired THP session: fetch the
//! secp256k1 public key (the identity-sandwich attestor) and produce
//! EIP-191 message signatures. Trezor's `EthereumSignMessage` uses the
//! same `\x19Ethereum Signed Message:\n` + keccak256 convention as the
//! Ledger path, so the existing attestation verifier handles both.

#![allow(dead_code)] // get_public_key/sign_message consumed by client + per-chain work.

use prost::Message as _;

use crate::error::TrezorError;
use crate::proto::hw::trezor::messages::ethereum::{
    EthereumAddress, EthereumGetAddress, EthereumGetPublicKey, EthereumMessageSignature,
    EthereumPublicKey, EthereumSignMessage, EthereumSignTxEip1559, EthereumTxRequest,
};
use crate::thp::connection::Connection;
use crate::types::Secp256k1Signature;

const ETH_GET_ADDRESS: u16 = 56;
const ETH_ADDRESS: u16 = 57;
const ETH_GET_PUBLIC_KEY: u16 = 450;
const ETH_PUBLIC_KEY: u16 = 451;
const ETH_SIGN_MESSAGE: u16 = 64;
const ETH_MESSAGE_SIGNATURE: u16 = 66;
const ETH_SIGN_TX_EIP1559: u16 = 452;
const ETH_TX_REQUEST: u16 = 59;

/// EIP-55 checksummed `0x…` address at `path`, on the given seeded
/// session.
pub(crate) async fn get_address(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
) -> Result<String, TrezorError> {
    let (rt, rp) = conn
        .transceive_on(
            session_id,
            ETH_GET_ADDRESS,
            &EthereumGetAddress {
                address_n: path.to_vec(),
                show_display: Some(false),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await?;
    if rt != ETH_ADDRESS {
        return Err(TrezorError::thp(format!(
            "expected EthereumAddress ({ETH_ADDRESS}), got message type {rt}"
        )));
    }
    EthereumAddress::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("EthereumAddress decode: {e}")))?
        .address
        .ok_or_else(|| TrezorError::thp("EthereumAddress missing address"))
}

/// BIP44 path m/44'/60'/<account>'/0/0.
pub(crate) fn account_path(account: u32) -> Vec<u32> {
    vec![0x8000_002C, 0x8000_003C, 0x8000_0000 | account, 0, 0]
}

/// Compressed secp256k1 public key (33 bytes) at `path`, on the given
/// seeded session.
pub(crate) async fn get_public_key(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
) -> Result<Vec<u8>, TrezorError> {
    let (rt, rp) = conn
        .transceive_on(
            session_id,
            ETH_GET_PUBLIC_KEY,
            &EthereumGetPublicKey {
                address_n: path.to_vec(),
                show_display: Some(false),
            }
            .encode_to_vec(),
        )
        .await?;
    if rt != ETH_PUBLIC_KEY {
        return Err(TrezorError::thp(format!(
            "expected EthereumPublicKey ({ETH_PUBLIC_KEY}), got message type {rt}"
        )));
    }
    let msg = EthereumPublicKey::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("EthereumPublicKey decode: {e}")))?;
    Ok(msg.node.public_key)
}

/// EIP-191 message signature, returned as `R || S` (64 bytes; the
/// recovery byte is dropped to match the ledger wire format).
pub(crate) async fn sign_message(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
    message: &[u8],
) -> Result<Vec<u8>, TrezorError> {
    let (rt, rp) = conn
        .transceive_on(
            session_id,
            ETH_SIGN_MESSAGE,
            &EthereumSignMessage {
                address_n: path.to_vec(),
                message: message.to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await?;
    if rt != ETH_MESSAGE_SIGNATURE {
        return Err(TrezorError::thp(format!(
            "expected EthereumMessageSignature ({ETH_MESSAGE_SIGNATURE}), got message type {rt}"
        )));
    }
    let sig = EthereumMessageSignature::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("EthereumMessageSignature decode: {e}")))?
        .signature;
    if sig.len() < 64 {
        return Err(TrezorError::thp("Ethereum signature shorter than 64 bytes"));
    }
    Ok(sig[..64].to_vec())
}

/// EIP-191 message signature, returned as the FULL 65-byte `R || S || V`.
/// Unlike `sign_message` (which drops the recovery byte for the identity
/// sandwich's R||S wire format), this keeps `V` so a user-facing
/// `personal_sign` can be verified by ecrecover off-device.
pub(crate) async fn sign_message_full(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
    message: &[u8],
) -> Result<Vec<u8>, TrezorError> {
    let (rt, rp) = conn
        .transceive_on(
            session_id,
            ETH_SIGN_MESSAGE,
            &EthereumSignMessage {
                address_n: path.to_vec(),
                message: message.to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await?;
    if rt != ETH_MESSAGE_SIGNATURE {
        return Err(TrezorError::thp(format!(
            "expected EthereumMessageSignature ({ETH_MESSAGE_SIGNATURE}), got message type {rt}"
        )));
    }
    let sig = EthereumMessageSignature::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("EthereumMessageSignature decode: {e}")))?
        .signature;
    if sig.len() < 65 {
        return Err(TrezorError::thp("Ethereum signature shorter than 65 bytes"));
    }
    Ok(sig[..65].to_vec())
}

/// Sign an EIP-1559 (type-2) transaction at `path` on a seeded
/// session. `envelope` is the host-built `0x02 || rlp([...])` unsigned
/// blob (identical to what the ledger path hands its device); we decode
/// it into the structured fields Trezor's protobuf wants. Maknoon's txs
/// carry at most ~68 bytes of calldata (an ERC-20 `transfer`), well
/// under the 1024-byte single-chunk limit, so this is one
/// request/response plus the device-confirm `ButtonRequest` that
/// `transceive` auto-ACKs. Returns the parity-bit V (0/1) and 32-byte
/// R / S, matching `Secp256k1Signature` and the ledger wire shape.
pub(crate) async fn sign_eip1559(
    conn: &mut Connection,
    session_id: u8,
    path: &[u32],
    envelope: &[u8],
) -> Result<Secp256k1Signature, TrezorError> {
    let tx = decode_eip1559_envelope(envelope)?;
    let to_str = if tx.to.is_empty() {
        // Contract creation: leave `to` empty.
        String::new()
    } else {
        format!("0x{}", hex_lower(&tx.to))
    };
    let data_length = tx.data.len() as u32;
    let msg = EthereumSignTxEip1559 {
        address_n: path.to_vec(),
        nonce: tx.nonce,
        max_gas_fee: tx.max_fee,
        max_priority_fee: tx.max_priority_fee,
        gas_limit: tx.gas_limit,
        to: Some(to_str),
        value: tx.value,
        data_initial_chunk: Some(tx.data),
        data_length,
        chain_id: tx.chain_id,
        access_list: Vec::new(),
        ..Default::default()
    };
    let (rt, rp) = conn
        .transceive_on(session_id, ETH_SIGN_TX_EIP1559, &msg.encode_to_vec())
        .await?;
    if rt != ETH_TX_REQUEST {
        return Err(TrezorError::thp(format!(
            "expected EthereumTxRequest ({ETH_TX_REQUEST}), got message type {rt}"
        )));
    }
    let req = EthereumTxRequest::decode(rp.as_slice())
        .map_err(|e| TrezorError::thp(format!("EthereumTxRequest decode: {e}")))?;
    // Single-chunk tx: the device must answer with the signature, not a
    // request for a further data chunk.
    let (Some(r), Some(s)) = (req.signature_r, req.signature_s) else {
        return Err(TrezorError::thp(
            "EthereumTxRequest carried no signature (device asked for more data?)",
        ));
    };
    let raw_v = req.signature_v.unwrap_or(0);
    // Trezor reports the recovery id; some firmware uses the legacy
    // 27/28 offset. Normalise to the 0/1 parity bit a type-2 signed
    // envelope wants (chain id is already in the payload).
    let v = if raw_v >= 27 {
        (raw_v - 27) as u8
    } else {
        raw_v as u8
    };
    Ok(Secp256k1Signature { v, r, s })
}

/// The fields we lift out of an EIP-1559 unsigned envelope. The wei /
/// gas fields stay as big-endian byte strings (minimal, no leading
/// zeros) because that is exactly what the Trezor protobuf wants.
struct Eip1559Tx {
    chain_id: u64,
    nonce: Vec<u8>,
    max_priority_fee: Vec<u8>,
    max_fee: Vec<u8>,
    gas_limit: Vec<u8>,
    to: Vec<u8>,
    value: Vec<u8>,
    data: Vec<u8>,
}

/// Decode `0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee,
/// gasLimit, to, value, data, accessList])`. Field order matches the
/// host `EthereumTxEncoder.payload`. The trailing access list is
/// ignored (Maknoon never sets one).
fn decode_eip1559_envelope(envelope: &[u8]) -> Result<Eip1559Tx, TrezorError> {
    if envelope.first() != Some(&0x02) {
        return Err(TrezorError::thp("not an EIP-1559 (0x02-typed) envelope"));
    }
    let items = rlp_decode_list(&envelope[1..])?;
    if items.len() < 8 {
        return Err(TrezorError::thp(format!(
            "EIP-1559 payload has {} items, expected at least 8",
            items.len()
        )));
    }
    Ok(Eip1559Tx {
        chain_id: be_to_u64(&items[0]),
        nonce: items[1].clone(),
        max_priority_fee: items[2].clone(),
        max_fee: items[3].clone(),
        gas_limit: items[4].clone(),
        to: items[5].clone(),
        value: items[6].clone(),
        data: items[7].clone(),
    })
}

/// Split a single RLP list into its top-level items' payloads. Only the
/// shapes the EIP-1559 envelope uses are exercised (byte strings + a
/// trailing list); each item is returned as its header-stripped bytes.
fn rlp_decode_list(buf: &[u8]) -> Result<Vec<Vec<u8>>, TrezorError> {
    let mut pos = 0usize;
    let (is_list, payload) = rlp_read(buf, &mut pos)?;
    if !is_list {
        return Err(TrezorError::thp(
            "EIP-1559 envelope body is not an RLP list",
        ));
    }
    let mut items = Vec::new();
    let mut ipos = 0usize;
    while ipos < payload.len() {
        let (_inner_is_list, item) = rlp_read(&payload, &mut ipos)?;
        items.push(item);
    }
    Ok(items)
}

/// Read one RLP item starting at `*pos`, advancing `*pos` past it.
/// Returns whether the item is a list and its header-stripped payload.
fn rlp_read(buf: &[u8], pos: &mut usize) -> Result<(bool, Vec<u8>), TrezorError> {
    let b = *buf
        .get(*pos)
        .ok_or_else(|| TrezorError::thp("RLP truncated"))?;
    *pos += 1;
    let (is_list, len) = match b {
        // Single byte below 0x80 is its own payload, no length header.
        0x00..=0x7f => return Ok((false, vec![b])),
        0x80..=0xb7 => (false, (b - 0x80) as usize),
        0xb8..=0xbf => (false, rlp_read_len(buf, pos, (b - 0xb7) as usize)?),
        0xc0..=0xf7 => (true, (b - 0xc0) as usize),
        _ => (true, rlp_read_len(buf, pos, (b - 0xf7) as usize)?),
    };
    let end = pos
        .checked_add(len)
        .ok_or_else(|| TrezorError::thp("RLP length overflow"))?;
    if end > buf.len() {
        return Err(TrezorError::thp("RLP item length exceeds buffer"));
    }
    let payload = buf[*pos..end].to_vec();
    *pos = end;
    Ok((is_list, payload))
}

/// Read an `n`-byte big-endian length prefix, advancing `*pos`.
fn rlp_read_len(buf: &[u8], pos: &mut usize, n: usize) -> Result<usize, TrezorError> {
    let end = pos
        .checked_add(n)
        .ok_or_else(|| TrezorError::thp("RLP length-prefix overflow"))?;
    if end > buf.len() {
        return Err(TrezorError::thp("RLP length-prefix exceeds buffer"));
    }
    let mut len = 0usize;
    for &x in &buf[*pos..end] {
        len = (len << 8) | x as usize;
    }
    *pos = end;
    Ok(len)
}

fn be_to_u64(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    v
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny independent RLP encoder, mirroring the host
    // `EthereumRLP`, so the decoder is checked against a separate
    // implementation rather than itself.
    fn rlp_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        let mut out = rlp_str_prefix(data.len());
        out.extend_from_slice(data);
        out
    }

    fn rlp_str_prefix(len: usize) -> Vec<u8> {
        if len < 56 {
            vec![0x80 + len as u8]
        } else {
            let lb = minimal_be(len);
            let mut out = vec![0xb7 + lb.len() as u8];
            out.extend_from_slice(&lb);
            out
        }
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut inner = Vec::new();
        for it in items {
            inner.extend_from_slice(it);
        }
        let mut out = if inner.len() < 56 {
            vec![0xc0 + inner.len() as u8]
        } else {
            let lb = minimal_be(inner.len());
            let mut p = vec![0xf7 + lb.len() as u8];
            p.extend_from_slice(&lb);
            p
        };
        out.extend_from_slice(&inner);
        out
    }

    fn minimal_be(mut n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        bytes
    }

    #[test]
    fn decodes_native_eip1559_envelope() {
        // chainId 11155111 (Sepolia), nonce 5, maxPriorityFee 1 gwei,
        // maxFee 30 gwei, gasLimit 21000, a 20-byte recipient, value
        // 1 wei, empty data, empty access list.
        let chain_id: u64 = 11_155_111;
        let to = [0x11u8; 20];
        let nonce = vec![0x05];
        let max_priority = vec![0x3b, 0x9a, 0xca, 0x00]; // 1e9
        let max_fee = vec![0x06, 0xfc, 0x23, 0xac, 0x00]; // 30e9
        let gas_limit = vec![0x52, 0x08]; // 21000
        let value = vec![0x01];

        let payload = rlp_list(&[
            rlp_bytes(&minimal_be(chain_id as usize)),
            rlp_bytes(&nonce),
            rlp_bytes(&max_priority),
            rlp_bytes(&max_fee),
            rlp_bytes(&gas_limit),
            rlp_bytes(&to),
            rlp_bytes(&value),
            rlp_bytes(&[]), // data
            rlp_list(&[]),  // accessList
        ]);
        let mut envelope = vec![0x02];
        envelope.extend_from_slice(&payload);

        let tx = decode_eip1559_envelope(&envelope).expect("decode");
        assert_eq!(tx.chain_id, chain_id);
        assert_eq!(tx.nonce, nonce);
        assert_eq!(tx.max_priority_fee, max_priority);
        assert_eq!(tx.max_fee, max_fee);
        assert_eq!(tx.gas_limit, gas_limit);
        assert_eq!(tx.to, to.to_vec());
        assert_eq!(tx.value, value);
        assert!(tx.data.is_empty());
    }

    #[test]
    fn decodes_erc20_envelope_with_calldata() {
        // 68-byte transfer(address,uint256) calldata exercises the
        // 0xb8 (one length byte) string header path.
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0u8; 64]);
        assert_eq!(data.len(), 68);

        let payload = rlp_list(&[
            rlp_bytes(&minimal_be(1)), // chainId 1
            rlp_bytes(&[]),            // nonce 0
            rlp_bytes(&[0x01]),        // maxPriorityFee
            rlp_bytes(&[0x02]),        // maxFee
            rlp_bytes(&[0x52, 0x08]),  // gasLimit
            rlp_bytes(&[0x22; 20]),    // token contract
            rlp_bytes(&[]),            // value 0
            rlp_bytes(&data),          // calldata
            rlp_list(&[]),             // accessList
        ]);
        let mut envelope = vec![0x02];
        envelope.extend_from_slice(&payload);

        let tx = decode_eip1559_envelope(&envelope).expect("decode");
        assert_eq!(tx.chain_id, 1);
        assert!(tx.nonce.is_empty());
        assert_eq!(tx.to, vec![0x22; 20]);
        assert!(tx.value.is_empty());
        assert_eq!(tx.data, data);
    }

    #[test]
    fn rejects_non_typed_envelope() {
        assert!(decode_eip1559_envelope(&[0x01, 0x02, 0x03]).is_err());
        assert!(decode_eip1559_envelope(&[]).is_err());
    }
}
