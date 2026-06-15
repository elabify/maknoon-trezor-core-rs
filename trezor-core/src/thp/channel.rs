//! THP L2 allocation layer: the channel-allocation handshake over the
//! broadcast channel (CID 0xFFFF) that assigns this host a channel id
//! before the secure handshake begins.
//!
//! Per the spec's "Allocation layer", the request transport payload
//! is `nonce (8 bytes)`, and the response is `nonce (8) || cid (2,
//! BE) || device_properties (serialized ThpDeviceProperties)`. These
//! payloads are wrapped by the `framing` layer with the
//! `channel_allocation_request` / `_response` control bytes on
//! `framing::BROADCAST_CID`.

// Driven by the connection/client layer (task #2 / #4); exercised by
// the unit tests now.
#![allow(dead_code)]

use prost::Message;

use crate::error::TrezorError;
use crate::proto::hw::trezor::messages::thp::ThpDeviceProperties;

/// Length of the allocation nonce echoed by the device.
pub(crate) const ALLOCATION_NONCE_LEN: usize = 8;

/// A successfully allocated channel: its id plus the device
/// properties (both the parsed message and the raw bytes, which the
/// handshake mixes into its transcript hash).
#[derive(Debug)]
pub(crate) struct ChannelAllocation {
    pub(crate) cid: u16,
    pub(crate) device_properties_raw: Vec<u8>,
    pub(crate) device_properties: ThpDeviceProperties,
}

/// A fresh random allocation nonce.
pub(crate) fn random_allocation_nonce() -> [u8; ALLOCATION_NONCE_LEN] {
    let mut nonce = [0u8; ALLOCATION_NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("platform RNG");
    nonce
}

/// The `ChannelAllocationRequest` transport payload (just the nonce).
pub(crate) fn build_allocation_request(nonce: &[u8; ALLOCATION_NONCE_LEN]) -> Vec<u8> {
    nonce.to_vec()
}

/// Parse a `ChannelAllocationResponse` transport payload, verifying
/// the echoed nonce matches the one we sent.
pub(crate) fn parse_allocation_response(
    sent_nonce: &[u8; ALLOCATION_NONCE_LEN],
    payload: &[u8],
) -> Result<ChannelAllocation, TrezorError> {
    if payload.len() < ALLOCATION_NONCE_LEN + 2 {
        return Err(TrezorError::thp("channel allocation response too short"));
    }
    if &payload[..ALLOCATION_NONCE_LEN] != sent_nonce {
        // Per spec, a non-matching nonce means this response is not
        // for us; the caller keeps waiting.
        return Err(TrezorError::thp("channel allocation nonce mismatch"));
    }
    let cid = u16::from_be_bytes([
        payload[ALLOCATION_NONCE_LEN],
        payload[ALLOCATION_NONCE_LEN + 1],
    ]);
    let device_properties_raw = payload[ALLOCATION_NONCE_LEN + 2..].to_vec();
    let device_properties = ThpDeviceProperties::decode(device_properties_raw.as_slice())
        .map_err(|e| TrezorError::thp(format!("device properties decode failed: {e}")))?;
    Ok(ChannelAllocation {
        cid,
        device_properties_raw,
        device_properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_properties() -> ThpDeviceProperties {
        ThpDeviceProperties {
            internal_model: "T3W1".to_string(),
            protocol_version_major: 2,
            protocol_version_minor: 0,
            ..Default::default()
        }
    }

    fn build_response(nonce: &[u8; 8], cid: u16, props: &ThpDeviceProperties) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&cid.to_be_bytes());
        payload.extend_from_slice(&props.encode_to_vec());
        payload
    }

    #[test]
    fn request_payload_is_the_nonce() {
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(build_allocation_request(&nonce), nonce.to_vec());
    }

    #[test]
    fn parses_a_matching_response() {
        let nonce = random_allocation_nonce();
        let props = sample_properties();
        let payload = build_response(&nonce, 0x1234, &props);

        let allocation = parse_allocation_response(&nonce, &payload).unwrap();
        assert_eq!(allocation.cid, 0x1234);
        assert_eq!(allocation.device_properties.internal_model, "T3W1");
        assert_eq!(allocation.device_properties.protocol_version_major, 2);
        // The raw bytes are preserved verbatim for the handshake hash.
        assert_eq!(allocation.device_properties_raw, props.encode_to_vec());
    }

    #[test]
    fn rejects_nonce_mismatch() {
        let sent = [9u8; 8];
        let other = [8u8; 8];
        let payload = build_response(&other, 5, &sample_properties());
        assert!(parse_allocation_response(&sent, &payload).is_err());
    }

    #[test]
    fn rejects_truncated_response() {
        assert!(parse_allocation_response(&[0u8; 8], &[0u8; 5]).is_err());
    }
}
