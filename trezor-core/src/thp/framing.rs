//! THP L2 transport framing: control bytes, CRC-32-IEEE, and the
//! segmentation / reassembly of a *transport payload* across an
//! initiation packet plus continuation packets.
//!
//! All constants are taken verbatim from the THP specification
//! (trezor-firmware internal docs). This layer is
//! transport-agnostic above the byte level: the host's foreign
//! `TrezorTransport` ships fixed-size reports (244 bytes on BLE, 64
//! on USB), and these routines pack / unpack them. No crypto here.

// The segment / reassemble API is exercised by the unit tests below
// and consumed by the channel + handshake layers as they land
// (task #2); allow dead_code until those callers exist in the
// non-test build.
#![allow(dead_code)]

use crate::error::TrezorError;

/// BLE report size (bytes). THP spec, "BLE packet size".
pub(crate) const BLE_PACKET_SIZE: usize = 244;
/// USB report size (bytes). THP spec, "USB packet size".
pub(crate) const USB_PACKET_SIZE: usize = 64;

/// Initiation-packet header: control(1) + cid(2) + length(2).
const INIT_HEADER: usize = 5;
/// Continuation-packet header: control(1) + cid(2).
const CONT_HEADER: usize = 3;
/// CRC-32 trailer length, appended to the transport payload.
const CRC_LEN: usize = 4;

/// Continuation-packet control byte. The high bit marks a
/// continuation; the low 7 bits are reserved (sent as zero).
const CONTINUATION_CONTROL: u8 = 0x80;
/// High bit: set => continuation packet, clear => initiation packet.
const CONTINUATION_MASK: u8 = 0x80;

// Recognized control-byte values for initiation packets (mask/value
// pairs from the spec's "Transport packet structure" table). Exposed
// for the channel + handshake layers; `framing` itself treats the
// control byte opaquely except for the continuation bit.
#[allow(dead_code)]
pub(crate) mod control {
    pub(crate) const CHANNEL_ALLOCATION_REQUEST: u8 = 0x40;
    pub(crate) const CHANNEL_ALLOCATION_RESPONSE: u8 = 0x41;
    pub(crate) const TRANSPORT_ERROR: u8 = 0x42;
    pub(crate) const PING: u8 = 0x43;
    pub(crate) const PONG: u8 = 0x44;
    /// `ack` base value `0010X000`; the X bit (0x08) carries the ABP
    /// sequence number.
    pub(crate) const ACK: u8 = 0x20;
    pub(crate) const ACK_SEQ_BIT: u8 = 0x08;
    pub(crate) const HANDSHAKE_INIT_REQUEST: u8 = 0x00;
    pub(crate) const HANDSHAKE_INIT_RESPONSE: u8 = 0x01;
    pub(crate) const HANDSHAKE_COMPLETION_REQUEST: u8 = 0x02;
    pub(crate) const HANDSHAKE_COMPLETION_RESPONSE: u8 = 0x03;
    pub(crate) const ENCRYPTED_TRANSPORT: u8 = 0x04;

    // Synchronization bits carried in data / ack control bytes
    // (firmware core/src/trezor/wire/thp/control_byte.py).
    /// ABP sequence bit of a data message.
    pub(crate) const SEQ_BIT: u8 = 0x10;
    /// ACK bit: in an `ack` control byte it carries the acked seq.
    pub(crate) const ACK_BIT: u8 = 0x08;
    /// Mask for matching an `ack` control byte (ignores the ack bit).
    pub(crate) const ACK_MASK: u8 = 0xF7;

    /// Apply the ABP sequence bit to a data control byte.
    pub(crate) fn with_seq(base: u8, seq: u8) -> u8 {
        if seq != 0 {
            base | SEQ_BIT
        } else {
            base & !SEQ_BIT
        }
    }
    /// Read the ABP sequence bit from a data control byte.
    pub(crate) fn seq_of(ctrl: u8) -> u8 {
        (ctrl & SEQ_BIT) >> 4
    }
    /// True if `ctrl` is an ACK control byte.
    pub(crate) fn is_ack(ctrl: u8) -> bool {
        ctrl & ACK_MASK == ACK
    }
    /// The acked sequence bit carried in an ACK control byte.
    pub(crate) fn ack_seq_of(ctrl: u8) -> u8 {
        (ctrl & ACK_BIT) >> 3
    }
    /// Build an ACK control byte acknowledging `seq`.
    pub(crate) fn ack_for(seq: u8) -> u8 {
        if seq != 0 {
            ACK | ACK_BIT
        } else {
            ACK
        }
    }
}

/// Broadcast channel id, used for channel allocation. THP spec,
/// "Channel identifier".
#[allow(dead_code)]
pub(crate) const BROADCAST_CID: u16 = 0xFFFF;

/// CRC-32-IEEE (polynomial 0x04C11DB7, reversed 0xEDB88320), the
/// algorithm the THP error-detection layer specifies. Bit-reflected
/// input/output, init/xor 0xFFFFFFFF — the standard "CRC-32" whose
/// check value over b"123456789" is 0xCBF43926.
pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Segment a transport payload into wire packets of `packet_size`.
///
/// `init_control_byte` is the control byte for the initiation packet
/// (e.g. `control::ENCRYPTED_TRANSPORT`, with any ABP sequence bit
/// already set by the caller). The CRC is computed over the
/// initiation header + the transport payload, then appended, exactly
/// as the spec's "Error detection layer" prescribes. Every returned
/// packet is exactly `packet_size` bytes; the final packet is null-
/// padded.
pub(crate) fn segment(
    packet_size: usize,
    cid: u16,
    init_control_byte: u8,
    transport_payload: &[u8],
) -> Result<Vec<Vec<u8>>, TrezorError> {
    if packet_size <= INIT_HEADER {
        return Err(TrezorError::thp("packet size too small for a THP header"));
    }
    let length = transport_payload.len() + CRC_LEN;
    let length_u16: u16 = u16::try_from(length)
        .map_err(|_| TrezorError::thp("transport payload exceeds the 16-bit length field"))?;

    // CRC over: control_byte || cid (BE) || length (BE) || payload.
    let mut crc_input = Vec::with_capacity(INIT_HEADER + transport_payload.len());
    crc_input.push(init_control_byte);
    crc_input.extend_from_slice(&cid.to_be_bytes());
    crc_input.extend_from_slice(&length_u16.to_be_bytes());
    crc_input.extend_from_slice(transport_payload);
    let crc = crc32_ieee(&crc_input);

    // payload_with_crc = transport_payload || CRC (BE).
    let mut payload_with_crc = Vec::with_capacity(length);
    payload_with_crc.extend_from_slice(transport_payload);
    payload_with_crc.extend_from_slice(&crc.to_be_bytes());

    let mut packets = Vec::new();
    let mut cursor = 0usize;

    // Initiation packet.
    let first_capacity = packet_size - INIT_HEADER;
    let take = first_capacity.min(payload_with_crc.len());
    let mut first = Vec::with_capacity(packet_size);
    first.push(init_control_byte);
    first.extend_from_slice(&cid.to_be_bytes());
    first.extend_from_slice(&length_u16.to_be_bytes());
    first.extend_from_slice(&payload_with_crc[cursor..cursor + take]);
    first.resize(packet_size, 0);
    packets.push(first);
    cursor += take;

    // Continuation packets.
    let cont_capacity = packet_size - CONT_HEADER;
    while cursor < payload_with_crc.len() {
        let take = cont_capacity.min(payload_with_crc.len() - cursor);
        let mut cont = Vec::with_capacity(packet_size);
        cont.push(CONTINUATION_CONTROL);
        cont.extend_from_slice(&cid.to_be_bytes());
        cont.extend_from_slice(&payload_with_crc[cursor..cursor + take]);
        cont.resize(packet_size, 0);
        packets.push(cont);
        cursor += take;
    }

    Ok(packets)
}

/// Reassembles a transport payload from incoming wire packets,
/// validating the CRC. Drives the spec's "Segmenting layer": a new
/// initiation packet resets any in-progress reassembly on the
/// channel; unexpected continuation packets are dropped.
#[derive(Default)]
pub(crate) struct Reassembler {
    active: bool,
    control_byte: u8,
    cid: u16,
    expected_len: usize,
    buf: Vec<u8>,
}

impl Reassembler {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed one wire packet. Returns `Ok(Some(transport_payload))`
    /// once a full, CRC-valid payload has been reassembled,
    /// `Ok(None)` while more packets are needed (or the packet was
    /// dropped), and `Err` on a malformed packet or CRC mismatch.
    pub(crate) fn push_packet(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, TrezorError> {
        if packet.is_empty() {
            return Err(TrezorError::thp("empty THP packet"));
        }
        let control_byte = packet[0];
        let is_continuation = control_byte & CONTINUATION_MASK == CONTINUATION_MASK;

        if is_continuation {
            if !self.active {
                // No payload in progress on this channel: drop it.
                return Ok(None);
            }
            if packet.len() <= CONT_HEADER {
                return Err(TrezorError::thp(
                    "continuation packet shorter than its header",
                ));
            }
            let remaining = self.expected_len - self.buf.len();
            let avail = packet.len() - CONT_HEADER;
            let take = remaining.min(avail);
            self.buf
                .extend_from_slice(&packet[CONT_HEADER..CONT_HEADER + take]);
        } else {
            // Initiation packet: (re)start reassembly on this channel.
            if packet.len() < INIT_HEADER {
                return Err(TrezorError::thp(
                    "initiation packet shorter than its header",
                ));
            }
            let cid = u16::from_be_bytes([packet[1], packet[2]]);
            let length = u16::from_be_bytes([packet[3], packet[4]]) as usize;
            if length < CRC_LEN {
                return Err(TrezorError::thp(
                    "THP length field smaller than the CRC trailer",
                ));
            }
            let avail = packet.len() - INIT_HEADER;
            let take = length.min(avail);
            self.active = true;
            self.control_byte = control_byte;
            self.cid = cid;
            self.expected_len = length;
            self.buf.clear();
            self.buf
                .extend_from_slice(&packet[INIT_HEADER..INIT_HEADER + take]);
        }

        if self.buf.len() >= self.expected_len {
            let payload_with_crc = std::mem::take(&mut self.buf);
            self.active = false;
            return self.finish(&payload_with_crc).map(Some);
        }
        Ok(None)
    }

    fn finish(&self, payload_with_crc: &[u8]) -> Result<Vec<u8>, TrezorError> {
        let split = self.expected_len - CRC_LEN;
        let transport_payload = &payload_with_crc[..split];
        let crc_received = u32::from_be_bytes([
            payload_with_crc[split],
            payload_with_crc[split + 1],
            payload_with_crc[split + 2],
            payload_with_crc[split + 3],
        ]);

        let mut crc_input = Vec::with_capacity(INIT_HEADER + transport_payload.len());
        crc_input.push(self.control_byte);
        crc_input.extend_from_slice(&self.cid.to_be_bytes());
        crc_input.extend_from_slice(&(self.expected_len as u16).to_be_bytes());
        crc_input.extend_from_slice(transport_payload);

        if crc32_ieee(&crc_input) != crc_received {
            return Err(TrezorError::thp("THP transport payload CRC mismatch"));
        }
        Ok(transport_payload.to_vec())
    }
}

/// Convenience: segment, then feed every packet back through a fresh
/// reassembler. Used by tests; also handy as a sanity self-check.
#[cfg(test)]
fn round_trip(packet_size: usize, cid: u16, control: u8, payload: &[u8]) -> Vec<u8> {
    let packets = segment(packet_size, cid, control, payload).expect("segment");
    for p in &packets {
        assert_eq!(p.len(), packet_size, "every packet is exactly packet_size");
    }
    let mut r = Reassembler::new();
    let mut out = None;
    for p in &packets {
        if let Some(done) = r.push_packet(p).expect("push") {
            out = Some(done);
        }
    }
    out.expect("reassembly completed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_standard_check_value() {
        // The canonical CRC-32/IEEE check value.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn round_trip_single_packet() {
        let payload = b"hello trezor".to_vec();
        let out = round_trip(
            BLE_PACKET_SIZE,
            0x1234,
            control::ENCRYPTED_TRANSPORT,
            &payload,
        );
        assert_eq!(out, payload);
    }

    #[test]
    fn round_trip_empty_payload() {
        let out = round_trip(
            BLE_PACKET_SIZE,
            0xABCD,
            control::HANDSHAKE_INIT_REQUEST,
            &[],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn round_trip_exactly_fills_first_packet() {
        // First packet holds packet_size - INIT_HEADER bytes of
        // payload_with_crc; size the payload so it lands exactly on
        // that boundary (no continuation, no padding slack).
        let payload = vec![0xA5u8; BLE_PACKET_SIZE - INIT_HEADER - CRC_LEN];
        let out = round_trip(BLE_PACKET_SIZE, 7, control::ENCRYPTED_TRANSPORT, &payload);
        assert_eq!(out, payload);
    }

    #[test]
    fn round_trip_multi_packet_ble_and_usb() {
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 256) as u8).collect();
        assert_eq!(
            round_trip(BLE_PACKET_SIZE, 1, control::ENCRYPTED_TRANSPORT, &payload),
            payload
        );
        assert_eq!(
            round_trip(USB_PACKET_SIZE, 1, control::ENCRYPTED_TRANSPORT, &payload),
            payload
        );
    }

    #[test]
    fn continuation_before_initiation_is_dropped() {
        let mut r = Reassembler::new();
        let bogus_cont = {
            let mut p = vec![CONTINUATION_CONTROL, 0x00, 0x01];
            p.resize(BLE_PACKET_SIZE, 0);
            p
        };
        assert!(r.push_packet(&bogus_cont).expect("drop").is_none());
    }

    #[test]
    fn new_initiation_resets_in_progress_reassembly() {
        let first = segment(
            BLE_PACKET_SIZE,
            9,
            control::ENCRYPTED_TRANSPORT,
            &vec![1u8; 5000],
        )
        .expect("segment big");
        let second_payload = b"second".to_vec();
        let second = segment(
            BLE_PACKET_SIZE,
            9,
            control::ENCRYPTED_TRANSPORT,
            &second_payload,
        )
        .expect("segment small");

        let mut r = Reassembler::new();
        // Feed only the first (incomplete) initiation packet of the
        // big message, then start the small message: the big one is
        // abandoned and the small one reassembles cleanly.
        assert!(r.push_packet(&first[0]).expect("partial").is_none());
        let out = r.push_packet(&second[0]).expect("restart");
        assert_eq!(out, Some(second_payload));
    }

    #[test]
    fn crc_corruption_is_rejected() {
        let mut packets = segment(
            BLE_PACKET_SIZE,
            2,
            control::ENCRYPTED_TRANSPORT,
            b"tamper me",
        )
        .expect("seg");
        // Flip a payload byte after segmentation so the CRC no longer
        // matches.
        packets[0][6] ^= 0xFF;
        let mut r = Reassembler::new();
        assert!(r.push_packet(&packets[0]).is_err());
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let too_big = vec![0u8; (u16::MAX as usize) - CRC_LEN + 1];
        assert!(segment(BLE_PACKET_SIZE, 1, control::ENCRYPTED_TRANSPORT, &too_big).is_err());
    }
}
