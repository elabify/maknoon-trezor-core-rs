//! THP connection driver: ties framing + the Alternating Bit Protocol
//! (ABP) + channel allocation + the Noise handshake together over the
//! async `TrezorTransport`, exposing whole-message send/receive and a
//! read-only handshake probe.
//!
//! Control-byte sync bits follow the firmware
//! (`core/src/trezor/wire/thp/control_byte.py`): seq bit `0x10`, ack
//! bit `0x08`. Per ABP, after sending a data message the host must
//! receive its ACK before sending the next one.
//!
//! What is validated in-process (see tests): the full
//! allocation → handshake exchange against a spec-faithful mock device
//! (framing + ABP + the TH1/TH2 responder), with both sides agreeing
//! on the session keys. What CANNOT be covered without a real device,
//! and is left to the on-device spike: ABP retransmission/timeout on a
//! lossy link, real GATT MTU, and on-device pairing.

// `transceive`/app-message helpers land with the per-chain work; the
// probe path (allocate + handshake) is live and exported via
// TrezorClient::thp_probe.
#![allow(dead_code)]

use std::sync::Arc;

use prost::Message as _;

use crate::error::TrezorError;
use crate::proto::hw::trezor::messages::common::{ButtonAck, Failure};
use crate::proto::hw::trezor::messages::thp::ThpCreateNewSession;
use crate::thp::channel::{self, ChannelAllocation};
use crate::thp::framing::{self, control, Reassembler};
use crate::thp::noise::{HostHandshake, SessionKeys};
use crate::thp::session::{self, Session};
use crate::transport::TrezorTransport;

/// Application message types used by the connection driver itself.
const MSG_SUCCESS: u16 = 2;
const MSG_FAILURE: u16 = 3;
const MSG_BUTTON_REQUEST: u16 = 26;
const MSG_BUTTON_ACK: u16 = 27;
const MSG_CREATE_NEW_SESSION: u16 = 1000;

/// Session id 0 is the channel's seedless session (GetFeatures,
/// pairing, ThpCreateNewSession). Seed-deriving ops run on a session
/// created via `create_seeded_session`.
const MANAGEMENT_SESSION_ID: u8 = 0;
pub(crate) const SEEDED_SESSION_ID: u8 = 1;

/// The high bit of a control byte marks a continuation packet; an
/// initiation packet (which carries the control byte we care about)
/// has it clear.
const CONTINUATION_BIT: u8 = 0x80;

/// Decode a THP `transport_error` payload (a single error-code byte)
/// into an actionable error. Codes per the spec's "Allocation layer".
fn decode_transport_error(payload: &[u8]) -> TrezorError {
    let code = payload.first().copied().unwrap_or(0);
    if code == 1 {
        return TrezorError::TransportBusy; // host backs off + retries
    }
    let detail = match code {
        2 => "the channel is unallocated — the device released it; reconnect to allocate a new one",
        3 => "decryption failed (bad authentication tag); the channel must be re-established",
        5 => "the device is locked — unlock your Trezor (enter your PIN on the device) and retry",
        _ => "unrecognized THP transport error",
    };
    TrezorError::thp(format!("THP transport error {code}: {detail}"))
}

pub(crate) struct Connection {
    transport: Arc<dyn TrezorTransport>,
    packet_size: usize,
    cid: u16,
    send_seq: u8,
    recv_seq: u8,
    session: Option<Session>,
    active_session_id: u8,
    /// The `(passphrase, on_device)` the current seeded session was
    /// created with, if any. Lets a pinned connection tell whether its
    /// seeded session matches the wallet a caller wants, so a hidden
    /// (passphrase) wallet never silently reuses the standard session.
    seeded_with: Option<(Option<String>, bool)>,
    /// A data frame the device sent BEFORE ACKing our request (some
    /// firmware does this on a validation `Failure`, e.g. a forbidden
    /// derivation path). `send_data` stashes it here so the next
    /// `recv_data` returns it instead of reading anew, keeping ABP in
    /// sync rather than erroring + desyncing the channel.
    pending_data: Option<(u8, Vec<u8>)>,
}

impl Connection {
    pub(crate) fn new(transport: Arc<dyn TrezorTransport>, packet_size: usize) -> Self {
        Self {
            transport,
            packet_size,
            cid: framing::BROADCAST_CID,
            send_seq: 0,
            recv_seq: 0,
            session: None,
            active_session_id: MANAGEMENT_SESSION_ID,
            seeded_with: None,
            pending_data: None,
        }
    }

    /// The `(passphrase, on_device)` key the seeded session was created
    /// with, or `None` if no seeded session has been opened yet.
    pub(crate) fn seeded_key(&self) -> Option<(Option<String>, bool)> {
        self.seeded_with.clone()
    }

    /// Install the encrypted-transport session derived from a
    /// completed handshake. Must be called before any `transceive`.
    pub(crate) fn set_session(&mut self, session: Session) {
        self.session = Some(session);
    }

    // ---- raw framed message I/O ----

    async fn write_framed(&self, ctrl: u8, payload: &[u8]) -> Result<(), TrezorError> {
        for packet in framing::segment(self.packet_size, self.cid, ctrl, payload)? {
            self.transport.write_chunk(packet).await?;
        }
        Ok(())
    }

    /// Read packets until a full transport payload reassembles,
    /// returning its control byte (captured from the initiation
    /// packet) and the payload.
    async fn read_framed(&self) -> Result<(u8, Vec<u8>), TrezorError> {
        let mut reasm = Reassembler::new();
        let mut ctrl = 0u8;
        loop {
            let chunk = self.transport.read_chunk().await?;
            if chunk.is_empty() {
                continue;
            }
            if chunk[0] & CONTINUATION_BIT == 0 {
                ctrl = chunk[0];
            }
            if let Some(payload) = reasm.push_packet(&chunk)? {
                if ctrl == control::TRANSPORT_ERROR {
                    return Err(decode_transport_error(&payload));
                }
                return Ok((ctrl, payload));
            }
        }
    }

    // ---- Alternating Bit Protocol ----

    async fn send_ack(&self, acked_seq: u8) -> Result<(), TrezorError> {
        self.write_framed(control::ack_for(acked_seq), &[]).await
    }

    /// Send a data message and block until its ACK arrives (ABP: no
    /// further send is allowed until the previous one is ACKed).
    async fn send_data(&mut self, base_ctrl: u8, payload: &[u8]) -> Result<(), TrezorError> {
        let ctrl = control::with_seq(base_ctrl, self.send_seq);
        self.write_framed(ctrl, payload).await?;
        loop {
            let (rctrl, rpayload) = self.read_framed().await?;
            if control::is_ack(rctrl) {
                if control::ack_seq_of(rctrl) == self.send_seq {
                    self.send_seq ^= 1;
                    return Ok(());
                }
                continue; // stale/duplicate ACK
            }
            // The device sent a DATA message instead of ACKing our
            // request. Some firmware does this on a validation error
            // (e.g. a forbidden derivation path on an alternative-path
            // sweep): it skips the ABP ACK and replies immediately. The
            // reply implies our request was received, so treat it as an
            // implicit ACK, then ACK + stash the device's frame so the
            // next recv returns it (transceive decodes it, typically a
            // Failure). This keeps ABP in sync instead of erroring and
            // desyncing the channel for every later op.
            self.send_seq ^= 1;
            let seq = control::seq_of(rctrl);
            self.send_ack(seq).await?;
            if seq == self.recv_seq {
                self.recv_seq ^= 1;
                self.pending_data = Some((rctrl, rpayload));
            }
            return Ok(());
        }
    }

    /// Receive the next data message, ACK it, and skip ABP duplicates.
    async fn recv_data(&mut self) -> Result<(u8, Vec<u8>), TrezorError> {
        // A frame the device sent early (before ACKing our request) was
        // already ACKed + recorded by `send_data`; return it first.
        if let Some(frame) = self.pending_data.take() {
            return Ok(frame);
        }
        loop {
            let (ctrl, payload) = self.read_framed().await?;
            if control::is_ack(ctrl) {
                continue; // stray ACK; not a data message
            }
            let seq = control::seq_of(ctrl);
            self.send_ack(seq).await?;
            if seq == self.recv_seq {
                self.recv_seq ^= 1;
                return Ok((ctrl, payload));
            }
            // Duplicate of an already-processed message: re-ACKed above,
            // keep waiting for the fresh one.
        }
    }

    // ---- high-level flow ----

    /// Allocate a channel over the broadcast CID (no ABP), capturing
    /// the device properties and switching to the assigned CID.
    ///
    /// Per the spec's allocation layer the host ignores any response
    /// whose nonce doesn't match and keeps waiting; we also skip
    /// unrelated broadcast traffic (stale ACKs/pings or leftover
    /// frames from a just-closed channel on a rapid reconnect) rather
    /// than failing on the first non-allocation frame.
    pub(crate) async fn allocate(&mut self) -> Result<ChannelAllocation, TrezorError> {
        const MAX_ALLOC_READS: usize = 8;
        let nonce = channel::random_allocation_nonce();
        self.cid = framing::BROADCAST_CID;
        self.write_framed(
            control::CHANNEL_ALLOCATION_REQUEST,
            &channel::build_allocation_request(&nonce),
        )
        .await?;
        for _ in 0..MAX_ALLOC_READS {
            let (ctrl, payload) = self.read_framed().await?;
            if ctrl == control::CHANNEL_ALLOCATION_RESPONSE {
                if let Ok(allocation) = channel::parse_allocation_response(&nonce, &payload) {
                    self.cid = allocation.cid;
                    self.send_seq = 0;
                    self.recv_seq = 0;
                    self.pending_data = None;
                    return Ok(allocation);
                }
                // Nonce mismatch: not our response, keep waiting.
            }
            // Stale/unrelated frame on the broadcast channel: skip it.
        }
        Err(TrezorError::thp(
            "no matching channel allocation response received",
        ))
    }

    /// Run the Noise XX handshake on the allocated channel, returning
    /// the encrypted-session keys. `device_properties_raw` must be the
    /// exact bytes from the allocation response (mixed into the
    /// transcript hash).
    pub(crate) async fn handshake(
        &mut self,
        device_properties_raw: Vec<u8>,
        host_static_priv: [u8; 32],
        credential: Option<Vec<u8>>,
    ) -> Result<SessionKeys, TrezorError> {
        let mut hs = HostHandshake::new(device_properties_raw, 0, host_static_priv, credential);
        self.send_data(control::HANDSHAKE_INIT_REQUEST, &hs.init_request_payload())
            .await?;
        let (_c, init_resp) = self.recv_data().await?;
        let completion = hs.read_init_response(&init_resp)?;
        self.send_data(control::HANDSHAKE_COMPLETION_REQUEST, &completion)
            .await?;
        let (_c2, comp_resp) = self.recv_data().await?;
        hs.read_completion_response(&comp_resp)
    }

    /// Seal and send one application message over the session (ABP).
    async fn send_app(&mut self, message_type: u16, protobuf: &[u8]) -> Result<(), TrezorError> {
        let session_id = self.active_session_id;
        let ct = {
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| TrezorError::thp("no encrypted session established"))?;
            let payload = session::encode_app_message(session_id, message_type, protobuf);
            session.seal(&payload)
        };
        self.send_data(control::ENCRYPTED_TRANSPORT, &ct).await
    }

    /// Receive and open one application message, returning its type +
    /// protobuf body.
    async fn recv_app(&mut self) -> Result<(u16, Vec<u8>), TrezorError> {
        let (_ctrl, ct) = self.recv_data().await?;
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| TrezorError::thp("no encrypted session established"))?;
        let pt = session.open(&ct)?;
        let (_sid, message_type, body) = session::decode_app_message(&pt)?;
        Ok((message_type, body.to_vec()))
    }

    /// Send an application message on a specific session id, returning
    /// the device's reply. Management messages (GetFeatures, pairing)
    /// use session 0; seed-deriving ops use the seeded session.
    pub(crate) async fn transceive_on(
        &mut self,
        session_id: u8,
        message_type: u16,
        protobuf: &[u8],
    ) -> Result<(u16, Vec<u8>), TrezorError> {
        self.active_session_id = session_id;
        self.transceive(message_type, protobuf).await
    }

    /// Send an application message and return the device's reply,
    /// transparently ACKing `ButtonRequest`s (device confirmation
    /// screens) and surfacing `Failure`s as errors.
    pub(crate) async fn transceive(
        &mut self,
        message_type: u16,
        protobuf: &[u8],
    ) -> Result<(u16, Vec<u8>), TrezorError> {
        self.send_app(message_type, protobuf).await?;
        loop {
            let (rt, rp) = self.recv_app().await?;
            match rt {
                MSG_BUTTON_REQUEST => {
                    self.send_app(MSG_BUTTON_ACK, &ButtonAck::default().encode_to_vec())
                        .await?;
                }
                MSG_FAILURE => return Err(decode_failure(&rp)),
                _ => return Ok((rt, rp)),
            }
        }
    }

    /// Create a seeded session via `ThpCreateNewSession` and switch
    /// subsequent app messages onto it. Seed-deriving ops
    /// (get-address, sign, attestor pubkey) require this; session 0 is
    /// seedless and rejects them with `Failure_InvalidSession`.
    /// `passphrase`/`on_device` select a standard wallet (None/false)
    /// or a hidden passphrase wallet.
    pub(crate) async fn create_seeded_session(
        &mut self,
        passphrase: Option<String>,
        on_device: bool,
    ) -> Result<(), TrezorError> {
        // The new session id is the application-layer session_id byte we
        // frame ThpCreateNewSession with; the device allocates it.
        self.active_session_id = SEEDED_SESSION_ID;
        let key = (passphrase.clone(), on_device);
        let msg = ThpCreateNewSession {
            passphrase,
            on_device: Some(on_device),
            derive_cardano: Some(false),
        };
        let (rt, _rp) = self
            .transceive(MSG_CREATE_NEW_SESSION, &msg.encode_to_vec())
            .await?;
        if rt != MSG_SUCCESS {
            return Err(TrezorError::thp(format!(
                "expected Success after ThpCreateNewSession, got message type {rt}"
            )));
        }
        self.seeded_with = Some(key);
        Ok(())
    }
}

/// Decode a protobuf `Failure` into a `TrezorError`. User-cancel
/// (`ActionCancelled` = 4) maps to `UserCanceled`.
fn decode_failure(proto: &[u8]) -> TrezorError {
    match Failure::decode(proto) {
        Ok(f) => {
            let code = f.code.unwrap_or(0);
            let reason = f.message.unwrap_or_default();
            if code == 4 {
                TrezorError::UserCanceled
            } else {
                TrezorError::DeviceRejected { code, reason }
            }
        }
        Err(_) => TrezorError::thp("device returned an undecodable Failure"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::hw::trezor::messages::thp::ThpDeviceProperties;
    use crate::thp::framing::{segment, BLE_PACKET_SIZE};
    use crate::thp::noise::test_support::TrezorResponder;
    use crate::transport::TrezorTransportError;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Phase of the mock device's state machine.
    #[derive(PartialEq)]
    enum Phase {
        ExpectAlloc,
        ExpectInit,
        ExpectCompletion,
        Done,
    }

    const DEVICE_CID: u16 = 0x0003;

    /// In-memory Trezor that speaks framing + ABP + the TH1/TH2
    /// handshake, so the driver can be validated end-to-end without a
    /// real device. Lossless and ordered, so it covers the message
    /// structure and ACK exchange but not retransmission.
    struct MockDevice {
        inner: Mutex<MockInner>,
    }

    struct MockInner {
        reasm: Reassembler,
        last_init_ctrl: u8,
        outbox: VecDeque<Vec<u8>>,
        device_seq: u8,
        device_props_raw: Vec<u8>,
        responder: TrezorResponder,
        phase: Phase,
        agreed_keys: Option<([u8; 32], [u8; 32])>,
    }

    impl MockDevice {
        fn new(model: &str, trezor_static: [u8; 32]) -> Self {
            let props = ThpDeviceProperties {
                internal_model: model.to_string(),
                protocol_version_major: 2,
                protocol_version_minor: 0,
                pairing_methods: vec![2], // CodeEntry
                ..Default::default()
            };
            let device_props_raw = props.encode_to_vec();
            let responder = TrezorResponder::new(device_props_raw.clone(), trezor_static);
            Self {
                inner: Mutex::new(MockInner {
                    reasm: Reassembler::new(),
                    last_init_ctrl: 0,
                    outbox: VecDeque::new(),
                    device_seq: 0,
                    device_props_raw,
                    responder,
                    phase: Phase::ExpectAlloc,
                    agreed_keys: None,
                }),
            }
        }

        fn agreed_keys(&self) -> Option<([u8; 32], [u8; 32])> {
            self.inner.lock().unwrap().agreed_keys
        }
    }

    impl MockInner {
        fn enqueue(&mut self, cid: u16, ctrl: u8, payload: &[u8]) {
            for packet in segment(BLE_PACKET_SIZE, cid, ctrl, payload).unwrap() {
                self.outbox.push_back(packet);
            }
        }

        fn on_message(&mut self, ctrl: u8, payload: Vec<u8>) {
            if control::is_ack(ctrl) {
                return; // host ACKing one of our responses; nothing to do
            }
            match self.phase {
                Phase::ExpectAlloc => {
                    // payload = 8-byte nonce; echo it + cid + device props.
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&payload[..8]);
                    resp.extend_from_slice(&DEVICE_CID.to_be_bytes());
                    resp.extend_from_slice(&self.device_props_raw);
                    self.enqueue(
                        framing::BROADCAST_CID,
                        control::CHANNEL_ALLOCATION_RESPONSE,
                        &resp,
                    );
                    self.phase = Phase::ExpectInit;
                }
                Phase::ExpectInit => {
                    let host_seq = control::seq_of(ctrl);
                    self.enqueue(DEVICE_CID, control::ack_for(host_seq), &[]);
                    let resp = self.responder.handle_init_request(&payload);
                    let rctrl =
                        control::with_seq(control::HANDSHAKE_INIT_RESPONSE, self.device_seq);
                    self.enqueue(DEVICE_CID, rctrl, &resp);
                    self.device_seq ^= 1;
                    self.phase = Phase::ExpectCompletion;
                }
                Phase::ExpectCompletion => {
                    let host_seq = control::seq_of(ctrl);
                    self.enqueue(DEVICE_CID, control::ack_for(host_seq), &[]);
                    let result = self.responder.handle_completion_request(&payload);
                    self.agreed_keys = Some((result.key_request, result.key_response));
                    let rctrl =
                        control::with_seq(control::HANDSHAKE_COMPLETION_RESPONSE, self.device_seq);
                    self.enqueue(DEVICE_CID, rctrl, &result.response);
                    self.device_seq ^= 1;
                    self.phase = Phase::Done;
                }
                Phase::Done => {}
            }
        }
    }

    #[async_trait::async_trait]
    impl TrezorTransport for MockDevice {
        async fn write_chunk(&self, data: Vec<u8>) -> Result<(), TrezorTransportError> {
            let mut inner = self.inner.lock().unwrap();
            if data.is_empty() {
                return Ok(());
            }
            let ctrl = if data[0] & CONTINUATION_BIT == 0 {
                inner.last_init_ctrl = data[0];
                data[0]
            } else {
                inner.last_init_ctrl
            };
            if let Some(payload) =
                inner
                    .reasm
                    .push_packet(&data)
                    .map_err(|e| TrezorTransportError::Io {
                        reason: e.to_string(),
                    })?
            {
                inner.on_message(ctrl, payload);
            }
            Ok(())
        }

        async fn read_chunk(&self) -> Result<Vec<u8>, TrezorTransportError> {
            let mut inner = self.inner.lock().unwrap();
            inner.outbox.pop_front().ok_or(TrezorTransportError::Io {
                reason: "mock device has no queued data".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn driver_completes_allocation_and_handshake_against_mock_device() {
        let host_static = [0x11u8; 32];
        let device = Arc::new(MockDevice::new("T3W1", [0x22u8; 32]));
        let mut conn = Connection::new(device.clone(), BLE_PACKET_SIZE);

        let allocation = conn.allocate().await.expect("channel allocation");
        assert_eq!(allocation.cid, DEVICE_CID);
        assert_eq!(allocation.device_properties.internal_model, "T3W1");
        assert_eq!(allocation.device_properties.pairing_methods, vec![2]);

        let keys = conn
            .handshake(allocation.device_properties_raw.clone(), host_static, None)
            .await
            .expect("handshake over the driver");

        // Driver + framing + ABP delivered a handshake that agrees with
        // the device on the encrypted-session keys.
        let (dev_req, dev_resp) = device.agreed_keys().expect("device derived keys");
        assert_eq!(keys.key_request, dev_req);
        assert_eq!(keys.key_response, dev_resp);
        assert_ne!(keys.key_request, keys.key_response);
        assert_eq!(keys.nonce_request, 0);
        assert_eq!(keys.nonce_response, 1);
        // Unpaired state byte from the mock (real values confirmed on-device).
        assert_eq!(keys.trezor_state, vec![0x02]);
    }

    #[test]
    fn decode_transport_error_messages() {
        assert!(matches!(
            decode_transport_error(&[1]),
            TrezorError::TransportBusy
        ));
        assert!(format!("{}", decode_transport_error(&[5])).contains("locked"));
        assert!(format!("{}", decode_transport_error(&[2])).contains("unallocated"));
        assert!(format!("{}", decode_transport_error(&[3])).contains("decryption"));
    }

    /// A device that answers any request with a DEVICE_LOCKED transport
    /// error frame, to confirm the driver decodes + surfaces it.
    struct LockedDevice {
        out: Mutex<VecDeque<Vec<u8>>>,
    }

    impl LockedDevice {
        fn new() -> Self {
            let frame = segment(
                BLE_PACKET_SIZE,
                framing::BROADCAST_CID,
                control::TRANSPORT_ERROR,
                &[5],
            )
            .unwrap();
            Self {
                out: Mutex::new(frame.into()),
            }
        }
    }

    #[async_trait::async_trait]
    impl TrezorTransport for LockedDevice {
        async fn write_chunk(&self, _data: Vec<u8>) -> Result<(), TrezorTransportError> {
            Ok(())
        }
        async fn read_chunk(&self) -> Result<Vec<u8>, TrezorTransportError> {
            self.out
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(TrezorTransportError::Io {
                    reason: "empty".to_string(),
                })
        }
    }

    #[tokio::test]
    async fn locked_device_surfaces_decoded_error() {
        let mut conn = Connection::new(Arc::new(LockedDevice::new()), BLE_PACKET_SIZE);
        let err = conn.allocate().await.unwrap_err();
        assert!(format!("{err}").contains("locked"), "got: {err}");
    }
}
