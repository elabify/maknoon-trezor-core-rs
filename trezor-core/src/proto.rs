//! Generated trezor-common protobuf bindings.
//!
//! Produced at build time by `build.rs` (protox + prost-build) from
//! the vendored `.proto` files under `proto/` (pinned, see
//! `proto/VENDORED_FROM.txt`). The module tree mirrors the proto
//! package layout, e.g.:
//!
//!   - `proto::hw::trezor::messages` — the `MessageType` wire-number
//!     enum + THP channel-allocation device-properties types.
//!   - `proto::hw::trezor::messages::management` — Initialize,
//!     Features, GetPublicKey, ...
//!   - `proto::hw::trezor::messages::{thp,common,bitcoin,ethereum,
//!     solana,tron}` — per-domain messages.
//!
//! This is generated code; lint groups are relaxed for the included
//! tree only. Do not edit by hand; change the protos + rebuild.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]
#![allow(rustdoc::all)]
#![allow(missing_docs)]
// Most generated types aren't referenced yet; the channel, handshake
// and per-chain layers consume them as they land (task #2 / #4).
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/trezor_proto.rs"));

#[cfg(test)]
mod proto_smoke {
    //! Locks the codegen: the generated module paths exist, the
    //! `MessageType` wire numbers match the spec, and prost
    //! encode/decode round-trips a real message.
    use super::hw::trezor::messages::thp::ThpCreateNewSession;
    use super::hw::trezor::messages::MessageType;
    use prost::Message;

    #[test]
    fn message_type_wire_numbers_match_spec() {
        assert_eq!(MessageType::Initialize as i32, 0);
        assert_eq!(MessageType::Features as i32, 17);
        assert_eq!(MessageType::GetFeatures as i32, 55);
        assert_eq!(MessageType::GetPublicKey as i32, 11);
        assert_eq!(MessageType::EthereumGetAddress as i32, 56);
        assert_eq!(MessageType::SolanaGetAddress as i32, 902);
        assert_eq!(MessageType::TronGetAddress as i32, 2200);
    }

    #[test]
    fn protobuf_round_trips_via_prost() {
        let msg = ThpCreateNewSession {
            passphrase: Some("correct horse".to_string()),
            on_device: Some(true),
            ..Default::default()
        };
        let bytes = msg.encode_to_vec();
        let decoded = ThpCreateNewSession::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.passphrase.as_deref(), Some("correct horse"));
    }
}
