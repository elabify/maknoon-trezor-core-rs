// Skeleton conformance: until the THP spike (task #2) lands, the
// contract is simply that the client constructs over an injected
// transport and every public method reports `NotImplemented` rather
// than panicking or hanging. This locks the UniFFI surface and the
// foreign-transport seam so the Swift side can be wired up against a
// real (if stubbed) API. Replace with real handshake / signing
// vectors as the implementation lands.

use std::sync::Arc;

use trezor_core::{TrezorClient, TrezorError, TrezorTransport, TrezorTransportError};

/// A transport that never gets driven (the stubs return before any
/// I/O). Present only so the client can be constructed.
struct NullTransport;

#[async_trait::async_trait]
impl TrezorTransport for NullTransport {
    async fn write_chunk(&self, _data: Vec<u8>) -> Result<(), TrezorTransportError> {
        Ok(())
    }
    async fn read_chunk(&self) -> Result<Vec<u8>, TrezorTransportError> {
        Ok(Vec::new())
    }
}

fn client() -> Arc<TrezorClient> {
    TrezorClient::new(Arc::new(NullTransport))
}

fn assert_not_implemented<T: std::fmt::Debug>(result: Result<T, TrezorError>) {
    match result {
        Err(TrezorError::NotImplemented { .. }) => {}
        other => panic!("expected NotImplemented, got {other:?}"),
    }
}

#[tokio::test]
async fn identity_surface_is_declared_and_stubbed() {
    let c = client();
    assert_not_implemented(c.identify().await);
    assert_not_implemented(c.pair().await);
    assert_not_implemented(c.sign_message(b"maknoon".to_vec()).await);
}

// Ethereum, Bitcoin, Solana, and Tron (address + sign) all drive BLE
// now. The only no-transport stub left is Tron's get_tron_pubkey, which
// Trezor's Tron protocol cannot satisfy (no public-key message).

#[tokio::test]
async fn tron_pubkey_has_no_trezor_message() {
    let c = client();
    assert_not_implemented(c.get_tron_pubkey(0).await);
}
