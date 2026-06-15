# trezor-core-rs

> **Status: pre-1.0, skeleton (2026-06-13).** This is the SDK
> skeleton: the crate compiles, the full UniFFI surface and the
> foreign-transport seam are declared, and every signing method
> returns `NotImplemented`. The Trezor Host Protocol (THP v2) and the
> per-chain signing land next, gated on a handshake spike against a
> real device. See the roadmap below.

A Rust core + UniFFI bindings for talking to a **Trezor** hardware
wallet over Bluetooth from iOS and Android. It is the Trezor
counterpart to the `ledger-*-rs` crates, with one structural
difference: where Ledger needs one crate per chain (each Ledger app
speaks a different APDU dialect), Trezor speaks a single protocol for
everything, so this is **one unified crate** with chains behind cargo
features.

Single source of truth, two artifacts:

```
trezor-core-rs/  (this repo)
   ├── trezor-core   ←  Rust crate (THP v2 + all chains)
   ├── ios           ←  build-xcframework.sh → TrezorCore.xcframework
   └── android       ←  build-aar.sh → trezor-core.aar
```

## Design pillars

1. **Native owns the raw BLE bytes; Rust owns everything above the
   wire.** The host (Swift `TrezorBLE` / Kotlin) does only GATT
   write + notify of raw reports through the `TrezorTransport`
   foreign callback. The THP v2 state machine (framing, channel
   allocation, Noise XX handshake, ChaCha20Poly1305 session, pairing
   credential) lives in Rust, so the handshake crypto uses vetted
   Rust crates and is reused verbatim across iOS and Android.
2. **One protocol, all chains.** THP carries the trezor-common
   protobuf message set for Bitcoin, Ethereum, Solana and Tron. No
   per-chain transport forks.
3. **Reuse the official assets, own the security layer.** Vendor the
   official `trezor-common` `.proto` files (compiled with `prost`);
   implement THP v2 on the audited `snow` Noise crate. The
   third-party `trezor-connect-rs` is a reference only, not a
   dependency.
4. **Host-shape parity with Ledger.** Method names and return shapes
   (`Secp256k1Signature`, signed-PSBT base64, etc.) match the ledger
   crates so the Swift `HardwareWallet` conformer is thin and the
   identity-sandwich + PSBT host paths are reused unchanged.
5. **Async end-to-end.** UniFFI callback interfaces are async; the
   host transport is `async` / `suspend`; the Rust client is `async`
   throughout.

## Surface

`TrezorClient` (one object per device session) exposes, mapping 1:1
to the Swift `HardwareWallet` protocol:

- Identity: `identify`, `pair`, `sign_message`
- Bitcoin: `get_bitcoin_account_xpub`, `get_bitcoin_master_fingerprint`, `sign_psbt`
- Ethereum: `get_ethereum_address`, `sign_ethereum_tx`
- Solana: `get_solana_address`, `sign_solana_tx`
- Tron: `get_tron_address`, `get_tron_pubkey`, `sign_tron_tx`

## Build

```
make all            # fmt-check + clippy + test (the CI gate)
make ios            # TrezorCore.xcframework + Swift bindings
make android        # trezor-core.aar + Kotlin bindings
make setup-ios-targets / setup-android-targets   # one-time per machine
```

## Roadmap

- [x] **Skeleton** — crate compiles, UniFFI surface + transport seam
  declared, conformance test asserts every method stubs cleanly.
- [ ] **THP spike** — vendor `trezor-common` protos (prost), THP
  channel + Noise XX (`snow`) + ChaCha20Poly1305 session; prove an
  encrypted `GetFeatures` round-trip against a real device; verify
  GATT UUIDs, framing, keep-alive, and the `sign_message` digest
  convention for identity-sandwich attestation parity.
- [ ] **Identity** — `identify` / `pair` / `sign_message` with
  pairing-credential persistence.
- [ ] **Chains** — Ethereum → Bitcoin (full PSBT) → Solana → Tron.
- [ ] **Conformance** — captured fixtures replayed byte-for-byte
  through a mock transport, matching the ledger crates' harness.
