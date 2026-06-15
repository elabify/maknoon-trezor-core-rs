//! Per-chain application-message helpers, run over a paired THP
//! session (see `thp::connection`). Each chain mirrors the shapes the
//! Swift `HardwareWallet` protocol expects, matching the ledger
//! crates. Ethereum lands first (identity attestor + EIP-191 signing);
//! Bitcoin / Solana / Tron follow with the per-chain work.

pub(crate) mod bitcoin;
pub(crate) mod ethereum;
pub(crate) mod solana;
#[cfg(feature = "tron")]
pub(crate) mod tron;
