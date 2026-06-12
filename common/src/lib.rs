#![forbid(unsafe_code)]
//! Shared building blocks for the LON Oracle Zone demo.

pub mod aggregate;
pub mod bedrock;
pub mod price;

pub use aggregate::{run_round, RoundConfig, RoundOutcome};
pub use bedrock::{now_ms, Inscription, MockBedrock};
pub use price::{fmt_price, random_signing_key, PriceRecord, VerifyError, PRICE_SCALE};
