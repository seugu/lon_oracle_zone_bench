#![forbid(unsafe_code)]

pub mod aggregate;
pub mod price;

pub use aggregate::{aggregate, AggregationResult, AggregatorConfig};
pub use price::{median, random_signing_key, PriceRecord, VerifyError};
