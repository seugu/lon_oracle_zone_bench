//! Zone aggregation logic — the heart of the Oracle Zone indexer.
//!
//! Given a batch of `PriceRecord`s (one zone block's worth), this:
//!   1. verifies every signature (the ECDSA work we benchmark),
//!   2. optionally filters by a permissioned key set,
//!   3. filters outliers against the running median (deviation bound),
//!   4. computes the attested median.
//!
//! It records the wall-clock time spent on the verification step so the
//! sequencer/indexer/bench can report "N signatures verified in X ms".

use std::collections::HashSet;
use std::time::{Duration, Instant};

use k256::ecdsa::VerifyingKey;

use crate::price::{median, PriceRecord};

/// Outcome of aggregating one batch of price records.
#[derive(Debug, Clone)]
pub struct AggregationResult {
    /// Number of records examined.
    pub total: usize,
    /// Number whose signature verified.
    pub verified: usize,
    /// Number rejected by signature verification.
    pub rejected_sig: usize,
    /// Number rejected by the deviation/outlier filter.
    pub rejected_outlier: usize,
    /// The attested median price, if a quorum of valid prices remained.
    pub attested_price: Option<u64>,
    /// Wall-clock time spent verifying signatures (the benchmark metric).
    pub verify_time: Duration,
}

/// Configuration for the aggregator.
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Optional permissioned set of allowed signer keys (SEC1 bytes). If
    /// `None`, any valid signature is accepted (Sybil resistance then relies
    /// on stake, out of scope for the benchmark).
    pub allowed_keys: Option<HashSet<Vec<u8>>>,
    /// Deviation bound in basis points (1% = 100 bps). Records farther than
    /// this from the provisional median are dropped. Set very high to disable.
    pub deviation_bps: u64,
    /// Minimum number of valid prices required to produce an attested median.
    pub min_quorum: usize,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            allowed_keys: None,
            deviation_bps: 100, // 1%
            min_quorum: 1,
        }
    }
}

/// Verify and aggregate a batch of records into an attested median.
///
/// The signature-verification loop is timed precisely; everything else
/// (filtering, median) is cheap arithmetic and excluded from `verify_time`.
pub fn aggregate(records: &[PriceRecord], config: &AggregatorConfig) -> AggregationResult {
    let total = records.len();
    let mut rejected_sig = 0usize;

    // --- Step 1: signature verification (TIMED) ---
    let mut verified_prices: Vec<u64> = Vec::with_capacity(total);
    let verify_start = Instant::now();
    for rec in records {
        match rec.verify() {
            Ok(vk) => {
                if key_allowed(&vk, config) {
                    verified_prices.push(rec.price);
                } else {
                    rejected_sig += 1;
                }
            }
            Err(_) => rejected_sig += 1,
        }
    }
    let verify_time = verify_start.elapsed();
    // --- end timed region ---

    let verified = verified_prices.len();

    // --- Step 2: outlier filter against provisional median ---
    let mut rejected_outlier = 0usize;
    let attested_price = if let Some(provisional) = median(&verified_prices) {
        let kept: Vec<u64> = verified_prices
            .into_iter()
            .filter(|&p| {
                let diff = p.abs_diff(provisional);
                // diff / provisional <= deviation_bps / 10_000
                let within = diff.saturating_mul(10_000)
                    <= provisional.saturating_mul(config.deviation_bps);
                if !within {
                    rejected_outlier += 1;
                }
                within
            })
            .collect();

        if kept.len() >= config.min_quorum {
            median(&kept)
        } else {
            None
        }
    } else {
        None
    };

    AggregationResult {
        total,
        verified,
        rejected_sig,
        rejected_outlier,
        attested_price,
        verify_time,
    }
}

fn key_allowed(vk: &VerifyingKey, config: &AggregatorConfig) -> bool {
    match &config.allowed_keys {
        None => true,
        Some(set) => set.contains(vk.to_encoded_point(true).as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::price::random_signing_key;

    fn batch(n: usize, base_price: u64) -> Vec<PriceRecord> {
        (0..n)
            .map(|i| {
                let sk = random_signing_key();
                // small spread around base_price
                let price = base_price + (i as u64 % 5);
                PriceRecord::signed(&sk, "BTC/USD", price, 1_700_000_000)
            })
            .collect()
    }

    #[test]
    fn aggregates_clean_batch() {
        let recs = batch(10, 65_000);
        let res = aggregate(&recs, &AggregatorConfig::default());
        assert_eq!(res.total, 10);
        assert_eq!(res.verified, 10);
        assert_eq!(res.rejected_sig, 0);
        assert!(res.attested_price.is_some());
    }

    #[test]
    fn rejects_bad_signature() {
        let mut recs = batch(3, 65_000);
        recs[0].price += 999; // invalidate signature on first record
        let res = aggregate(&recs, &AggregatorConfig::default());
        assert_eq!(res.rejected_sig, 1);
        assert_eq!(res.verified, 2);
    }
}
