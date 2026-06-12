//! Round aggregation — the Oracle Zone's "indexer logic".
//!
//! Per round (one push heartbeat) the indexer:
//!   1. verifies every record's ECDSA signature (timed; this is the work the
//!      LEZ on-chain path cannot afford beyond ~64 verifications),
//!   2. computes the mean of the verified prices,
//!   3. discards records farther than `outlier_bps` (default 5% = 500 bps)
//!      from that mean,
//!   4. if at least `quorum` (default 10) records survive, attests the mean
//!      of the survivors and writes it to state.
//!
//! Design note: the spec for this demo asks for a *mean*-based filter. Mean is
//! sensitive to coordinated outliers (they drag the reference point toward
//! themselves before being filtered); a median-based provisional reference is
//! the robust production choice. With a minority of outliers (< ~20%) and a
//! 5% band the mean filter behaves correctly, which the tests pin down.

use std::time::{Duration, Instant};

use crate::price::PriceRecord;

/// Aggregation parameters for one round.
#[derive(Debug, Clone)]
pub struct RoundConfig {
    /// Outlier band around the mean, in basis points (500 = 5%).
    pub outlier_bps: u64,
    /// Minimum surviving records required to attest a price.
    pub quorum: usize,
}

impl Default for RoundConfig {
    fn default() -> Self {
        Self {
            outlier_bps: 500,
            quorum: 10,
        }
    }
}

/// Outcome of one aggregation round.
#[derive(Debug, Clone)]
pub struct RoundOutcome {
    /// Records examined.
    pub total: usize,
    /// Records whose signature verified.
    pub verified: usize,
    /// Records rejected at signature verification.
    pub rejected_sig: usize,
    /// Mean over all verified records (the outlier reference), cents.
    pub mean_verified: Option<u64>,
    /// Verified records rejected by the outlier band.
    pub rejected_outlier: usize,
    /// Verified, in-band records.
    pub survivors: usize,
    /// Attested price (mean of survivors) if `survivors >= quorum`.
    pub attested_price: Option<u64>,
    /// Wall-clock time of the signature-verification loop only.
    pub verify_time: Duration,
}

fn mean(prices: &[u64]) -> Option<u64> {
    if prices.is_empty() {
        return None;
    }
    let sum: u128 = prices.iter().map(|&p| p as u128).sum();
    Some((sum / prices.len() as u128) as u64)
}

/// Run one aggregation round over the records received in this heartbeat.
pub fn run_round(records: &[PriceRecord], cfg: &RoundConfig) -> RoundOutcome {
    let total = records.len();

    // --- 1. signature verification (timed region) ---
    let mut prices: Vec<u64> = Vec::with_capacity(total);
    let t0 = Instant::now();
    for r in records {
        if r.verify().is_ok() {
            prices.push(r.price);
        }
    }
    let verify_time = t0.elapsed();
    // --- end timed region ---

    let verified = prices.len();
    let rejected_sig = total - verified;

    // --- 2-3. mean + outlier band ---
    let mean_verified = mean(&prices);
    let mut rejected_outlier = 0usize;
    let survivors_vec: Vec<u64> = match mean_verified {
        None => Vec::new(),
        Some(m) => prices
            .into_iter()
            .filter(|&p| {
                // |p - m| / m <= outlier_bps / 10_000, in integer arithmetic
                let in_band =
                    (p.abs_diff(m) as u128) * 10_000 <= (m as u128) * (cfg.outlier_bps as u128);
                if !in_band {
                    rejected_outlier += 1;
                }
                in_band
            })
            .collect(),
    };

    let survivors = survivors_vec.len();

    // --- 4. quorum + attestation ---
    let attested_price = if survivors >= cfg.quorum {
        mean(&survivors_vec)
    } else {
        None
    };

    RoundOutcome {
        total,
        verified,
        rejected_sig,
        mean_verified,
        rejected_outlier,
        survivors,
        attested_price,
        verify_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::price::random_signing_key;

    const BASE: u64 = 65_000_00; // 65000.00 USDT in cents
    const TS: u64 = 1_700_000_000_000;

    fn honest(n: usize) -> Vec<PriceRecord> {
        // Deterministic small offsets within ±0.3% — comfortably inside 5%.
        (0..n)
            .map(|i| {
                let sk = random_signing_key();
                let off = (i as i64 % 7 - 3) * 65 * 100 / 100; // ±~0.03% steps
                let price = (BASE as i64 + off) as u64;
                PriceRecord::signed(&sk, "BTC/USDT", price, TS)
            })
            .collect()
    }

    fn outlier(n: usize, bps_off: i64) -> Vec<PriceRecord> {
        (0..n)
            .map(|_| {
                let sk = random_signing_key();
                let price = (BASE as i128 * (10_000 + bps_off as i128) / 10_000) as u64;
                PriceRecord::signed(&sk, "BTC/USDT", price, TS)
            })
            .collect()
    }

    #[test]
    fn attests_with_quorum_and_filters_outliers() {
        // 14 honest + 4 outliers at +8%: outliers must be cut, attest near BASE.
        let mut recs = honest(14);
        recs.extend(outlier(4, 800));
        let out = run_round(&recs, &RoundConfig::default());

        assert_eq!(out.total, 18);
        assert_eq!(out.verified, 18);
        assert_eq!(out.rejected_sig, 0);
        assert_eq!(out.rejected_outlier, 4, "all +8% records must be out");
        assert_eq!(out.survivors, 14);
        let attested = out.attested_price.expect("quorum of 10 met");
        let dev_bps = attested.abs_diff(BASE) as u128 * 10_000 / BASE as u128;
        assert!(dev_bps <= 50, "attested within 0.5% of base, got {dev_bps} bps");
    }

    #[test]
    fn no_attestation_below_quorum() {
        // 9 honest survivors < quorum 10 → no state write.
        let recs = honest(9);
        let out = run_round(&recs, &RoundConfig::default());
        assert_eq!(out.survivors, 9);
        assert!(out.attested_price.is_none());
    }

    #[test]
    fn outliers_cannot_rescue_quorum() {
        // 9 honest + 5 far outliers: outliers are filtered, so quorum still fails.
        let mut recs = honest(9);
        recs.extend(outlier(5, 900));
        let out = run_round(&recs, &RoundConfig::default());
        assert_eq!(out.rejected_outlier, 5);
        assert_eq!(out.survivors, 9);
        assert!(out.attested_price.is_none());
    }

    #[test]
    fn bad_signatures_never_count() {
        let mut recs = honest(12);
        // Tamper two records after signing → signature must fail.
        recs[0].price += 1;
        recs[1].price += 1;
        let out = run_round(&recs, &RoundConfig::default());
        assert_eq!(out.rejected_sig, 2);
        assert_eq!(out.verified, 10);
        assert_eq!(out.survivors, 10);
        assert!(out.attested_price.is_some(), "exactly at quorum");
    }

    #[test]
    fn negative_outliers_filtered_symmetrically() {
        let mut recs = honest(12);
        recs.extend(outlier(3, -700)); // -7%
        let out = run_round(&recs, &RoundConfig::default());
        assert_eq!(out.rejected_outlier, 3);
        assert_eq!(out.survivors, 12);
        assert!(out.attested_price.is_some());
    }

    #[test]
    fn empty_round_is_a_clean_noop() {
        let out = run_round(&[], &RoundConfig::default());
        assert_eq!(out.total, 0);
        assert!(out.attested_price.is_none());
    }
}
