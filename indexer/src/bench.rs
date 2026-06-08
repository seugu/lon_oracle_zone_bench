//! Standalone benchmark for the Oracle Zone aggregation step.
//!
//! This runs WITHOUT a Logos node. It fabricates N signed price records,
//! then runs the exact same `aggregate()` path the indexer uses, and reports
//! how long the signature-verification step took. This answers the core
//! question: how many ECDSA verifications can the indexer perform per block,
//! and how does that compare to LEZ's per-program limit of 64 ECDSA
//! verifications (32M cycle budget / ~524K cycles per secp256k1 verify)?
//!
//! Usage:
//!   oracle-bench                       # default: N = 10
//!   oracle-bench --n 64                # match LEZ's theoretical ECDSA ceiling
//!   oracle-bench --sweep 3,10,50,100,500,1000   # benchmark a range
//!   oracle-bench --n 100 --iterations 20        # average over 20 runs

use clap::Parser;
use oracle_zone_common::{aggregate, random_signing_key, AggregatorConfig, PriceRecord};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(about = "Standalone Oracle Zone verification benchmark (no node required)")]
struct BenchArgs {
    /// Number of signed price records per block to verify.
    #[arg(long, default_value_t = 10)]
    n: usize,

    /// Comma-separated list of N values to sweep (overrides --n if set).
    #[arg(long)]
    sweep: Option<String>,

    /// How many times to repeat each measurement (results are averaged).
    #[arg(long, default_value_t = 10)]
    iterations: usize,

    /// Deviation bound in basis points for outlier filtering.
    #[arg(long, default_value_t = 100)]
    deviation_bps: u64,
}

/// Fabricate a batch of N validly-signed price records around a base price.
fn make_batch(n: usize, base_price: u64) -> Vec<PriceRecord> {
    (0..n)
        .map(|i| {
            let sk = random_signing_key();
            let price = base_price + (i as u64 % 7); // small spread
            PriceRecord::signed(&sk, "BTC/USD", price, 1_700_000_000)
        })
        .collect()
}

struct Row {
    n: usize,
    avg_verify_ms: f64,
    per_sig_us: f64,
    throughput_per_s: f64,
    attested: bool,
}

fn bench_n(n: usize, iterations: usize, config: &AggregatorConfig) -> Row {
    // Pre-generate records OUTSIDE the timed region (signing is not what we
    // measure — only verification, which is what the indexer actually does).
    let batches: Vec<Vec<PriceRecord>> =
        (0..iterations).map(|_| make_batch(n, 65_000)).collect();

    let mut total_verify_secs = 0.0_f64;
    let mut last_attested = false;

    for batch in &batches {
        let res = aggregate(batch, config);
        total_verify_secs += res.verify_time.as_secs_f64();
        last_attested = res.attested_price.is_some();
    }

    let avg_verify_secs = total_verify_secs / iterations as f64;
    let avg_verify_ms = avg_verify_secs * 1000.0;
    let per_sig_us = if n > 0 {
        (avg_verify_secs * 1_000_000.0) / n as f64
    } else {
        0.0
    };
    let throughput_per_s = if avg_verify_secs > 0.0 {
        n as f64 / avg_verify_secs
    } else {
        0.0
    };

    Row {
        n,
        avg_verify_ms,
        per_sig_us,
        throughput_per_s,
        attested: last_attested,
    }
}

fn main() {
    let args = BenchArgs::parse();
    let config = AggregatorConfig {
        allowed_keys: None,
        deviation_bps: args.deviation_bps,
        min_quorum: 1,
    };

    let ns: Vec<usize> = match &args.sweep {
        Some(s) => s
            .split(',')
            .filter_map(|x| x.trim().parse::<usize>().ok())
            .collect(),
        None => vec![args.n],
    };

    println!("Oracle Zone verification benchmark");
    println!("  curve: secp256k1 ECDSA (k256)");
    println!("  iterations per N: {}", args.iterations);
    println!("  deviation bound: {} bps", args.deviation_bps);
    println!();

    // Warm-up so the first measurement isn't skewed by cold caches / lazy init.
    let _ = bench_n(8, 3, &config);

    let overall = Instant::now();
    println!(
        "{:>8} | {:>14} | {:>12} | {:>16} | {:>8}",
        "N", "verify (ms)", "per-sig (us)", "verif/sec", "attested"
    );
    println!("{}", "-".repeat(70));

    let mut rows = Vec::new();
    for n in ns {
        let row = bench_n(n, args.iterations, &config);
        println!(
            "{:>8} | {:>14.3} | {:>12.2} | {:>16.0} | {:>8}",
            row.n,
            row.avg_verify_ms,
            row.per_sig_us,
            row.throughput_per_s,
            if row.attested { "yes" } else { "no" }
        );
        rows.push(row);
    }

    println!("{}", "-".repeat(70));
    println!("total wall time: {:.2} s", overall.elapsed().as_secs_f64());
    println!();

    // Contextualize against LEZ's on-chain limit.
    if let Some(r) = rows.iter().max_by_key(|r| r.n) {
        let in_30s = (r.throughput_per_s * 30.0) as u64;
        println!("Context:");
        println!(
            "  LEZ on-chain ceiling (single program execution): ~64 ECDSA verifications"
        );
        println!(
            "    (32M cycle budget / ~524K cycles per secp256k1 verify)"
        );
        println!(
            "  Oracle Zone indexer (native, this machine): ~{} verifications in a 30s heartbeat",
            in_30s
        );
        if in_30s > 64 {
            println!(
                "  => The indexer clears the LEZ on-chain ceiling by ~{}x, so moving",
                in_30s / 64
            );
            println!(
                "     verification off LEZ into the Oracle Zone removes the N<=3..64 bottleneck."
            );
        }
    }
}
