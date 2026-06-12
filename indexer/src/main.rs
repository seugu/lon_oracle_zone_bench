#![forbid(unsafe_code)]
//! Oracle Zone indexer.
//!
//! Follows the sequencer's inscription stream (backlog + live, in Bedrock seq
//! order), and on a fixed **push heartbeat** (default every 5 s):
//!   1. takes every record finalized since the previous round,
//!   2. verifies all ECDSA signatures,
//!   3. computes the mean, drops records >5% away from it,
//!   4. if >= 10 valid records survive, writes the attested price to state
//!      (`<state-dir>/latest.json` + append `<state-dir>/history.jsonl`).
//!
//! State files play the role of the SQLite demo's local database: any party
//! running this indexer against the same inscription stream reconstructs the
//! same attested history (aggregation is deterministic given the inputs).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::net::TcpStream;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter};

use oracle_zone_common::{fmt_price, now_ms, run_round, Inscription, PriceRecord, RoundConfig};

/// Oracle Zone indexer: verify, filter, attest, persist.
#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    /// Sequencer follow-stream address.
    #[arg(long, default_value = "127.0.0.1:9090")]
    connect: SocketAddr,

    /// Push heartbeat: aggregate and (if quorum) write state this often, ms.
    #[arg(long, default_value_t = 5_000)]
    heartbeat_ms: u64,

    /// Minimum surviving records to attest a price.
    #[arg(long, default_value_t = 10)]
    quorum: usize,

    /// Outlier band around the round mean, basis points (500 = 5%).
    #[arg(long, default_value_t = 500)]
    outlier_bps: u64,

    /// Directory for attested state (latest.json, history.jsonl).
    #[arg(long, default_value = "./data")]
    state_dir: PathBuf,
}

/// What gets persisted per attested round.
#[derive(Debug, Serialize)]
struct AttestedState {
    round: u64,
    pair: &'static str,
    attested_price: u64,
    attested_price_human: String,
    survivors: usize,
    verified: usize,
    rejected_sig: usize,
    rejected_outlier: usize,
    verify_ms: f64,
    finalized_at_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    std::fs::create_dir_all(&args.state_dir)?;

    info!("Oracle Zone indexer starting");
    info!(
        "  connect={}  heartbeat={}ms  quorum={}  outlier_band={}bps",
        args.connect, args.heartbeat_ms, args.quorum, args.outlier_bps
    );

    // Records finalized since the last round, in arrival (= seq) order.
    let pending: Arc<Mutex<Vec<PriceRecord>>> = Arc::new(Mutex::new(Vec::new()));

    spawn_follower(args.connect, Arc::clone(&pending));
    run_rounds(args, pending).await
}

/// Connect to the sequencer (with retry) and feed finalized records into the
/// pending buffer. Tracks the highest seq seen so a reconnect — which replays
/// the full backlog — never double-counts a record.
fn spawn_follower(addr: SocketAddr, pending: Arc<Mutex<Vec<PriceRecord>>>) {
    tokio::spawn(async move {
        let mut last_seq: i128 = -1;
        loop {
            info!("Connecting to sequencer at {addr}...");
            let stream = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("connect failed: {e}; retrying in 3s");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
            };
            info!("Connected, following inscription stream");
            let mut lines = BufReader::new(stream).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let Some(ins) = Inscription::from_line(&line) else {
                            warn!("skipping malformed inscription line");
                            continue;
                        };
                        if (ins.seq as i128) <= last_seq {
                            continue; // backlog replay after reconnect
                        }
                        last_seq = ins.seq as i128;
                        pending
                            .lock()
                            .expect("pending buffer poisoned")
                            .push(ins.record);
                    }
                    Ok(None) => {
                        warn!("stream closed by sequencer; reconnecting in 3s");
                        break;
                    }
                    Err(e) => {
                        warn!("stream error: {e}; reconnecting in 3s");
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

/// The push loop: every heartbeat, aggregate whatever arrived and, on quorum,
/// write the attested state.
async fn run_rounds(args: Args, pending: Arc<Mutex<Vec<PriceRecord>>>) -> anyhow::Result<()> {
    let cfg = RoundConfig {
        outlier_bps: args.outlier_bps,
        quorum: args.quorum,
    };
    let latest_path = args.state_dir.join("latest.json");
    let history_path = args.state_dir.join("history.jsonl");

    let mut round: u64 = 0;
    let mut tick = tokio::time::interval(Duration::from_millis(args.heartbeat_ms));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // consume the immediate first tick

    loop {
        tick.tick().await;
        round += 1;

        let batch: Vec<PriceRecord> = {
            let mut buf = pending.lock().expect("pending buffer poisoned");
            std::mem::take(&mut *buf)
        };

        let out = run_round(&batch, &cfg);
        let verify_ms = out.verify_time.as_secs_f64() * 1000.0;

        match out.attested_price {
            Some(price) => {
                let state = AttestedState {
                    round,
                    pair: "BTC/USDT",
                    attested_price: price,
                    attested_price_human: fmt_price(price),
                    survivors: out.survivors,
                    verified: out.verified,
                    rejected_sig: out.rejected_sig,
                    rejected_outlier: out.rejected_outlier,
                    verify_ms,
                    finalized_at_ms: now_ms(),
                };
                let json = serde_json::to_string_pretty(&state)?;
                std::fs::write(&latest_path, &json)?;
                append_line(&history_path, &serde_json::to_string(&state)?)?;
                info!(
                    "round {round}: ATTESTED BTC/USDT = {} | received={} verified={} bad_sig={} outliers={} survivors={} | verify={:.3} ms | state -> {}",
                    fmt_price(price),
                    out.total,
                    out.verified,
                    out.rejected_sig,
                    out.rejected_outlier,
                    out.survivors,
                    verify_ms,
                    latest_path.display()
                );
            }
            None => {
                info!(
                    "round {round}: quorum NOT met ({} valid < {}) | received={} bad_sig={} outliers={} | verify={:.3} ms | state unchanged",
                    out.survivors,
                    cfg.quorum,
                    out.total,
                    out.rejected_sig,
                    out.rejected_outlier,
                    verify_ms
                );
            }
        }
    }
}

fn append_line(path: &PathBuf, line: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")
}
