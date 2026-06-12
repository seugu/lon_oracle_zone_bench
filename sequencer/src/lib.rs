#![forbid(unsafe_code)]
//! Oracle Zone sequencer side: simulated market, oracle users, mock Bedrock,
//! and a TCP "follow" server that streams finalized inscriptions to indexers.
//!
//! Mapping to the SQLite zone demo:
//!   - SQLite demo's sequencer publishes SQL statements to a Logos channel;
//!     here, oracle users publish signed price records into the mock Bedrock.
//!   - SQLite demo's indexer follows the channel over the zone SDK; here, the
//!     indexer follows over a TCP stream that replays the backlog and then
//!     tails live inscriptions — the same contract, minus the real chain.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use oracle_zone_common::{fmt_price, now_ms, random_signing_key, MockBedrock, PriceRecord};

/// Simulation parameters.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Total oracle users.
    pub users: usize,
    /// How many of them are outlier producers (always > 5% off).
    pub outlier_users: usize,
    /// Starting BTC/USDT price in cents.
    pub base_price: u64,
    /// Per-user submit interval bounds, milliseconds.
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            users: 50,
            outlier_users: 6,
            base_price: 65_000_00,
            min_interval_ms: 800,
            max_interval_ms: 4_000,
        }
    }
}

/// Slow random walk of the "market" price: ±5 bps every second.
/// All honest users observe this shared price plus their own small noise.
pub fn spawn_market(base: Arc<AtomicU64>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let cur = base.load(Ordering::Relaxed);
            let drift_bps: i64 = rand::thread_rng().gen_range(-5..=5);
            let next = apply_bps(cur, drift_bps);
            base.store(next, Ordering::Relaxed);
        }
    });
}

/// price * (1 + bps/10_000) in integer arithmetic.
fn apply_bps(price: u64, bps: i64) -> u64 {
    let p = price as i128;
    (p + p * bps as i128 / 10_000) as u64
}

/// Spawn the oracle users. Each holds its own secp256k1 key, wakes at a
/// random interval, samples the market, signs a record and submits it.
/// Users with index < outlier_users always report a price 6–12% off — the
/// indexer's 5% band must reject every one of them.
pub fn spawn_users(cfg: &SimConfig, market: Arc<AtomicU64>, tx: mpsc::Sender<PriceRecord>) {
    for i in 0..cfg.users {
        let is_outlier = i < cfg.outlier_users;
        let market = Arc::clone(&market);
        let tx = tx.clone();
        let (min_ms, max_ms) = (cfg.min_interval_ms, cfg.max_interval_ms);
        tokio::spawn(async move {
            let key = random_signing_key();
            // Random initial phase so users don't fire in lockstep.
            let phase = rand::thread_rng().gen_range(0..max_ms);
            tokio::time::sleep(Duration::from_millis(phase)).await;
            loop {
                let base = market.load(Ordering::Relaxed);
                let bps: i64 = if is_outlier {
                    // 6%..12% off, random sign — always outside the 5% band.
                    let mag = rand::thread_rng().gen_range(600..=1200);
                    if rand::thread_rng().gen_bool(0.5) { mag } else { -mag }
                } else {
                    // Honest observation noise: within ±0.8%.
                    rand::thread_rng().gen_range(-80..=80)
                };
                let price = apply_bps(base, bps);
                let rec = PriceRecord::signed(&key, "BTC/USDT", price, now_ms());
                if tx.send(rec).await.is_err() {
                    return; // intake closed → shut down
                }
                let sleep_ms = rand::thread_rng().gen_range(min_ms..=max_ms);
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            }
        });
    }
}

/// Intake loop: every record submitted by a user is published (ordered +
/// finalized) on the mock Bedrock.
pub fn spawn_intake(bedrock: Arc<MockBedrock>, mut rx: mpsc::Receiver<PriceRecord>) {
    tokio::spawn(async move {
        while let Some(rec) = rx.recv().await {
            let price = rec.price;
            let pk_short = rec.pubkey.chars().take(10).collect::<String>();
            let ins = bedrock.publish(rec);
            info!(
                "Published seq={} price={} signer={}…",
                ins.seq,
                fmt_price(price),
                pk_short
            );
        }
    });
}

/// TCP follow server. Per connection: subscribe to live FIRST, then send the
/// full backlog, then forward live inscriptions with seq > last backlog seq.
/// That ordering guarantees no gap between backlog and live (same pattern the
/// MockBedrock tests pin down).
pub async fn run_follow_server(addr: SocketAddr, bedrock: Arc<MockBedrock>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("Follow server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await?;
        info!("Indexer connected from {peer}");
        let bedrock = Arc::clone(&bedrock);
        tokio::spawn(async move {
            if let Err(e) = serve_follower(stream, bedrock).await {
                warn!("follower {peer} disconnected: {e}");
            }
        });
    }
}

async fn serve_follower(mut stream: TcpStream, bedrock: Arc<MockBedrock>) -> anyhow::Result<()> {
    let mut live = bedrock.subscribe();
    let backlog = bedrock.backlog();
    let mut last_seq: i128 = -1;

    for ins in &backlog {
        stream.write_all(ins.to_line().as_bytes()).await?;
        stream.write_all(b"\n").await?;
        last_seq = ins.seq as i128;
    }
    stream.flush().await?;
    debug!("backlog of {} sent, tailing live", backlog.len());

    loop {
        match live.recv().await {
            Ok(ins) => {
                if (ins.seq as i128) <= last_seq {
                    continue; // already covered by the backlog snapshot
                }
                last_seq = ins.seq as i128;
                stream.write_all(ins.to_line().as_bytes()).await?;
                stream.write_all(b"\n").await?;
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!("follower lagged by {n} inscriptions; continuing");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}
