use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter};

use oracle_zone_common::{fmt_price, MockBedrock};
use oracle_zone_sequencer::{run_follow_server, spawn_intake, spawn_market, spawn_users, SimConfig};

/// Oracle Zone sequencer: 50 simulated oracle users sign BTC/USDT prices and
/// publish them to a mock Bedrock; indexers follow over TCP.
#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    /// Listen address for the indexer follow stream.
    #[arg(long, default_value = "127.0.0.1:9090")]
    listen: SocketAddr,

    /// Total simulated oracle users.
    #[arg(long, default_value_t = 50)]
    users: usize,

    /// How many users always produce outliers (>5% off the market).
    #[arg(long, default_value_t = 6)]
    outlier_users: usize,

    /// Starting BTC/USDT price in cents (65_000_00 = 65000.00).
    #[arg(long, default_value_t = 65_000_00)]
    base_price: u64,

    /// Minimum per-user submit interval, ms.
    #[arg(long, default_value_t = 800)]
    min_interval_ms: u64,

    /// Maximum per-user submit interval, ms.
    #[arg(long, default_value_t = 4_000)]
    max_interval_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let cfg = SimConfig {
        users: args.users,
        outlier_users: args.outlier_users,
        base_price: args.base_price,
        min_interval_ms: args.min_interval_ms,
        max_interval_ms: args.max_interval_ms,
    };

    info!("Oracle Zone sequencer starting");
    info!(
        "  users={} (outliers={})  base={}  interval={}..{}ms",
        cfg.users,
        cfg.outlier_users,
        fmt_price(cfg.base_price),
        cfg.min_interval_ms,
        cfg.max_interval_ms
    );

    let bedrock = Arc::new(MockBedrock::new());
    let market = Arc::new(AtomicU64::new(cfg.base_price));
    let (tx, rx) = mpsc::channel(1024);

    spawn_market(Arc::clone(&market));
    spawn_users(&cfg, market, tx);
    spawn_intake(Arc::clone(&bedrock), rx);

    run_follow_server(args.listen, bedrock).await
}
