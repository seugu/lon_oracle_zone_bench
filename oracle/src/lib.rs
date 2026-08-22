#![forbid(unsafe_code)]
#![allow(clippy::allow_attributes_without_reason)]

//! Logos Oracle Zone node.
//!
//! One oracle, one channel, one writer. The node creates a channel derived
//! from its own keys, becomes that channel's sole accredited writer by being
//! the first to inscribe into it, and then publishes BIP-340-signed price
//! records there. `watch` reads the same channel back and verifies both
//! properties.
//!
//! See `README.md` for the full public-testnet runbook.

pub mod keys;
pub mod node;
pub mod record;
pub mod watch;

use std::{path::PathBuf, time::Duration};

use clap::{Args, Parser, Subcommand};
use lb_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::sequencer::FundingConfig;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::{
    keys::{OracleIdentity, decode_fixed},
    node::{OracleConfig, node_client},
    record::HARDCODED_PRICE,
};

#[derive(Parser, Debug)]
#[command(
    name = "logos-oracle-node",
    about = "Logos Oracle Zone node: a single-writer price channel with BIP-340 attestations"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Publish signed price records into this oracle's own channel.
    Run(RunArgs),
    /// Follow an oracle channel and verify every record it carries.
    Watch(WatchArgs),
    /// Print this node's keys and the channel id they derive, then exit.
    Identity(IdentityArgs),
    /// Print the on-chain state of this oracle's channel.
    State(StateArgs),
}

/// Where the node's key material lives.
#[derive(Args, Debug, Clone)]
pub struct KeyArgs {
    /// Ed25519 channel key — the channel's accredited writer. Created on
    /// first run.
    #[arg(
        long,
        default_value = "./data/oracle-channel.ed25519",
        env = "ORACLE_CHANNEL_KEY_PATH"
    )]
    pub channel_key_path: PathBuf,

    /// secp256k1 / BIP-340 attestation key that signs price records. Created
    /// on first run.
    #[arg(
        long,
        default_value = "./data/oracle-attestation.bip340",
        env = "ORACLE_ATTESTATION_KEY_PATH"
    )]
    pub attestation_key_path: PathBuf,

    /// Use this channel id (64 hex chars) instead of deriving one from the
    /// two public keys.
    #[arg(long, env = "ORACLE_CHANNEL_ID")]
    pub channel_id: Option<String>,
}

/// How to reach the Logos node.
#[derive(Args, Debug, Clone)]
pub struct NodeArgs {
    /// Logos blockchain node HTTP endpoint.
    #[arg(long, default_value = "http://localhost:8080", env = "ORACLE_NODE_URL")]
    pub node_url: String,

    /// Basic-auth username for the node endpoint, if it has one.
    #[arg(long, env = "ORACLE_NODE_AUTH_USERNAME")]
    pub node_auth_username: Option<String>,

    /// Basic-auth password for the node endpoint.
    #[arg(long, env = "ORACLE_NODE_AUTH_PASSWORD")]
    pub node_auth_password: Option<String>,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub node: NodeArgs,
    #[command(flatten)]
    pub keys: KeyArgs,

    /// Crash-recovery checkpoint written by the sequencer.
    #[arg(
        long,
        default_value = "./data/oracle.checkpoint",
        env = "ORACLE_CHECKPOINT_PATH"
    )]
    pub checkpoint_path: PathBuf,

    /// File the derived channel id is written to, for `watch` to read.
    #[arg(long, default_value = "./data/channel.txt", env = "ORACLE_CHANNEL_PATH")]
    pub channel_path: PathBuf,

    /// Feed identifier carried in every record.
    #[arg(long, default_value = "BTC/USD", env = "ORACLE_PAIR")]
    pub pair: String,

    /// Decimal scale of the published price.
    #[arg(long, default_value_t = 8, env = "ORACLE_DECIMALS")]
    pub decimals: u8,

    /// Seconds between publications (the spec's heartbeat interval).
    #[arg(long, default_value_t = 30, env = "ORACLE_INTERVAL_SECS")]
    pub interval_secs: u64,

    #[command(flatten)]
    pub funding: FundingArgs,
}

/// Who pays the gas.
///
/// The node's own wallet sponsors the fee: it appends the fee inputs, proves
/// the transfer and returns the funded transaction, so the wallet's secret
/// key never leaves the node. Omit `--funding-pk` to build fee-less
/// transactions, which the chain accepts only while gas prices are zero.
#[derive(Args, Debug, Clone)]
pub struct FundingArgs {
    /// Hex public key of a wallet the connected node controls. Take it from
    /// `known_keys` in the node's `user_config.yaml`.
    #[arg(long, env = "ORACLE_FUNDING_PK")]
    pub funding_pk: Option<String>,

    /// Hard cap on a single transaction's fee, in gas units.
    #[arg(long, default_value_t = 1_000_000, env = "ORACLE_MAX_TX_FEE")]
    pub max_tx_fee: u64,

    /// Execution tip paid on top of the mandatory fee, capped by
    /// `--max-tx-fee`.
    #[arg(
        long,
        default_value_t = FundingConfig::DEFAULT_PRIORITY_FEE,
        env = "ORACLE_PRIORITY_FEE"
    )]
    pub priority_fee: u64,
}

impl FundingArgs {
    /// Builds the SDK funding config, or `None` for fee-less transactions.
    pub fn to_config(&self) -> Result<Option<FundingConfig>, keys::Error> {
        let Some(hex_key) = self.funding_pk.as_deref() else {
            return Ok(None);
        };

        let bytes = decode_fixed::<32>(hex_key)?;
        let field_element = lb_groth16::fr_from_bytes(&bytes)
            .map_err(|_ignored| keys::Error::BadHexLength {
                expected: 32,
                actual: bytes.len(),
            })?;

        Ok(Some(FundingConfig {
            funding_pk: lb_key_management_system_service::keys::ZkPublicKey::new(field_element),
            max_tx_fee: self.max_tx_fee.into(),
            priority_fee: self.priority_fee,
        }))
    }
}

#[derive(Args, Debug)]
pub struct WatchArgs {
    #[command(flatten)]
    pub node: NodeArgs,

    /// Channel id to follow (64 hex chars). Mutually exclusive with
    /// `--channel-path`.
    #[arg(long, env = "ORACLE_CHANNEL_ID")]
    pub channel_id: Option<String>,

    /// Read the channel id from the file the oracle wrote.
    #[arg(long, default_value = "./data/channel.txt", env = "ORACLE_CHANNEL_PATH")]
    pub channel_path: PathBuf,

    /// Pin the oracle's BIP-340 x-only public key (64 hex chars) instead of
    /// learning it from the channel's announcement.
    #[arg(long, env = "ORACLE_EXPECT_WRITER")]
    pub expect_writer: Option<String>,
}

#[derive(Args, Debug)]
pub struct IdentityArgs {
    #[command(flatten)]
    pub keys: KeyArgs,
}

#[derive(Args, Debug)]
pub struct StateArgs {
    #[command(flatten)]
    pub node: NodeArgs,
    #[command(flatten)]
    pub keys: KeyArgs,
}

/// Entry point.
pub async fn run(cli: Cli) {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_ignored| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let outcome = match cli.command {
        Command::Run(args) => run_oracle(args).await,
        Command::Watch(args) => run_watch(args).await,
        Command::Identity(args) => print_identity(&args),
        Command::State(args) => print_state(args).await,
    };

    if let Err(message) = outcome {
        error!("{message}");
        std::process::exit(1);
    }
}

async fn run_oracle(args: RunArgs) -> Result<(), String> {
    let identity = OracleIdentity::load_or_create(
        &args.keys.channel_key_path,
        &args.keys.attestation_key_path,
        args.keys.channel_id.as_deref(),
    )
    .map_err(|e| e.to_string())?;

    let funding = args.funding.to_config().map_err(|e| e.to_string())?;

    let config = OracleConfig {
        node_url: args.node.node_url,
        node_auth_username: args.node.node_auth_username,
        node_auth_password: args.node.node_auth_password,
        checkpoint_path: args.checkpoint_path,
        channel_path: args.channel_path,
        pair: args.pair,
        decimals: args.decimals,
        interval: Duration::from_secs(args.interval_secs.max(1)),
        funding,
    };

    node::run(identity, config).await.map_err(|e| e.to_string())
}

async fn run_watch(args: WatchArgs) -> Result<(), String> {
    let channel_id = resolve_watch_channel(&args)?;
    let node = node_client(
        &args.node.node_url,
        args.node.node_auth_username,
        args.node.node_auth_password,
    )
    .map_err(|e| e.to_string())?;

    watch::run(node, channel_id, args.expect_writer.as_deref())
        .await
        .map_err(|e| e.to_string())
}

fn resolve_watch_channel(args: &WatchArgs) -> Result<ChannelId, String> {
    let hex_id = match args.channel_id.as_deref() {
        Some(id) => id.to_owned(),
        None => std::fs::read_to_string(&args.channel_path).map_err(|e| {
            format!(
                "no --channel-id given and {} could not be read: {e}",
                args.channel_path.display()
            )
        })?,
    };

    decode_fixed::<32>(hex_id.trim())
        .map(ChannelId::from)
        .map_err(|e| format!("invalid channel id: {e}"))
}

fn print_identity(args: &IdentityArgs) -> Result<(), String> {
    let identity = OracleIdentity::load_or_create(
        &args.keys.channel_key_path,
        &args.keys.attestation_key_path,
        args.keys.channel_id.as_deref(),
    )
    .map_err(|e| e.to_string())?;

    println!("channel id       : {}", hex::encode(identity.channel_id.as_ref()));
    println!("channel key      : {} (ed25519)", hex::encode(identity.channel_pubkey()));
    println!(
        "attestation key  : {} (BIP-340 x-only)",
        hex::encode(identity.attestation_pubkey().serialize())
    );
    println!("hardcoded price  : {HARDCODED_PRICE}");

    Ok(())
}

async fn print_state(args: StateArgs) -> Result<(), String> {
    let identity = OracleIdentity::load_or_create(
        &args.keys.channel_key_path,
        &args.keys.attestation_key_path,
        args.keys.channel_id.as_deref(),
    )
    .map_err(|e| e.to_string())?;

    let node = node_client(
        &args.node.node_url,
        args.node.node_auth_username,
        args.node.node_auth_password,
    )
    .map_err(|e| e.to_string())?;

    let channel_hex = hex::encode(identity.channel_id.as_ref());
    let Some(state) = node::try_channel_state(&node, identity.channel_id)
        .await
        .map_err(|e| e.to_string())?
    else {
        info!("channel {channel_hex} does not exist yet");
        return Ok(());
    };

    info!("channel {channel_hex} exists");
    for (index, key) in state.accredited_keys.iter().enumerate() {
        info!("  accredited key [{index}]: {}", hex::encode(key.to_bytes()));
    }
    info!("  tip message: {}", hex::encode(state.tip_message.as_ref()));
    info!("  tip slot:    {:?}", state.tip_slot);
    node::ensure_channel_owned(Some(&state), &identity).map_err(|e| e.to_string())?;

    Ok(())
}
