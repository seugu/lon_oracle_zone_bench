//! The oracle node: owns one channel, writes BIP-340-signed prices into it.
//!
//! # How single-writer works
//!
//! Bedrock enforces it, not this code. `InscriptionOp::verify` looks the
//! channel up in ledger state and rejects any inscription whose signer is not
//! the accredited key whose turn it is:
//!
//! ```text
//! if self.signer != channel.accredited_keys[channel.round_robin(slot).0] {
//!     return Err(Error::UnauthorizedSigner { .. })
//! }
//! ```
//!
//! and `InscriptionOp::execute` creates a previously-unseen channel with
//! `accredited_keys = [signer]`. So the *first* inscription on a fresh
//! `ChannelId` permanently installs its signer as the sole writer, and every
//! later inscription from anyone else is rejected by consensus. That single
//! accredited key also makes the round-robin degenerate — index 0 always —
//! so this oracle holds the turn forever and never has to wait for one.
//!
//! Two consequences worth being deliberate about:
//!
//! * A channel id is claimed on a first-come basis. [`ensure_channel_owned`]
//!   therefore refuses to run if the channel already exists under someone
//!   else's key, instead of publishing into a log it does not own and having
//!   every transaction rejected.
//! * That first inscription is load-bearing, so this node makes it an
//!   [`OracleMessage::Announce`] carrying both public keys — the log then
//!   states, in its own genesis message, which BIP-340 key readers must
//!   demand on every record that follows.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lb_common_http_client::{BasicAuthCredentials, CommonHttpClient};
use lb_core::mantle::{channel::ChannelState, ops::channel::inscribe::Inscription};
use logos_blockchain_zone_sdk::{
    adapter::{Node as _, NodeHttpClient},
    sequencer::{
        Event, FinalizedOp, FinalizedTx, FundingConfig, SequencerCheckpoint, SequencerConfig,
        ZoneSequencer,
    },
};
use reqwest::Url;
use tracing::{debug, error, info, warn};

use crate::{
    keys::OracleIdentity,
    record::{
        AnnounceBody, HARDCODED_PRICE, OracleEnvelope, OracleMessage, PriceRecord, sign_announce,
        sign_price_record,
    },
};

/// How long to wait between channel-state polls while the node is starting.
const CHANNEL_STATE_RETRY: Duration = Duration::from_secs(2);

/// How many times startup retries a channel-state query before giving up.
///
/// Generous enough to cover a node that is still opening its HTTP port, short
/// enough that a wrong `--node-url` is reported rather than waited on.
pub const STARTUP_CHANNEL_STATE_ATTEMPTS: u32 = 15;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid node URL: {0}")]
    Url(String),
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("checkpoint file {path} is corrupt: {source}")]
    Checkpoint {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Keys(#[from] crate::keys::Error),
    #[error(transparent)]
    Record(#[from] crate::record::Error),
    #[error("payload does not fit in one inscription: {0}")]
    InscriptionTooLarge(String),
    #[error(
        "channel {channel_id} is already owned by {owner}, not by this node's key {ours} - \
         every inscription would be rejected as an unauthorized signer. Use a different \
         channel key, or point --channel-id at your own channel."
    )]
    ChannelNotOurs {
        channel_id: String,
        owner: String,
        ours: String,
    },
    #[error("publish failed: {0}")]
    Publish(#[from] logos_blockchain_zone_sdk::sequencer::Error),
    #[error("node request failed: {0}")]
    Node(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Everything the run loop needs, resolved from CLI arguments.
pub struct OracleConfig {
    pub node_url: String,
    pub node_auth_username: Option<String>,
    pub node_auth_password: Option<String>,
    pub checkpoint_path: PathBuf,
    pub channel_path: PathBuf,
    pub pair: String,
    pub decimals: u8,
    pub interval: Duration,
    pub funding: Option<FundingConfig>,
}

/// Builds an HTTP client for a Logos node.
pub fn node_client(
    node_url: &str,
    username: Option<String>,
    password: Option<String>,
) -> Result<NodeHttpClient> {
    let url = Url::parse(node_url).map_err(|e| Error::Url(e.to_string()))?;
    let basic_auth = username.map(|user| BasicAuthCredentials::new(user, password));
    Ok(NodeHttpClient::new(CommonHttpClient::new(basic_auth), url))
}

/// Runs the oracle until Ctrl-C.
pub async fn run(identity: OracleIdentity, config: OracleConfig) -> Result<()> {
    let channel_hex = hex::encode(identity.channel_id.as_ref());
    let attestation_hex = hex::encode(identity.attestation_pubkey().serialize());
    let channel_key_hex = hex::encode(identity.channel_pubkey());

    info!("Logos Oracle Zone node");
    info!("  node:            {}", config.node_url);
    info!("  channel id:      {channel_hex}");
    info!("  channel key:     {channel_key_hex} (ed25519, sole writer)");
    info!("  attestation key: {attestation_hex} (BIP-340 x-only)");
    info!("  feed:            {} @ {} decimals", config.pair, config.decimals);
    info!(
        "  price:           {} ({} raw, hardcoded)",
        crate::record::format_scaled(HARDCODED_PRICE, config.decimals),
        HARDCODED_PRICE
    );
    if config.funding.is_none() {
        info!("  funding:         none (fee-less txs; valid only while gas prices are zero)");
    }

    // The indexer needs the channel id, and it is derived rather than
    // configured, so hand it over through a file the way the SQLite demo does.
    write_atomically(&config.channel_path, channel_hex.as_bytes())?;

    let node = node_client(
        &config.node_url,
        config.node_auth_username.clone(),
        config.node_auth_password.clone(),
    )?;

    // Query before init: whether the channel already exists decides both
    // whether we must announce and whether a stale checkpoint is usable.
    let existing = channel_state(&node, identity.channel_id, STARTUP_CHANNEL_STATE_ATTEMPTS).await?;
    ensure_channel_owned(existing.as_ref(), &identity)?;
    let channel_exists = existing.is_some();

    let checkpoint = load_checkpoint(&config.checkpoint_path, channel_exists)?;
    let sequencer_config = SequencerConfig {
        funding: config.funding.clone(),
        ..SequencerConfig::default()
    };

    let mut sequencer = ZoneSequencer::init_with_config(
        identity.channel_id,
        identity.channel_key.clone(),
        node.clone(),
        sequencer_config,
        checkpoint,
    );

    info!("Bootstrapping sequencer (backfilling channel history)...");

    let mut ticker = tokio::time::interval(config.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut progress = Progress {
        ready: false,
        announced: channel_exists,
        published: 0,
    };

    loop {
        tokio::select! {
            event = sequencer.next_event() => {
                if matches!(event, Event::Ready) && !progress.ready {
                    progress.ready = true;
                    info!("Sequencer ready - publishing every {:?}", config.interval);
                }
                handle_event(event, &config.checkpoint_path);
            }

            _ = ticker.tick(), if progress.ready => {
                publish_tick(&mut sequencer, &identity, &config, &mut progress).await?;
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Run-loop state that outlives a single tick.
struct Progress {
    /// Set once the sequencer has finished backfilling.
    ready: bool,
    /// Set once the channel carries its announcement.
    announced: bool,
    /// Price records enqueued so far.
    published: u64,
}

/// Publishes one message per tick: the announcement first, then prices.
///
/// A publish failure is logged rather than propagated - the node should keep
/// ticking through a node hiccup, and the next tick carries a fresher price
/// than a retry of this one would. Only a failure to *build* the payload,
/// which cannot fix itself, aborts the loop.
async fn publish_tick(
    sequencer: &mut ZoneSequencer<NodeHttpClient>,
    identity: &OracleIdentity,
    config: &OracleConfig,
    progress: &mut Progress,
) -> Result<()> {
    // The announcement is the channel's genesis message, so it has to land
    // before any price record.
    if !progress.announced {
        let payload = build_announce(identity, config)?;
        match publish(sequencer, payload, &config.checkpoint_path).await {
            Ok(()) => {
                progress.announced = true;
                info!("Published channel announcement (channel genesis)");
            }
            Err(e) => error!("failed to publish announcement: {e}"),
        }
        return Ok(());
    }

    let (payload, record) = build_price(identity, config)?;
    match publish(sequencer, payload, &config.checkpoint_path).await {
        Ok(()) => {
            progress.published += 1;
            info!(
                "Published {} = {} (raw {}, t={}) - {} total",
                record.pair,
                record.display_price(),
                record.price,
                record.timestamp,
                progress.published,
            );
        }
        Err(e) => error!("failed to publish price record: {e}"),
    }

    Ok(())
}

/// Refuses to start when the channel exists but is not ours.
///
/// Without this the node would publish happily and every transaction would be
/// rejected on chain as `UnauthorizedSigner` — a failure that is invisible
/// from the publish call, since publishing only enqueues.
pub fn ensure_channel_owned(state: Option<&ChannelState>, identity: &OracleIdentity) -> Result<()> {
    let Some(state) = state else {
        // Channel does not exist yet: our first inscription creates it and
        // makes us the sole accredited key.
        return Ok(());
    };

    let ours = identity.channel_pubkey();
    let keys = state.accredited_keys.as_slice();

    if keys.len() == 1 && keys[0].to_bytes() == ours {
        info!("Channel exists and this node is its sole accredited writer");
        return Ok(());
    }

    if keys.iter().any(|key| key.to_bytes() == ours) {
        warn!(
            "Channel has {} accredited keys and ours is one of them - this is no longer a \
             single-writer oracle channel; writes are round-robin scheduled",
            keys.len()
        );
        return Ok(());
    }

    Err(Error::ChannelNotOurs {
        channel_id: hex::encode(identity.channel_id.as_ref()),
        owner: keys
            .iter()
            .map(|key| hex::encode(key.to_bytes()))
            .collect::<Vec<_>>()
            .join(", "),
        ours: hex::encode(ours),
    })
}

/// Reads channel state once. `Ok(None)` means the channel does not exist yet,
/// which is the normal state before an oracle's first inscription.
pub async fn try_channel_state(
    node: &NodeHttpClient,
    channel_id: lb_core::mantle::ops::channel::ChannelId,
) -> Result<Option<ChannelState>> {
    node.channel_state(channel_id)
        .await
        .map_err(|e| Error::Node(e.to_string()))
}

/// Polls the node for channel state, retrying transport failures.
///
/// Used at startup, where the node may still be coming up: an unreachable
/// node is a reason to wait, not to give up. `attempts` bounds the wait so a
/// permanently wrong `--node-url` surfaces as an error instead of hanging.
pub async fn channel_state(
    node: &NodeHttpClient,
    channel_id: lb_core::mantle::ops::channel::ChannelId,
    attempts: u32,
) -> Result<Option<ChannelState>> {
    let mut last = None;

    for attempt in 1..=attempts.max(1) {
        match try_channel_state(node, channel_id).await {
            Ok(state) => return Ok(state),
            Err(e) => {
                warn!("could not query channel state (attempt {attempt}/{attempts}): {e}");
                last = Some(e);
                tokio::time::sleep(CHANNEL_STATE_RETRY).await;
            }
        }
    }

    Err(last.unwrap_or_else(|| Error::Node("channel state unavailable".to_owned())))
}

fn build_announce(identity: &OracleIdentity, config: &OracleConfig) -> Result<Inscription> {
    let body = AnnounceBody {
        writer_pubkey: [0u8; 32], // filled in by the signer
        channel_pubkey: identity.channel_pubkey(),
        pair: config.pair.clone(),
        decimals: config.decimals,
        timestamp: unix_seconds(),
    };
    let announce = sign_announce(&identity.secp, &identity.attestation_key, body)?;
    encode(OracleMessage::Announce(announce))
}

fn build_price(
    identity: &OracleIdentity,
    config: &OracleConfig,
) -> Result<(Inscription, PriceRecord)> {
    let record = PriceRecord {
        pair: config.pair.clone(),
        price: HARDCODED_PRICE,
        decimals: config.decimals,
        timestamp: unix_seconds(),
        writer_pubkey: [0u8; 32], // filled in by the signer
    };
    let signed = sign_price_record(&identity.secp, &identity.attestation_key, record)?;
    let record = signed.record.clone();

    Ok((encode(OracleMessage::Price(signed))?, record))
}

fn encode(message: OracleMessage) -> Result<Inscription> {
    let bytes = OracleEnvelope::new(message).encode()?;
    Inscription::try_from(bytes).map_err(|e| Error::InscriptionTooLarge(e.to_string()))
}

async fn publish(
    sequencer: &mut ZoneSequencer<NodeHttpClient>,
    payload: Inscription,
    checkpoint_path: &Path,
) -> Result<()> {
    let (result, checkpoint) = sequencer.handle().publish(payload).await?;
    save_checkpoint(checkpoint_path, &checkpoint);

    let info = result.tx.inscription();
    debug!(
        "enqueued msg {} (tx {:?})",
        hex::encode(info.this_msg.as_ref()),
        result.inscription_id(),
    );

    Ok(())
}

fn handle_event(event: Event, checkpoint_path: &Path) {
    match event {
        Event::Ready => {}
        Event::BlocksProcessed {
            checkpoint,
            channel_update,
            finalized,
        } => {
            log_finalized(&finalized);

            // Orphaned txs are the SDK telling us a branch change dropped one
            // of our inscriptions. Republishing is not needed here: the next
            // tick publishes a fresh record with a current timestamp, which
            // is more useful for a price feed than resurrecting a stale one.
            if !channel_update.orphaned.is_empty() {
                warn!(
                    "{} inscription(s) orphaned by a chain reorg; the next tick supersedes them",
                    channel_update.orphaned.len()
                );
            }

            save_checkpoint(checkpoint_path, &checkpoint);
        }
        Event::MempoolPending(tx_hash) => debug!("tx {tx_hash:?} accepted into the mempool"),
        Event::TurnNotification { notification } => {
            debug!("turn notification: {notification:?}");
        }
    }
}

fn log_finalized(finalized: &[FinalizedTx]) {
    for tx in finalized {
        for op in &tx.ops {
            if let FinalizedOp::Inscription(info) = op {
                info!(
                    "Finalized msg {} at slot {:?}",
                    hex::encode(info.this_msg.as_ref()),
                    tx.l1_slot,
                );
            }
        }
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Loads the persisted checkpoint, discarding it if the channel is gone.
///
/// A checkpoint describes a position in a channel's history. If the node is
/// pointed at a fresh network (or the channel was never created), replaying
/// from it would resume a history that does not exist, so it is dropped.
pub fn load_checkpoint(path: &Path, channel_exists: bool) -> Result<Option<SequencerCheckpoint>> {
    if !path.exists() {
        return Ok(None);
    }

    if !channel_exists {
        warn!(
            "discarding checkpoint {}: the channel does not exist on this node's chain",
            path.display()
        );
        return Ok(None);
    }

    let bytes = fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| Error::Checkpoint {
            path: path.to_path_buf(),
            source,
        })
}

fn save_checkpoint(path: &Path, checkpoint: &SequencerCheckpoint) {
    match serde_json::to_vec(checkpoint) {
        Ok(bytes) => {
            if let Err(e) = write_atomically(path, &bytes) {
                error!("failed to save checkpoint: {e}");
            }
        }
        Err(e) => error!("failed to serialize checkpoint: {e}"),
    }
}

/// Writes via a temporary file and a rename, so a crash mid-write cannot
/// leave a half-written checkpoint that fails to parse on restart.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| Error::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let temp = path.with_extension("tmp");
    fs::write(&temp, bytes).map_err(|source| Error::Io {
        path: temp.clone(),
        source,
    })?;
    fs::rename(&temp, path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(())
}
