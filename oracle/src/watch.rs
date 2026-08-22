//! The consumer side: follow an oracle channel and verify what it says.
//!
//! This is the first three steps of the spec's indexer pipeline —
//! *signature verification*, *membership validation*, then the rest
//! (outlier filtering, quorum, median) which only make sense once several
//! oracle channels are being read at once. What it demonstrates for one
//! channel is the part that has to be right before any aggregation is
//! meaningful:
//!
//! 1. The Ed25519 key that owns the channel is fetched from ledger state, so
//!    "who is allowed to write here" comes from consensus, not from the log.
//! 2. The channel's genesis announcement names the BIP-340 key, and the
//!    announcement is itself signed by that key.
//! 3. Every price record must carry a BIP-340 signature from exactly that
//!    key. A validly-signed record from any other oracle is rejected — a
//!    signature that verifies is not the same as a signature that counts.
//!
//! Note where the two layers sit. Bedrock's Ed25519 check is what stops a
//! third party writing into the channel at all. The BIP-340 check is what
//! lets a consumer that got this record over a relay, a cache, or a
//! screenshot still tell whether the oracle really said it.

use std::time::Duration;

use futures::StreamExt as _;
use lb_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer};
use secp256k1::XOnlyPublicKey;
use tracing::{error, info, warn};

use crate::{
    keys::decode_fixed,
    node::try_channel_state,
    record::{OracleAnnounce, OracleEnvelope, OracleMessage, SignedPriceRecord},
};

const RECONNECT_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Keys(#[from] crate::keys::Error),
    #[error(transparent)]
    Node(#[from] crate::node::Error),
    #[error("indexer error: {0}")]
    Indexer(#[from] logos_blockchain_zone_sdk::indexer::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Follows `channel_id` and prints every verified price record.
///
/// `expected_writer`, when given, pins the BIP-340 key up front instead of
/// learning it from the channel's announcement. Use it when the key is known
/// out of band — it removes the trust-on-first-use window in which a
/// channel's first message could name a key you never intended to follow.
pub async fn run(
    node: NodeHttpClient,
    channel_id: ChannelId,
    expected_writer: Option<&str>,
) -> Result<()> {
    info!("Watching channel {}", hex::encode(channel_id.as_ref()));

    // Consensus, not the log, is the authority on who may write here.
    match try_channel_state(&node, channel_id).await? {
        Some(state) => {
            let keys: Vec<_> = state
                .accredited_keys
                .iter()
                .map(|key| hex::encode(key.to_bytes()))
                .collect();
            info!("Accredited writer(s) on chain: {}", keys.join(", "));
            if keys.len() > 1 {
                warn!("channel has {} writers - not a single-writer oracle channel", keys.len());
            }
        }
        None => {
            info!("Channel does not exist yet; waiting for its first inscription");
        }
    }

    let mut expected: Option<XOnlyPublicKey> = match expected_writer {
        Some(hex_key) => {
            let bytes = decode_fixed::<32>(hex_key)?;
            match XOnlyPublicKey::from_byte_array(bytes) {
                Ok(key) => {
                    info!("Pinned attestation key: {}", hex::encode(key.serialize()));
                    Some(key)
                }
                Err(e) => {
                    error!("--expect-writer is not a valid x-only public key: {e}");
                    return Ok(());
                }
            }
        }
        None => None,
    };

    let indexer = ZoneIndexer::new(channel_id, node);
    let mut tally = Tally::default();

    loop {
        let stream = match indexer.follow().await {
            Ok(stream) => stream,
            Err(e) => {
                error!("could not open the block stream ({e}); retrying");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };
        info!("Connected to the zone block stream");

        futures::pin_mut!(stream);
        while let Some(message) = stream.next().await {
            let ZoneMessage::Block(block) = message else {
                // Deposits and withdrawals are bridging traffic, not oracle
                // data; an oracle channel carries no balance.
                continue;
            };
            let msg_id = hex::encode(block.id.as_ref());

            let payload = Vec::from(block.data);
            let envelope = match OracleEnvelope::decode(&payload) {
                Ok(envelope) => envelope,
                Err(e) => {
                    tally.rejected += 1;
                    warn!("msg {msg_id}: not a well-formed oracle payload ({e})");
                    continue;
                }
            };

            match envelope.message {
                OracleMessage::Announce(announce) => {
                    handle_announce(&announce, &mut expected, &mut tally);
                }
                OracleMessage::Price(signed) => {
                    handle_price(&signed, expected.as_ref(), &msg_id, &mut tally);
                }
            }
        }

        error!("block stream ended; reconnecting");
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Running counts, reported on every accepted or rejected message.
#[derive(Default)]
struct Tally {
    verified: u64,
    rejected: u64,
}

/// Learns the channel's attestation key from its announcement, or checks the
/// announcement against a key that was already pinned.
fn handle_announce(
    announce: &OracleAnnounce,
    expected: &mut Option<XOnlyPublicKey>,
    tally: &mut Tally,
) {
    let key = match announce.verify() {
        Ok(key) => key,
        Err(e) => {
            tally.rejected += 1;
            error!("announcement has an invalid signature: {e}");
            return;
        }
    };

    let announced = hex::encode(key.serialize());

    match expected {
        Some(pinned) if *pinned != key => {
            tally.rejected += 1;
            error!(
                "announcement names {announced}, which is not the pinned attestation key - \
                 ignoring it"
            );
        }
        Some(_pinned) => info!("announcement confirms the pinned key {announced}"),
        None => {
            info!(
                "Channel announcement: feed {} @ {} decimals, attestation key {announced}, \
                 channel key {}",
                announce.body.pair,
                announce.body.decimals,
                hex::encode(announce.body.channel_pubkey),
            );
            *expected = Some(key);
        }
    }
}

/// Verifies one price record and reports the outcome.
fn handle_price(
    signed: &SignedPriceRecord,
    expected: Option<&XOnlyPublicKey>,
    msg_id: &str,
    tally: &mut Tally,
) {
    match verify_price(signed, expected) {
        Ok(()) => {
            tally.verified += 1;
            info!(
                "OK  {} = {} (raw {}, t={}, by {}) - {} verified, {} rejected",
                signed.record.pair,
                signed.record.display_price(),
                signed.record.price,
                signed.record.timestamp,
                hex::encode(signed.record.writer_pubkey),
                tally.verified,
                tally.rejected,
            );
        }
        Err(e) => {
            tally.rejected += 1;
            error!("REJECT msg {msg_id}: {e}");
        }
    }
}

/// Verifies a record's signature, and that it came from the channel's key.
///
/// Before the announcement is seen there is no key to bind to, so the
/// signature is checked but the record is only accepted provisionally — this
/// is reported rather than silently treated as verified.
fn verify_price(
    signed: &SignedPriceRecord,
    expected: Option<&XOnlyPublicKey>,
) -> crate::record::Result<()> {
    let Some(key) = expected else {
        let signer = signed.verify()?;
        warn!(
            "no announcement seen yet; accepting {} on trust-on-first-use",
            hex::encode(signer.serialize())
        );
        return Ok(());
    };

    signed.verify_from(key)
}
