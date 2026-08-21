//! LON dispute resolution on LEZ (RFC-244 shape).
//!
//! # The flow
//!
//! On the optimistic path a proposer writes an attested price and the contract
//! stores it unchecked, which opens the dispute window.
//!
//! To dispute, an indexer reads the round's finalized observations from Bedrock
//! and pushes them to LEZ wrapped in its **own** BIP-340 signature and its own
//! membership proof. LEZ cannot know what Bedrock actually finalized, so a
//! single deliverer is not enough: it could hand over a valid but *incomplete*
//! set, chosen to move the median. The defence is the union — the contract
//! accumulates observations from many independent indexers, and one honest
//! contributor is enough to put back whatever an attacker left out. The quorum
//! is therefore counted over **distinct submitting indexers**, not over
//! observations.
//!
//! # Two signature layers, 2N verifications
//!
//! Each `submit` verifies the submitter (1 BIP-340 + 1 membership proof) and
//! every *new* observation it carries (1 BIP-340 + 1 membership proof each).
//! Observations already accumulated are skipped, so across a whole dispute the
//! contract performs N submitter checks plus one check per distinct observation
//! — 2N in the common case where every indexer relays the same set.
//!
//! # Verified on arrival
//!
//! Nothing unverified is ever stored or counted. An observation that fails its
//! signature or its membership proof is dropped on the spot and never occupies
//! a slot, so a submitter cannot fill the accumulator with junk to starve the
//! dispute. Only the price survives into state; the observation itself is
//! discarded, which keeps the account at a few hundred bytes instead of tens of
//! kilobytes and keeps every later transaction cheap.

use borsh::{BorshDeserialize, BorshSerialize};
use spel_framework::prelude::*;

/// Largest active oracle set this program indexes into.
pub const MAX_SET: usize = 1024;

/// Domain tag for a leaf of the membership tree.
pub const LEAF_TAG: u8 = 0;
/// Domain tag for an interior node of the membership tree.
pub const NODE_TAG: u8 = 1;

/// A price observation as it was finalized on Bedrock (RFC `PriceObservation`).
///
/// The signature covers the SHA-256 of the canonical encoding of the first six
/// fields; `merkle_proof` is a separate witness, outside the signature's scope.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Observation {
    pub feed_id: Vec<u8>,
    pub price: i64,
    pub decimals: i32,
    pub round: u64,
    pub timestamp: u64,
    /// The oracle's 32-byte BIP-340 x-only public key.
    pub oracle_id: Vec<u8>,
    /// 64-byte BIP-340 signature.
    pub signature: Vec<u8>,
    /// Leaf position in the membership tree.
    pub leaf_index: u32,
    /// Sibling hashes from leaf to root.
    pub merkle_proof: Vec<Vec<u8>>,
}

/// One indexer's delivery (RFC `DisputeSubmission`).
///
/// An indexer may split its delivery across several transactions; it still
/// counts once toward the quorum.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct DisputeSubmission {
    pub disputed_round: u64,
    pub sender_oracle_id: Vec<u8>,
    pub sender_signature: Vec<u8>,
    pub sender_leaf_index: u32,
    pub sender_merkle_proof: Vec<Vec<u8>>,
    pub observations: Vec<Observation>,
}

/// Persistent state, held in the `literal("lon_dispute")` PDA.
///
/// Deliberately small: prices plus two bitmaps, no observations.
#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct DisputeState {
    // ── configuration ────────────────────────────────────────────────
    /// `root_cycle` — the membership root frozen for the disputed round.
    pub membership_root: [u8; 32],
    /// Quorum `N`: distinct submitting indexers needed to trigger resolution.
    pub quorum_n: u16,
    /// Size of the active oracle set, which sizes the bitmaps.
    pub set_size: u32,
    /// Account allowed to write an attested price.
    pub proposer: [u8; 32],

    // ── optimistic path ──────────────────────────────────────────────
    pub disputed_round: u64,
    pub proposed_price: i64,
    pub decimals: i32,
    /// 1 while the dispute window accepts submissions.
    pub window_open: u8,

    // ── accumulation (everything here is verified) ───────────────────
    /// Prices of the observations accepted so far — the union, in arrival order.
    pub prices: Vec<i64>,
    /// Bit `i` set ⇒ an observation from set member `i` is already counted.
    pub observed_bitmap: Vec<u8>,
    /// Bit `i` set ⇒ set member `i` has submitted at least once this round.
    pub submitter_bitmap: Vec<u8>,
    /// Distinct submitting indexers so far.
    pub submitter_count: u16,
    /// Total `submit` transactions this round.
    pub submissions: u16,
    /// BIP-340 verifications performed this round, submitters and observations.
    pub verifications: u32,

    // ── resolution ───────────────────────────────────────────────────
    /// 0 = unresolved, 1 = dispute failed, 2 = dispute succeeded.
    pub outcome: u8,
    /// Observations that were accepted (== `prices.len()`).
    pub valid_count: u16,
    /// Median the contract computed itself.
    pub recomputed_price: i64,
    /// Set when the proposal did not match the recomputed median.
    pub proposer_slashable: u8,
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn bit_get(bitmap: &[u8], index: usize) -> bool {
    bitmap
        .get(index / 8)
        .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
}

fn bit_set(bitmap: &mut [u8], index: usize) {
    if let Some(byte) = bitmap.get_mut(index / 8) {
        *byte |= 1 << (index % 8);
    }
}

/// SHA-256 over the canonical encoding of an observation's signed fields.
///
/// Stands in for "the canonical serialization of fields 1 to 6" in the RFC.
/// `round` is inside the digest, so an old round's observations cannot be
/// replayed into a later one.
#[must_use]
pub fn observation_digest(
    feed_id: &[u8],
    price: i64,
    decimals: i32,
    round: u64,
    timestamp: u64,
    oracle_id: &[u8],
) -> [u8; 32] {
    sha256(&[
        b"LON:PriceObservation:v1",
        &(feed_id.len() as u32).to_le_bytes(),
        feed_id,
        &price.to_le_bytes(),
        &decimals.to_le_bytes(),
        &round.to_le_bytes(),
        &timestamp.to_le_bytes(),
        oracle_id,
    ])
}

/// What a disputing indexer signs, binding its submission to one round.
#[must_use]
pub fn submission_digest(disputed_round: u64, sender_oracle_id: &[u8]) -> [u8; 32] {
    sha256(&[
        b"LON:DisputeSubmission:v1",
        &disputed_round.to_le_bytes(),
        sender_oracle_id,
    ])
}

/// Verifies a BIP-340 Schnorr signature over `digest` under an x-only key.
pub fn verify_bip340(digest: &[u8; 32], xonly_pubkey: &[u8], signature: &[u8]) -> bool {
    use k256::schnorr::signature::Verifier;
    use k256::schnorr::{Signature, VerifyingKey};

    if xonly_pubkey.len() != 32 || signature.len() != 64 {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(xonly_pubkey) else {
        return false;
    };
    let Ok(sig) = Signature::try_from(signature) else {
        return false;
    };
    key.verify(digest, &sig).is_ok()
}

/// Walks a Merkle inclusion proof from the leaf up and compares with the root.
///
/// A passing proof is what authenticates `leaf_index`: the key and the position
/// are bound together by the tree, so the index can be used as an identity
/// afterwards.
#[must_use]
pub fn verify_membership(
    oracle_id: &[u8],
    leaf_index: u32,
    proof: &[Vec<u8>],
    root: &[u8; 32],
) -> bool {
    if oracle_id.len() != 32 || proof.len() > 32 {
        return false;
    }
    let mut node = sha256(&[&[LEAF_TAG], oracle_id]);
    let mut index = leaf_index;
    for sibling in proof {
        if sibling.len() != 32 {
            return false;
        }
        node = if index & 1 == 0 {
            sha256(&[&[NODE_TAG], &node, sibling])
        } else {
            sha256(&[&[NODE_TAG], sibling, &node])
        };
        index >>= 1;
    }
    node == *root
}

/// Median with the RFC's even-count rule: the lower of the two middle values,
/// so the result is always one of the observed prices and never an average.
#[must_use]
pub fn median_lower(values: &mut [i64]) -> i64 {
    values.sort_unstable();
    let len = values.len();
    if len % 2 == 1 {
        values[len / 2]
    } else {
        values[len / 2 - 1]
    }
}

fn load(account: &AccountWithMetadata) -> Result<DisputeState, SpelError> {
    let bytes: Vec<u8> = account.account.data.clone().into();
    borsh::from_slice(&bytes).map_err(|e| SpelError::DeserializationError {
        account_index: 0,
        message: e.to_string(),
    })
}

fn store(account: &mut AccountWithMetadata, state: &DisputeState) -> Result<(), SpelError> {
    let bytes = borsh::to_vec(state).map_err(|e| SpelError::SerializationError {
        message: e.to_string(),
    })?;
    let len = bytes.len();
    account.account.data = bytes.try_into().map_err(|_| SpelError::Custom {
        code: 1,
        message: format!("state is {len} bytes, over the account data limit"),
    })?;
    Ok(())
}

/// Computes the verdict once the quorum of distinct submitters is reached.
fn finish(state: &mut DisputeState) {
    state.window_open = 0;
    state.valid_count = u16::try_from(state.prices.len()).unwrap_or(u16::MAX);

    if state.prices.len() < usize::from(state.quorum_n) {
        state.outcome = 1;
        println!(
            "[resolve] round={} only {} valid observations for a quorum of {} — dispute invalid, proposed price stands",
            state.disputed_round, state.valid_count, state.quorum_n
        );
        return;
    }

    let mut prices = state.prices.clone();
    let recomputed = median_lower(&mut prices);
    state.recomputed_price = recomputed;

    if recomputed == state.proposed_price {
        state.outcome = 1;
        println!(
            "[resolve] round={} median {recomputed} over {} observations matches the proposal — dispute fails",
            state.disputed_round, state.valid_count
        );
    } else {
        state.outcome = 2;
        state.proposer_slashable = 1;
        println!(
            "[resolve] round={} median {recomputed} over {} observations != proposed {} — dispute succeeds, proposer slashable",
            state.disputed_round, state.valid_count, state.proposed_price
        );
    }
}

#[lez_program]
mod lon_dispute {

    /// Creates the dispute PDA and freezes the membership root, quorum and set size.
    #[instruction]
    pub fn initialize(
        #[account(init, pda = literal("lon_dispute"))] mut state: AccountWithMetadata,
        #[account(signer)] proposer: AccountWithMetadata,
        membership_root: Vec<u8>,
        quorum_n: u16,
        set_size: u32,
        decimals: i32,
    ) -> SpelResult {
        if membership_root.len() != 32 {
            return Err(SpelError::Custom {
                code: 2,
                message: "membership_root must be 32 bytes".to_string(),
            });
        }
        let set = usize::try_from(set_size).unwrap_or(usize::MAX);
        if set == 0 || set > MAX_SET {
            return Err(SpelError::Custom {
                code: 3,
                message: format!("set_size must be 1..={MAX_SET}"),
            });
        }
        if quorum_n == 0 || usize::from(quorum_n) > set {
            return Err(SpelError::Custom {
                code: 4,
                message: "quorum must be 1..=set_size".to_string(),
            });
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&membership_root);
        let bitmap_len = set.div_ceil(8);

        let fresh = DisputeState {
            membership_root: root,
            quorum_n,
            set_size,
            decimals,
            proposer: *proposer.account_id.value(),
            observed_bitmap: vec![0u8; bitmap_len],
            submitter_bitmap: vec![0u8; bitmap_len],
            ..DisputeState::default()
        };
        store(&mut state, &fresh)?;

        Ok(SpelOutput::execute(vec![state, proposer], vec![]))
    }

    /// The optimistic path: the proposer writes an attested price, unchecked.
    #[instruction]
    pub fn propose(
        #[account(mut, pda = literal("lon_dispute"))] mut state: AccountWithMetadata,
        #[account(signer)] proposer: AccountWithMetadata,
        round: u64,
        price: i64,
    ) -> SpelResult {
        let mut s = load(&state)?;

        if *proposer.account_id.value() != s.proposer {
            return Err(SpelError::Unauthorized {
                message: "only the proposer may attest a price".to_string(),
            });
        }
        if s.window_open == 1 {
            return Err(SpelError::Custom {
                code: 5,
                message: format!("round {} is still in its dispute window", s.disputed_round),
            });
        }

        let bitmap_len = usize::try_from(s.set_size).unwrap_or(0).div_ceil(8);
        s.disputed_round = round;
        s.proposed_price = price;
        s.window_open = 1;
        s.prices = Vec::new();
        s.observed_bitmap = vec![0u8; bitmap_len];
        s.submitter_bitmap = vec![0u8; bitmap_len];
        s.submitter_count = 0;
        s.submissions = 0;
        s.verifications = 0;
        s.outcome = 0;
        s.valid_count = 0;
        s.recomputed_price = 0;
        s.proposer_slashable = 0;

        println!(
            "[propose] round={round} price={price} (window open, quorum {} distinct indexers)",
            s.quorum_n
        );

        store(&mut state, &s)?;
        Ok(SpelOutput::execute(vec![state, proposer], vec![]))
    }

    /// An indexer delivers observations it read from Bedrock.
    ///
    /// `submission` is `borsh(DisputeSubmission)`. The submitter is
    /// authenticated, then every observation is verified before it is counted.
    /// Reaching the quorum of distinct submitters resolves the dispute in this
    /// same transaction.
    #[instruction]
    pub fn submit(
        #[account(mut, pda = literal("lon_dispute"))] mut state: AccountWithMetadata,
        #[account(signer)] relayer: AccountWithMetadata,
        submission: Vec<u8>,
    ) -> SpelResult {
        let mut s = load(&state)?;

        if s.window_open != 1 {
            return Err(SpelError::Custom {
                code: 6,
                message: "no open dispute window".to_string(),
            });
        }

        let sub: DisputeSubmission =
            borsh::from_slice(&submission).map_err(|e| SpelError::DeserializationError {
                account_index: 0,
                message: format!("submission: {e}"),
            })?;

        if sub.disputed_round != s.disputed_round {
            return Err(SpelError::Custom {
                code: 7,
                message: format!(
                    "submission targets round {}, the open round is {}",
                    sub.disputed_round, s.disputed_round
                ),
            });
        }

        // ── layer 1: the submitter ───────────────────────────────────
        let sender_digest = submission_digest(sub.disputed_round, &sub.sender_oracle_id);
        if !verify_bip340(&sender_digest, &sub.sender_oracle_id, &sub.sender_signature) {
            return Err(SpelError::Unauthorized {
                message: "submitter signature is invalid".to_string(),
            });
        }
        if !verify_membership(
            &sub.sender_oracle_id,
            sub.sender_leaf_index,
            &sub.sender_merkle_proof,
            &s.membership_root,
        ) {
            return Err(SpelError::Unauthorized {
                message: "submitter is not in the active oracle set".to_string(),
            });
        }
        s.verifications = s.verifications.saturating_add(1);

        let sender_slot = usize::try_from(sub.sender_leaf_index).unwrap_or(usize::MAX);
        if sender_slot >= usize::try_from(s.set_size).unwrap_or(0) {
            return Err(SpelError::Unauthorized {
                message: "submitter leaf index is outside the set".to_string(),
            });
        }

        // ── layer 2: the observations ────────────────────────────────
        let mut added = 0u32;
        for obs in sub.observations {
            let slot = usize::try_from(obs.leaf_index).unwrap_or(usize::MAX);
            if slot >= usize::try_from(s.set_size).unwrap_or(0) {
                continue;
            }
            // Already accounted for by an earlier indexer: skip without paying
            // for the verification. Skipping can only ever drop the caller's own
            // duplicate; nothing unverified can enter this way.
            if bit_get(&s.observed_bitmap, slot) {
                continue;
            }
            if obs.round != s.disputed_round || obs.decimals != s.decimals {
                continue;
            }

            let digest = observation_digest(
                &obs.feed_id,
                obs.price,
                obs.decimals,
                obs.round,
                obs.timestamp,
                &obs.oracle_id,
            );
            if !verify_bip340(&digest, &obs.oracle_id, &obs.signature) {
                continue;
            }
            s.verifications = s.verifications.saturating_add(1);
            if !verify_membership(
                &obs.oracle_id,
                obs.leaf_index,
                &obs.merkle_proof,
                &s.membership_root,
            ) {
                continue;
            }

            bit_set(&mut s.observed_bitmap, slot);
            s.prices.push(obs.price);
            added = added.saturating_add(1);
        }

        // An indexer that splits its delivery across transactions still counts once.
        let first_time = !bit_get(&s.submitter_bitmap, sender_slot);
        if first_time {
            bit_set(&mut s.submitter_bitmap, sender_slot);
            s.submitter_count = s.submitter_count.saturating_add(1);
        }
        s.submissions = s.submissions.saturating_add(1);

        println!(
            "[submit] round={} indexer={sender_slot}{} +{added} observations -> {} accepted, {}/{} indexers",
            s.disputed_round,
            if first_time { "" } else { " (repeat)" },
            s.prices.len(),
            s.submitter_count,
            s.quorum_n
        );

        if s.submitter_count >= s.quorum_n {
            finish(&mut s);
        }

        store(&mut state, &s)?;
        Ok(SpelOutput::execute(vec![state, relayer], vec![]))
    }
}
