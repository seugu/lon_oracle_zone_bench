//! Drives LON disputes against a single-node LEZ chain.
//!
//! Three rounds:
//!
//! 1. **Honest dispute.** The proposer attests a wrong price. `N` distinct
//!    indexers each push the round's finalized observations; the first delivery
//!    verifies them, the rest are recognised as already-counted and cost almost
//!    nothing. Reaching `N` distinct submitters resolves the dispute, the median
//!    is recomputed over the union, and the proposer is marked slashable.
//! 2. **Honest proposal.** Same delivery, correct proposal — the dispute fails
//!    and nothing is slashed.
//! 3. **Subset attack.** `N` colluding indexers deliver a deliberately
//!    incomplete set — the highest-priced observations only. Because resolution
//!    fires the moment `N` distinct submitters have spoken, honest indexers
//!    never get to put back what was left out, and the median is computed over
//!    the attacker's selection.
//!
//! Round 3 is the reason `N` matters: the submitter quorum only helps while the
//! adversary controls fewer than `N` seats. It is a demonstration, not a bug in
//! the program.
//!
//! `LON_QUORUM`, `LON_OBSERVERS`, `LON_SET` and `LON_BATCH` override defaults.

mod lez_node;

use anyhow::{bail, Context, Result};
use k256::schnorr::signature::Signer;
use k256::schnorr::{Signature, SigningKey};
use lez_node::{LezNode, Receipt};
use lon_sig_accum_program::{
    observation_digest, submission_digest, DisputeState, DisputeSubmission, Observation,
    LEAF_TAG, NODE_TAG,
};
use nssa::{AccountId, PrivateKey, PublicKey};
use risc0_binfmt::ProgramBinary;
use risc0_zkos_v1compat::V1COMPAT_ELF;
use sha2::{Digest, Sha256};
use spel_framework::pda::{compute_pda, seed_from_str};

const DEFAULT_SET: usize = 512;
/// Distinct indexers that must submit before resolution fires.
const DEFAULT_QUORUM: u16 = 50;
/// Oracle nodes that actually published an observation this round. Larger than
/// the quorum so an incomplete delivery is distinguishable from a complete one.
const DEFAULT_OBSERVERS: usize = 60;
/// Observations per `submit`. An indexer may split its delivery; it still
/// counts once toward the quorum.
const DEFAULT_BATCH: usize = 30;

const FEED_ID: &[u8] = b"BTC/USDT";
const DECIMALS: i32 = 6;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The active oracle set: a binary Merkle tree over the members' x-only keys.
struct OracleSet {
    keys: Vec<SigningKey>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl OracleSet {
    fn new(size: usize) -> Self {
        let keys: Vec<SigningKey> = (0..size)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                seed[0] = 0x4c;
                SigningKey::from_bytes(&seed).expect("valid scalar")
            })
            .collect();

        let mut levels = vec![keys
            .iter()
            .map(|k| sha256(&[&[LEAF_TAG], &k.verifying_key().to_bytes()]))
            .collect::<Vec<_>>()];
        while levels.last().expect("non-empty").len() > 1 {
            let prev = levels.last().expect("non-empty");
            levels.push(
                prev.chunks(2)
                    .map(|pair| sha256(&[&[NODE_TAG], &pair[0], &pair[1]]))
                    .collect(),
            );
        }
        Self { keys, levels }
    }

    fn root(&self) -> [u8; 32] {
        self.levels.last().expect("non-empty")[0]
    }

    fn oracle_id(&self, i: usize) -> Vec<u8> {
        self.keys[i].verifying_key().to_bytes().to_vec()
    }

    fn proof(&self, mut index: usize) -> Vec<Vec<u8>> {
        let mut path = Vec::new();
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[index ^ 1].to_vec());
            index >>= 1;
        }
        path
    }

    fn observation(&self, i: usize, round: u64, price: i64, timestamp: u64) -> Observation {
        let oracle_id = self.oracle_id(i);
        let digest = observation_digest(FEED_ID, price, DECIMALS, round, timestamp, &oracle_id);
        let sig: Signature = self.keys[i].sign(&digest);
        Observation {
            feed_id: FEED_ID.to_vec(),
            price,
            decimals: DECIMALS,
            round,
            timestamp,
            oracle_id,
            signature: sig.to_bytes().to_vec(),
            leaf_index: u32::try_from(i).expect("set stays small"),
            merkle_proof: self.proof(i),
        }
    }

    fn submission(
        &self,
        sender: usize,
        round: u64,
        observations: Vec<Observation>,
    ) -> DisputeSubmission {
        let sender_oracle_id = self.oracle_id(sender);
        let digest = submission_digest(round, &sender_oracle_id);
        let sig: Signature = self.keys[sender].sign(&digest);
        DisputeSubmission {
            disputed_round: round,
            sender_oracle_id,
            sender_signature: sig.to_bytes().to_vec(),
            sender_leaf_index: u32::try_from(sender).expect("set stays small"),
            sender_merkle_proof: self.proof(sender),
            observations,
        }
    }
}

fn load_program_binary() -> Result<(Vec<u8>, String)> {
    if let Ok(path) = std::env::var("LON_PROGRAM_BIN") {
        let bytes = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
        return Ok((bytes, format!("{path} (ProgramBinary)")));
    }
    let candidates = [
        std::env::var("LON_GUEST_ELF").unwrap_or_default(),
        "methods/guest/target/riscv32im-risc0-zkvm-elf/release/lon_sig_accum".to_string(),
        "methods/guest/target/riscv32im-risc0-zkvm-elf/docker/lon_sig_accum.bin".to_string(),
    ];
    for path in candidates.iter().filter(|p| !p.is_empty()) {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        if bytes.starts_with(b"R0BF") {
            return Ok((bytes, format!("{path} (ProgramBinary)")));
        }
        return Ok((
            ProgramBinary::new(&bytes, V1COMPAT_ELF).encode(),
            format!("{path} (raw ELF, wrapped here)"),
        ));
    }
    bail!("no guest binary found — run ./build_guest.sh, or set LON_GUEST_ELF / LON_PROGRAM_BIN")
}

fn read_state(node: &LezNode, pda: AccountId) -> Result<(DisputeState, usize)> {
    let data: Vec<u8> = node.account(pda).data.clone().into();
    if data.is_empty() {
        bail!("dispute state account is empty");
    }
    let len = data.len();
    Ok((borsh::from_slice(&data)?, len))
}

fn expect_ok(receipt: &Receipt) -> Result<()> {
    if !receipt.accepted {
        bail!(
            "{} was expected to succeed but failed: {}",
            receipt.label,
            receipt.error.clone().unwrap_or_default()
        );
    }
    match (receipt.cycles, receipt.budget_share()) {
        (Some(c), Some(share)) => println!(
            "  ✓ {} — accepted  [{c} cycles, {:.1}% of budget]",
            receipt.label,
            share * 100.0
        ),
        _ => println!("  ✓ {} — accepted", receipt.label),
    }
    Ok(())
}

fn expect_rejected(receipt: &Receipt, must_contain: &str) -> Result<()> {
    match (&receipt.accepted, &receipt.error) {
        (true, _) => bail!("{} was expected to be rejected but succeeded", receipt.label),
        (false, Some(err)) if err.contains(must_contain) => {
            println!("  ✓ {} — rejected ({must_contain})", receipt.label);
            Ok(())
        }
        (false, Some(err)) => bail!(
            "{} was rejected for the wrong reason.\n     expected to contain: {must_contain}\n     actual: {err}",
            receipt.label
        ),
        (false, None) => bail!("{} was rejected without an error", receipt.label),
    }
}

/// The observations the oracle nodes published for a round.
fn finalized_round(set: &OracleSet, round: u64, base: i64, observers: usize) -> Vec<Observation> {
    (0..observers)
        .map(|i| {
            // Spread the prices so a truncated set has a visibly different median.
            let drift = i as i64 - (observers as i64 / 2);
            set.observation(i, round, base + drift * 100_000, 1_755_600_000 + round)
        })
        .collect()
}

fn median_of(observations: &[Observation]) -> i64 {
    let mut prices: Vec<i64> = observations.iter().map(|o| o.price).collect();
    prices.sort_unstable();
    let len = prices.len();
    if len % 2 == 1 {
        prices[len / 2]
    } else {
        prices[len / 2 - 1]
    }
}

/// Every indexer in `senders` delivers `observations`, in batches of `batch`.
///
/// Resolution fires inside the transaction that reaches the quorum, which
/// closes the window. Anything still in flight after that is rejected — as it
/// would be on-chain — so delivery stops there.
#[allow(clippy::too_many_arguments)]
fn deliver(
    node: &mut LezNode,
    set: &OracleSet,
    state_pda: AccountId,
    relayer: &PrivateKey,
    relayer_id: AccountId,
    round: u64,
    senders: &[usize],
    observations: &[Observation],
    batch: usize,
    verbose_first: usize,
) -> Result<usize> {
    let mut txs = 0usize;
    for (n, &sender) in senders.iter().enumerate() {
        let mut sent = 0usize;
        while sent < observations.len() {
            let take = usize::min(batch, observations.len() - sent);
            let submission = set.submission(sender, round, observations[sent..sent + take].to_vec());
            let receipt = node.send(
                &format!("indexer {sender} delivers {take}"),
                vec![state_pda, relayer_id],
                relayer,
                lon_sig_accum_program::Instruction::Submit {
                    submission: borsh::to_vec(&submission)?,
                },
            );
            if n < verbose_first {
                expect_ok(&receipt)?;
            } else if !receipt.accepted {
                bail!(
                    "indexer {sender} delivery failed: {}",
                    receipt.error.clone().unwrap_or_default()
                );
            }
            txs += 1;
            sent += take;

            let (s, _) = read_state(node, state_pda)?;
            if s.window_open == 0 {
                if sent < observations.len() {
                    println!(
                        "     (quorum reached mid-delivery; indexer {sender}'s remaining batch is moot)"
                    );
                }
                return Ok(txs);
            }
        }
    }
    Ok(txs)
}

fn main() -> Result<()> {
    println!("═══ LON dispute resolution on LEZ ═══\n");

    let set_size = env_usize("LON_SET", DEFAULT_SET);
    let quorum = u16::try_from(env_usize("LON_QUORUM", DEFAULT_QUORUM as usize))?;
    let observers = env_usize("LON_OBSERVERS", DEFAULT_OBSERVERS);
    let batch = env_usize("LON_BATCH", DEFAULT_BATCH);
    let measure = std::env::var("LON_MEASURE").as_deref() != Ok("0");

    if observers < usize::from(quorum) {
        bail!("LON_OBSERVERS must be at least LON_QUORUM");
    }

    let (program_binary, source) = load_program_binary()?;
    println!("guest binary : {source}");

    let proposer = PrivateKey::try_new([7u8; 32])?;
    let proposer_id = AccountId::from(&PublicKey::new_from_private_key(&proposer));
    let relayer = PrivateKey::try_new([9u8; 32])?;
    let relayer_id = AccountId::from(&PublicKey::new_from_private_key(&relayer));

    let mut node = LezNode::boot(
        program_binary,
        &[(proposer_id, 1_000_000), (relayer_id, 1_000_000)],
        measure,
    )?;
    let program_id = node.program_id();
    let state_pda = compute_pda(&program_id, &[&seed_from_str("lon_dispute")]);

    let set = OracleSet::new(set_size);
    println!("state PDA    : {state_pda:?}");
    println!(
        "oracle set   : {set_size} members, Merkle depth {}",
        set.levels.len() - 1
    );
    println!("quorum N     : {quorum} distinct indexers");
    println!("observers    : {observers} published this round, {batch} per submit\n");

    let all_indexers: Vec<usize> = (0..usize::from(quorum)).collect();

    // ── setup ────────────────────────────────────────────────────────
    println!("── setup ──");
    let receipt = node.send(
        "initialize",
        vec![state_pda, proposer_id],
        &proposer,
        lon_sig_accum_program::Instruction::Initialize {
            membership_root: set.root().to_vec(),
            quorum_n: quorum,
            set_size: u32::try_from(set_size)?,
            decimals: DECIMALS,
        },
    );
    expect_ok(&receipt)?;

    // ── round 1: wrong proposal, honest delivery ─────────────────────
    let base = 94_123_550_000i64;
    let obs1 = finalized_round(&set, 1, base, observers);
    let true_median = median_of(&obs1);

    println!("\n── round 1: the proposer attests a wrong price ──");
    let wrong_price = true_median + 5_000_000;
    let receipt = node.send(
        "propose(round 1)",
        vec![state_pda, proposer_id],
        &proposer,
        lon_sig_accum_program::Instruction::Propose {
            round: 1,
            price: wrong_price,
        },
    );
    expect_ok(&receipt)?;
    println!("  true median over {observers} observations : {true_median}");
    println!("  proposed                                  : {wrong_price}");

    // ── guards ───────────────────────────────────────────────────────
    println!("\n── guards ──");
    let outsider = OracleSet::new(4);
    let forged = outsider.submission(0, 1, obs1[..1].to_vec());
    let receipt = node.send(
        "submit by a non-member",
        vec![state_pda, relayer_id],
        &relayer,
        lon_sig_accum_program::Instruction::Submit {
            submission: borsh::to_vec(&forged)?,
        },
    );
    expect_rejected(&receipt, "not in the active oracle set")?;

    // Junk signatures never enter the accumulator: verification happens on
    // arrival, so nothing unverified can occupy a slot or move the counter.
    // Sent by indexer 0, which will deliver honestly later — its second
    // submission is recognised as a repeat and does not count twice.
    let junk: Vec<Observation> = (0..observers)
        .map(|i| {
            let mut o = set.observation(i, 1, base, 1_755_600_001);
            o.signature = vec![0xAB; 64];
            o
        })
        .collect();
    let receipt = node.send(
        "submit with junk signatures",
        vec![state_pda, relayer_id],
        &relayer,
        lon_sig_accum_program::Instruction::Submit {
            submission: borsh::to_vec(&set.submission(0, 1, junk))?,
        },
    );
    expect_ok(&receipt)?;
    let (s, _) = read_state(&node, state_pda)?;
    if !s.prices.is_empty() {
        bail!("junk observations entered the accumulator");
    }
    println!("     ✓ 0 accepted — junk cannot occupy a slot");

    // ── round 1: N distinct indexers deliver ─────────────────────────
    println!("\n── round 1: {quorum} distinct indexers deliver the finalized set ──");
    let txs1 = deliver(
        &mut node, &set, state_pda, &relayer, relayer_id, 1, &all_indexers, &obs1, batch, 3,
    )?;

    let (s, bytes) = read_state(&node, state_pda)?;
    println!("\n── round 1: verdict ──");
    println!("  indexers     : {}/{}", s.submitter_count, s.quorum_n);
    println!("  submit txs   : {txs1}");
    println!("  observations : {}", s.valid_count);
    println!("  verifications: {} BIP-340 checks", s.verifications);
    println!("  state size   : {bytes} bytes");
    println!("  recomputed   : {}", s.recomputed_price);
    println!("  proposed     : {}", s.proposed_price);
    println!(
        "  outcome      : {}",
        if s.outcome == 2 { "dispute SUCCEEDED, proposer slashable" } else { "dispute failed" }
    );

    if s.outcome != 2 || s.proposer_slashable != 1 {
        bail!("a wrong proposal was not caught");
    }
    if s.recomputed_price != true_median {
        bail!("recomputed {} != true median {true_median}", s.recomputed_price);
    }
    if usize::from(s.valid_count) != observers {
        bail!("collected {} of {observers} observations", s.valid_count);
    }
    // One submitter check per submit transaction — including the rejected junk
    // one — plus one check per accepted observation. With every indexer sending
    // a single transaction this is the 2N the two-layer scheme implies.
    let submit_txs = txs1 + 1;
    let expected_verifications = submit_txs as u32 + observers as u32;
    if s.verifications != expected_verifications {
        bail!(
            "expected {expected_verifications} verifications ({submit_txs} submitters + {observers} observations), got {}",
            s.verifications
        );
    }
    println!(
        "  ratio        : {} checks = {submit_txs} submitters + {observers} observations",
        s.verifications
    );

    // ── round 2: honest proposal survives ────────────────────────────
    println!("\n── round 2: honest proposal ──");
    let obs2 = finalized_round(&set, 2, base + 400_000, observers);
    let median2 = median_of(&obs2);
    let receipt = node.send(
        "propose(round 2, correct median)",
        vec![state_pda, proposer_id],
        &proposer,
        lon_sig_accum_program::Instruction::Propose {
            round: 2,
            price: median2,
        },
    );
    expect_ok(&receipt)?;
    deliver(
        &mut node, &set, state_pda, &relayer, relayer_id, 2, &all_indexers, &obs2, batch, 0,
    )
    .map(|_| ())?;

    let (s, _) = read_state(&node, state_pda)?;
    if s.outcome != 1 || s.proposer_slashable != 0 {
        bail!("an honest proposal was slashed");
    }
    println!("  ✓ median {} matches the proposal — dispute fails, nothing slashed", s.recomputed_price);

    // ── round 3: the subset attack ───────────────────────────────────
    println!("\n── round 3: SUBSET ATTACK — {quorum} colluding indexers deliver an incomplete set ──");
    let obs3 = finalized_round(&set, 3, base + 900_000, observers);
    let honest_median3 = median_of(&obs3);

    let receipt = node.send(
        "propose(round 3, the honest median)",
        vec![state_pda, proposer_id],
        &proposer,
        lon_sig_accum_program::Instruction::Propose {
            round: 3,
            price: honest_median3,
        },
    );
    expect_ok(&receipt)?;

    // Keep only the highest-priced observations — all of them genuinely signed
    // by registered members, just not the whole set.
    let mut skewed = obs3.clone();
    skewed.sort_by_key(|o| -o.price);
    skewed.truncate(usize::from(quorum));
    let skewed_median = median_of(&skewed);
    println!("  honest median over {observers}         : {honest_median3}");
    println!("  attacker's median over its {quorum}    : {skewed_median}");

    deliver(
        &mut node, &set, state_pda, &relayer, relayer_id, 3, &all_indexers, &skewed, batch, 0,
    )
    .map(|_| ())?;

    let (s, _) = read_state(&node, state_pda)?;
    println!("  observations : {} (of {observers} finalized)", s.valid_count);
    println!("  recomputed   : {}", s.recomputed_price);
    println!(
        "  outcome      : {}",
        if s.outcome == 2 { "dispute SUCCEEDED, proposer slashable" } else { "dispute failed" }
    );
    if s.outcome != 2 || s.recomputed_price != skewed_median {
        bail!("the subset attack did not behave as the early-resolution rule implies");
    }
    println!("  ⚠ an honest proposer was slashed on a median the attacker chose.");
    println!("    Resolution fired the moment {quorum} distinct indexers had spoken, so no honest");
    println!("    indexer could put back the {} omitted observations.", observers - usize::from(quorum));
    println!("    Resolving at window close over the union instead would prevent this.");

    println!("\n═══ all checks passed ═══");
    Ok(())
}
