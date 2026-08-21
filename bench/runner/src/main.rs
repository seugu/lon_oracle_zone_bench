//! Measures the zkVM cost of the LON dispute-resolution workload.
//!
//! Builds a realistic active oracle set, signs one observation per member with
//! BIP-340, produces membership proofs against the set root, and executes the
//! benchmark guest for a range of batch sizes — reporting cycles against the
//! 32M public-execution budget.
//!
//! Usage:
//!   cargo run --release -p lon_bench_runner -- <path-to-guest-elf> [sizes...]

use anyhow::{bail, Context, Result};
use k256::ecdsa::SigningKey as EcdsaKey;
use k256::schnorr::SigningKey as SchnorrKey;
use lon_bench_common::{BenchInput, BenchObs, OP_ECDSA, OP_MERKLE, OP_SCHNORR};
use risc0_binfmt::ProgramBinary;
use risc0_zkos_v1compat::V1COMPAT_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use sha2::{Digest, Sha256};

/// Mirrors `MAX_NUM_CYCLES_PUBLIC_EXECUTION` in `lee::program`.
const BUDGET: u64 = 1024 * 1024 * 32;

/// Active oracle set size; the LON default is 500, so the tree has depth 9.
const SET_SIZE: usize = 512;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

/// A binary Merkle tree over the oracle public keys, domain-separated by level.
struct MembershipTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MembershipTree {
    fn new(leaves: &[[u8; 32]]) -> Self {
        let mut levels = vec![leaves
            .iter()
            .map(|pk| sha256(&[&[0u8], pk]))
            .collect::<Vec<_>>()];
        while levels.last().expect("non-empty").len() > 1 {
            let prev = levels.last().expect("non-empty");
            let next = prev
                .chunks(2)
                .map(|pair| sha256(&[&[1u8], &pair[0], &pair[1]]))
                .collect::<Vec<_>>();
            levels.push(next);
        }
        Self { levels }
    }

    fn root(&self) -> [u8; 32] {
        self.levels.last().expect("non-empty")[0]
    }

    fn path(&self, mut index: usize) -> Vec<Vec<u8>> {
        let mut path = Vec::new();
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = index ^ 1;
            path.push(level[sibling].to_vec());
            index >>= 1;
        }
        path
    }
}

fn load_program_binary(path: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    if bytes.starts_with(b"R0BF") {
        return Ok(bytes);
    }
    Ok(ProgramBinary::new(&bytes, V1COMPAT_ELF).encode())
}

fn build_observations(tree: &MembershipTree, members: &[(SchnorrKey, EcdsaKey)]) -> Vec<BenchObs> {
    use k256::schnorr::signature::Signer;
    use tiny_keccak::{Hasher, Keccak};

    members
        .iter()
        .enumerate()
        .map(|(i, (schnorr, ecdsa))| {
            // Stands in for SHA-256 over the canonical PriceObservation fields.
            let msg = sha256(&[b"PriceObservation", &(i as u64).to_le_bytes()]);

            let schnorr_sig: k256::schnorr::Signature = schnorr.sign(&msg);
            let (ecdsa_sig, rec_id) = ecdsa
                .sign_prehash_recoverable(&msg)
                .expect("prehash signing");

            let mut address = [0u8; 20];
            let mut hasher = Keccak::v256();
            hasher.update(&ecdsa.verifying_key().to_encoded_point(false).as_bytes()[1..]);
            let mut out = [0u8; 32];
            hasher.finalize(&mut out);
            address.copy_from_slice(&out[12..32]);

            BenchObs {
                msg: msg.to_vec(),
                xonly_pubkey: schnorr.verifying_key().to_bytes().to_vec(),
                schnorr_sig: schnorr_sig.to_bytes().to_vec(),
                ecdsa_sig: ecdsa_sig.to_bytes().to_vec(),
                ecdsa_rec_id: rec_id.to_byte(),
                ecdsa_address: address.to_vec(),
                leaf_index: u32::try_from(i).expect("set stays small"),
                merkle_path: tree.path(i),
            }
        })
        .collect()
}

fn run(elf: &[u8], input: &BenchInput) -> Result<u64> {
    let bytes = borsh::to_vec(input)?;
    let env = ExecutorEnv::builder()
        .write(&bytes)?
        // Deliberately above the LEZ budget so oversized batches still report a
        // number instead of aborting.
        .session_limit(Some(BUDGET * 16))
        .build()?;
    let session = default_executor().execute(env, elf)?;
    Ok(session.cycles())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(elf_path) = args.next() else {
        bail!("usage: lon_bench_runner <guest-elf> [batch sizes...]");
    };
    let sizes: Vec<usize> = {
        let rest: Vec<usize> = args.filter_map(|a| a.parse().ok()).collect();
        if rest.is_empty() {
            vec![0, 1, 2, 5, 10, 25, 50]
        } else {
            rest
        }
    };

    let elf = load_program_binary(&elf_path)?;
    println!("guest    : {elf_path}");
    println!("budget   : {BUDGET} cycles (MAX_NUM_CYCLES_PUBLIC_EXECUTION)");
    println!("set size : {SET_SIZE} (Merkle depth {})\n", SET_SIZE.trailing_zeros());

    // Deterministic key material keeps the run reproducible.
    let members: Vec<(SchnorrKey, EcdsaKey)> = (0..SET_SIZE)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            seed[0] = 0x4c;
            (
                SchnorrKey::from_bytes(&seed).expect("valid scalar"),
                EcdsaKey::from_slice(&seed).expect("valid scalar"),
            )
        })
        .collect();

    let leaves: Vec<[u8; 32]> = members
        .iter()
        .map(|(s, _)| {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&s.verifying_key().to_bytes());
            pk
        })
        .collect();
    let tree = MembershipTree::new(&leaves);
    let observations = build_observations(&tree, &members);

    let cases: [(&str, u8); 4] = [
        ("merkle only", OP_MERKLE),
        ("BIP-340 only", OP_SCHNORR),
        ("BIP-340 + merkle", OP_SCHNORR | OP_MERKLE),
        ("ECDSA recover only", OP_ECDSA),
    ];

    for (label, op) in cases {
        println!("── {label} ──");
        println!("{:>6}  {:>12}  {:>9}  {:>14}", "n", "cycles", "budget", "per obs");
        let mut baseline = 0u64;
        for (i, &n) in sizes.iter().enumerate() {
            let input = BenchInput {
                op,
                merkle_root: tree.root().to_vec(),
                observations: observations[..n].to_vec(),
            };
            let cycles = run(&elf, &input)?;
            if i == 0 && n == 0 {
                baseline = cycles;
            }
            let per = if n > 0 {
                format!("{}", (cycles.saturating_sub(baseline)) / n as u64)
            } else {
                "-".to_string()
            };
            println!(
                "{n:>6}  {cycles:>12}  {:>8.1}%  {per:>14}",
                cycles as f64 / BUDGET as f64 * 100.0
            );
        }
        println!();
    }

    Ok(())
}
