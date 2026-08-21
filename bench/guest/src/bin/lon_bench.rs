//! Cycle benchmark for the LON dispute-resolution workload.
//!
//! Performs, per observation, the verification the LEZ contract must do when a
//! dispute is resolved: a BIP-340 Schnorr check against the oracle's own key,
//! and a Merkle membership check against the active-set root. secp256k1 ECDSA
//! recovery is included as a comparison point.
#![no_main]

use lon_bench_common::{BenchInput, OP_ECDSA, OP_MERKLE, OP_SCHNORR};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

fn main() {
    let bytes: Vec<u8> = env::read();
    let input: BenchInput = borsh::from_slice(&bytes).expect("payload");

    let mut accepted = 0u32;

    for obs in &input.observations {
        if input.op & OP_SCHNORR != 0 {
            use k256::schnorr::{Signature, VerifyingKey};
            use k256::schnorr::signature::Verifier;

            let vk = VerifyingKey::from_bytes(&obs.xonly_pubkey).expect("x-only key");
            let sig = Signature::try_from(obs.schnorr_sig.as_slice()).expect("schnorr sig");
            vk.verify(&obs.msg, &sig).expect("BIP-340 verification");
            accepted += 1;
        }

        if input.op & OP_ECDSA != 0 {
            use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
            use tiny_keccak::{Hasher, Keccak};

            let digest: [u8; 32] = obs.msg.as_slice().try_into().expect("32-byte digest");
            let rec = RecoveryId::from_byte(obs.ecdsa_rec_id).expect("recovery id");
            let sig = Signature::from_slice(&obs.ecdsa_sig).expect("ecdsa sig");
            let key = VerifyingKey::recover_from_prehash(&digest, &sig, rec).expect("recover");

            let mut hasher = Keccak::v256();
            hasher.update(&key.to_encoded_point(false).as_bytes()[1..]);
            let mut out = [0u8; 32];
            hasher.finalize(&mut out);
            assert_eq!(&out[12..32], obs.ecdsa_address.as_slice(), "address");
            accepted += 1;
        }

        if input.op & OP_MERKLE != 0 {
            // Leaf commits to the oracle_id; nodes are ordered by the path bit.
            let mut node = sha256(&[&[0u8], obs.xonly_pubkey.as_slice()]);
            let mut index = obs.leaf_index;
            for sibling in &obs.merkle_path {
                node = if index & 1 == 0 {
                    sha256(&[&[1u8], &node, sibling])
                } else {
                    sha256(&[&[1u8], sibling, &node])
                };
                index >>= 1;
            }
            assert_eq!(node.as_slice(), input.merkle_root.as_slice(), "membership");
            accepted += 1;
        }
    }

    env::commit(&accepted);
}
