//! Payload shared between the benchmark guest and its host runner.
//!
//! Kept in its own crate so the guest and the runner cannot drift.

use borsh::{BorshDeserialize, BorshSerialize};

/// Work the guest should perform, as a bit set.
pub const OP_SCHNORR: u8 = 1; // BIP-340 verification, as LON specifies
pub const OP_MERKLE: u8 = 2; // membership proof against the set root
pub const OP_ECDSA: u8 = 4; // secp256k1 recovery, for comparison

/// One observation's worth of verification work.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BenchObs {
    /// SHA-256 of the canonical observation bytes — what the oracle signs.
    pub msg: Vec<u8>,
    /// BIP-340 x-only public key (32 bytes) — the `oracle_id`.
    pub xonly_pubkey: Vec<u8>,
    /// BIP-340 signature (64 bytes).
    pub schnorr_sig: Vec<u8>,
    /// Compact secp256k1 ECDSA signature (64 bytes) over `msg`.
    pub ecdsa_sig: Vec<u8>,
    /// ECDSA recovery id.
    pub ecdsa_rec_id: u8,
    /// Ethereum-style address expected from the ECDSA recovery.
    pub ecdsa_address: Vec<u8>,
    /// Index of this oracle's leaf in the membership tree.
    pub leaf_index: u32,
    /// Sibling hashes from leaf to root.
    pub merkle_path: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BenchInput {
    pub op: u8,
    /// Membership tree root the proofs are checked against.
    pub merkle_root: Vec<u8>,
    pub observations: Vec<BenchObs>,
}
