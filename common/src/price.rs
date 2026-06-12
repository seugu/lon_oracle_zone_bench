//! Signed price records.
//!
//! Each oracle user holds a secp256k1 key pair and signs every price
//! observation it submits. The indexer verifies these signatures before any
//! aggregation; an unverifiable record never influences the attested price.
//!
//! Cryptographic notes (staff-engineer checklist):
//! - Curve/scheme: secp256k1 ECDSA via `k256`, matching the LEZ signature
//!   benchmark so cycle/throughput comparisons stay apples-to-apples.
//! - Nonces: `k256` signs with RFC 6979 deterministic nonces — no RNG misuse
//!   risk at signing time.
//! - Domain separation: the signed digest is `SHA-256(DOMAIN_TAG || pair ||
//!   price || timestamp_ms || nonce)`. The tag prevents cross-protocol replay
//!   (a signature produced here can never validate as some other message in
//!   another Logos context, and vice versa).
//! - Replay within the protocol: the random `nonce` makes each record unique; a production
//!   zone would additionally bind a round/sequence number and enforce
//!   staleness windows on `timestamp_ms` (the indexer demo keeps records only
//!   within its 5 s heartbeat window, which bounds replay usefulness).
//! - Malleability: ECDSA signatures are encoded as DER. We do not enforce
//!   low-S here because the signature is an authenticity check, not a
//!   consensus identifier; a production chain integration should normalize to
//!   low-S before using signatures as unique IDs.

use k256::ecdsa::signature::{Signer as _, Verifier as _};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Domain-separation tag, versioned. Changing the record layout must bump it.
const DOMAIN_TAG: &[u8] = b"LON-ORACLE-PRICE-V1";

/// Price scale: prices are integers in **cents** (1e2). 65_000_00 = 65000.00.
pub const PRICE_SCALE: u64 = 100;

/// A single signed price observation from one oracle user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceRecord {
    /// Trading pair, e.g. "BTC/USDT".
    pub pair: String,
    /// Price in cents (see [`PRICE_SCALE`]).
    pub price: u64,
    /// Observation time, Unix milliseconds.
    pub timestamp_ms: u64,
    /// Per-record random nonce (16 bytes, hex): makes identical observations
    /// distinct and bounds trivial replays.
    pub nonce: String,
    /// SEC1 compressed public key, hex.
    pub pubkey: String,
    /// DER ECDSA signature, hex.
    pub signature: String,
}

impl PriceRecord {
    /// Canonical digest that is signed/verified. Deterministic across all
    /// parties; any field change invalidates the signature.
    fn digest(pair: &str, price: u64, timestamp_ms: u64, nonce: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_TAG);
        h.update((pair.len() as u32).to_be_bytes()); // length-prefix the only
        h.update(pair.as_bytes()); //                   variable-length field
        h.update(price.to_be_bytes());
        h.update(timestamp_ms.to_be_bytes());
        h.update(nonce.as_bytes());
        h.finalize().into()
    }

    /// Build and sign a record.
    pub fn signed(
        signing_key: &SigningKey,
        pair: impl Into<String>,
        price: u64,
        timestamp_ms: u64,
    ) -> Self {
        let pair = pair.into();
        let nonce = random_nonce();
        let digest = Self::digest(&pair, price, timestamp_ms, &nonce);
        let signature: Signature = signing_key.sign(&digest);
        let verifying_key = VerifyingKey::from(signing_key);
        Self {
            pair,
            price,
            timestamp_ms,
            nonce,
            pubkey: hex::encode(verifying_key.to_encoded_point(true).as_bytes()),
            signature: hex::encode(signature.to_der().as_bytes()),
        }
    }

    /// Verify the embedded signature. Returns the verifying key so callers can
    /// additionally check set membership (permissioned list / stake registry).
    pub fn verify(&self) -> Result<VerifyingKey, VerifyError> {
        let pk = hex::decode(&self.pubkey).map_err(|_| VerifyError::BadEncoding)?;
        let sig = hex::decode(&self.signature).map_err(|_| VerifyError::BadEncoding)?;
        let vk = VerifyingKey::from_sec1_bytes(&pk).map_err(|_| VerifyError::BadKey)?;
        let sig = Signature::from_der(&sig).map_err(|_| VerifyError::BadSignature)?;
        let digest = Self::digest(&self.pair, self.price, self.timestamp_ms, &self.nonce);
        vk.verify(&digest, &sig)
            .map_err(|_| VerifyError::VerificationFailed)?;
        Ok(vk)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("PriceRecord is always serializable")
    }

    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("hex encoding of pubkey or signature is invalid")]
    BadEncoding,
    #[error("public key is not a valid secp256k1 point")]
    BadKey,
    #[error("signature bytes are not valid DER")]
    BadSignature,
    #[error("signature does not verify")]
    VerificationFailed,
}

/// 16 random bytes from OS entropy, hex-encoded.
pub fn random_nonce() -> String {
    use rand::RngCore as _;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Fresh random signing key (OS entropy).
pub fn random_signing_key() -> SigningKey {
    SigningKey::random(&mut rand::rngs::OsRng)
}

/// Render cents as a human price string.
pub fn fmt_price(cents: u64) -> String {
    format!("{}.{:02}", cents / PRICE_SCALE, cents % PRICE_SCALE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = random_signing_key();
        let r = PriceRecord::signed(&sk, "BTC/USDT", 65_000_00, 1_700_000_000_000);
        assert!(r.verify().is_ok());
    }

    #[test]
    fn any_field_tamper_fails() {
        let sk = random_signing_key();
        let base = PriceRecord::signed(&sk, "BTC/USDT", 65_000_00, 1_700_000_000_000);

        let mut t = base.clone();
        t.price += 1;
        assert!(t.verify().is_err(), "price tamper must fail");

        let mut t = base.clone();
        t.pair = "ETH/USDT".into();
        assert!(t.verify().is_err(), "pair tamper must fail");

        let mut t = base.clone();
        t.timestamp_ms += 1;
        assert!(t.verify().is_err(), "timestamp tamper must fail");

        let mut t = base;
        t.nonce = random_nonce();
        assert!(t.verify().is_err(), "nonce tamper must fail");
    }

    #[test]
    fn signature_is_not_transplantable() {
        // A signature from one key must not verify under another pubkey.
        let a = random_signing_key();
        let b = random_signing_key();
        let ra = PriceRecord::signed(&a, "BTC/USDT", 65_000_00, 1);
        let rb = PriceRecord::signed(&b, "BTC/USDT", 65_000_00, 1);
        let mut frankenstein = ra;
        frankenstein.pubkey = rb.pubkey;
        assert!(frankenstein.verify().is_err());
    }

    #[test]
    fn json_roundtrip_preserves_validity() {
        let sk = random_signing_key();
        let r = PriceRecord::signed(&sk, "BTC/USDT", 64_123_45, 1_700_000_000_000);
        let back = PriceRecord::from_json(&r.to_json()).unwrap();
        assert!(back.verify().is_ok());
        assert_eq!(back.price, 64_123_45);
    }

    #[test]
    fn fmt_price_renders_cents() {
        assert_eq!(fmt_price(65_000_00), "65000.00");
        assert_eq!(fmt_price(64_123_45), "64123.45");
        assert_eq!(fmt_price(5), "0.05");
    }
}
