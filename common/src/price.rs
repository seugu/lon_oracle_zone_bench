use k256::ecdsa::signature::{Signer as _, Verifier as _};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceRecord {
    pub pair: String,
    pub price: u64,
    pub timestamp: u64,
    pub uuid: Uuid,
    pub pubkey: String,
    pub signature: String,
}

impl PriceRecord {
    fn signing_bytes(pair: &str, price: u64, timestamp: u64, uuid: &Uuid) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(pair.as_bytes());
        hasher.update(price.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(uuid.as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn signed(signing_key: &SigningKey, pair: impl Into<String>, price: u64, timestamp: u64) -> Self {
        let pair = pair.into();
        let uuid = Uuid::new_v4();
        let msg = Self::signing_bytes(&pair, price, timestamp, &uuid);
        let signature: Signature = signing_key.sign(&msg);
        let verifying_key = VerifyingKey::from(signing_key);
        Self {
            pair,
            price,
            timestamp,
            uuid,
            pubkey: hex::encode(verifying_key.to_encoded_point(true).as_bytes()),
            signature: hex::encode(signature.to_der().as_bytes()),
        }
    }

    pub fn verify(&self) -> Result<VerifyingKey, VerifyError> {
        let pubkey_bytes = hex::decode(&self.pubkey).map_err(|_| VerifyError::BadEncoding)?;
        let sig_bytes = hex::decode(&self.signature).map_err(|_| VerifyError::BadEncoding)?;
        let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes).map_err(|_| VerifyError::BadKey)?;
        let signature = Signature::from_der(&sig_bytes).map_err(|_| VerifyError::BadSignature)?;
        let msg = Self::signing_bytes(&self.pair, self.price, self.timestamp, &self.uuid);
        verifying_key.verify(&msg, &signature).map_err(|_| VerifyError::VerificationFailed)?;
        Ok(verifying_key)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("PriceRecord serialization should not fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("hex encoding invalid")]
    BadEncoding,
    #[error("invalid public key")]
    BadKey,
    #[error("invalid signature bytes")]
    BadSignature,
    #[error("signature verification failed")]
    VerificationFailed,
}

pub fn median(prices: &[u64]) -> Option<u64> {
    if prices.is_empty() { return None; }
    let mut sorted = prices.to_vec();
    sorted.sort_unstable();
    Some(sorted[(sorted.len() - 1) / 2])
}

pub fn random_signing_key() -> SigningKey {
    SigningKey::random(&mut rand::rngs::OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = random_signing_key();
        let rec = PriceRecord::signed(&sk, "BTC/USD", 65_000_00000000, 1_700_000_000);
        assert!(rec.verify().is_ok());
    }

    #[test]
    fn tampered_price_fails_verification() {
        let sk = random_signing_key();
        let mut rec = PriceRecord::signed(&sk, "BTC/USD", 65_000_00000000, 1_700_000_000);
        rec.price += 1;
        assert!(rec.verify().is_err());
    }

    #[test]
    fn median_odd_and_even() {
        assert_eq!(median(&[3, 1, 2]), Some(2));
        assert_eq!(median(&[4, 1, 3, 2]), Some(2));
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn json_roundtrip() {
        let sk = random_signing_key();
        let rec = PriceRecord::signed(&sk, "ETH/USD", 3_200_00000000, 1_700_000_001);
        let back = PriceRecord::from_bytes(&rec.to_bytes()).unwrap();
        assert!(back.verify().is_ok());
    }
}
