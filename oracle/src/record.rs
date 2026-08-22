//! The Oracle Zone wire format and its BIP-340 attestation.
//!
//! Layout of what an oracle node writes into its channel, per the LON Oracle
//! Zone draft spec (Borsh-serialisable `{ pair, price, timestamp,
//! writer_pubkey, signature }`):
//!
//! ```text
//! OracleEnvelope
//!   magic:   b"LON1"                       -- cheap non-oracle-traffic filter
//!   version: 1
//!   message: OracleMessage
//!              | Announce(OracleAnnounce)  -- channel genesis, binds the keys
//!              | Price(SignedPriceRecord)  -- { record, signature }
//! ```
//!
//! [`SignedPriceRecord`] flattens to exactly the five fields the spec names:
//! `record` carries `pair`, `price`, `timestamp` and `writer_pubkey`, and the
//! detached `signature` is the BIP-340 signature over it. Keeping the
//! signature outside the signed struct is what makes the signing pre-image
//! unambiguous — the bytes that get hashed are precisely
//! `borsh(PriceRecord)`, with nothing to zero out first.
//!
//! # What is signed
//!
//! BIP-340 (Schnorr over secp256k1, x-only public keys). The message handed
//! to the signer is a BIP-340 style tagged hash of the Borsh encoding of the
//! record:
//!
//! ```text
//! tag = "LON/oracle-price-record/v1"
//! e   = SHA256( SHA256(tag) || SHA256(tag) || borsh(PriceRecord) )
//! sig = schnorr_sign(e, oracle_secret_key)          // 64 bytes, R||s
//! ```
//!
//! Tagging is what stops a signature produced here from ever being replayed
//! as a signature over some other protocol's 32-byte digest. Signing is done
//! with `sign_schnorr_no_aux_rand`, i.e. `aux_rand = 0`, so the same record
//! always yields the same signature and a re-published (orphaned) inscription
//! is byte-identical to the original.

use borsh::{BorshDeserialize, BorshSerialize};
use secp256k1::{Keypair, Secp256k1, SignOnly, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest as _, Sha256};

/// Magic prefix on every oracle inscription.
pub const MAGIC: [u8; 4] = *b"LON1";

/// Wire format version.
pub const VERSION: u8 = 1;

/// BIP-340 tag for the price-record signing pre-image.
pub const PRICE_RECORD_TAG: &[u8] = b"LON/oracle-price-record/v1";

/// BIP-340 tag for the announcement signing pre-image.
pub const ANNOUNCE_TAG: &[u8] = b"LON/oracle-announce/v1";

/// Domain separator for deriving a channel id from an oracle's key pair.
pub const CHANNEL_ID_TAG: &[u8] = b"LON/oracle-channel-id/v1";

/// The price this node publishes.
///
/// Hardcoded on purpose: this build attests to a fixed value so that the
/// channel, the single-writer rule and the BIP-340 attestation can be
/// verified end-to-end on the public testnet without a price source in the
/// loop. A production node would replace the price source rather than this
/// constant.
pub const HARDCODED_PRICE: u64 = 9_412_345_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("borsh codec error: {0}")]
    Borsh(#[from] std::io::Error),
    #[error("bad magic: expected {expected:?}, got {actual:?}")]
    BadMagic { expected: [u8; 4], actual: [u8; 4] },
    #[error("unsupported wire version {0}")]
    BadVersion(u8),
    #[error("trailing bytes after envelope ({0} byte(s))")]
    TrailingBytes(usize),
    #[error("invalid x-only public key: {0}")]
    PublicKey(secp256k1::Error),
    #[error("BIP-340 signature verification failed: {0}")]
    Signature(secp256k1::Error),
    #[error("record is signed by {actual}, expected the channel owner {expected}")]
    WrongWriter { expected: String, actual: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// The signed part of a price submission — the spec's `{ pair, price,
/// timestamp, writer_pubkey }`.
///
/// Field order is the Borsh encoding order and is consensus-relevant for the
/// signature: changing it changes every pre-image. Bump [`VERSION`] if it
/// ever has to move.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct PriceRecord {
    /// Feed identifier, e.g. `"BTC/USD"`.
    pub pair: String,
    /// Price as a fixed-point integer, scaled by `10^decimals`.
    pub price: u64,
    /// Number of decimal places `price` is scaled by.
    pub decimals: u8,
    /// Oracle-local observation time, Unix seconds.
    ///
    /// Advisory only. The spec requires aggregation windows to be defined by
    /// inscription order or block height, never by this field — it is not
    /// consensus input, it is provenance.
    pub timestamp: u64,
    /// BIP-340 x-only public key of the oracle that signed this record.
    pub writer_pubkey: [u8; 32],
}

impl PriceRecord {
    /// The exact bytes that get hashed and signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(borsh::to_vec(self)?)
    }

    /// The BIP-340 message: a tagged hash of [`Self::signing_bytes`].
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        Ok(tagged_hash(PRICE_RECORD_TAG, &self.signing_bytes()?))
    }

    /// The price rendered with its decimal point, for logs and humans.
    #[must_use]
    pub fn display_price(&self) -> String {
        format_scaled(self.price, self.decimals)
    }
}

/// A [`PriceRecord`] plus its detached BIP-340 signature.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SignedPriceRecord {
    pub record: PriceRecord,
    /// 64-byte BIP-340 signature (`R.x || s`) over
    /// [`PriceRecord::signing_digest`].
    pub signature: [u8; 64],
}

impl SignedPriceRecord {
    /// Verifies the signature against the key named inside the record.
    ///
    /// This proves the record is self-consistent. It does **not** prove the
    /// signer is allowed to write here — bind the key to the channel with
    /// [`Self::verify_from`].
    pub fn verify(&self) -> Result<XOnlyPublicKey> {
        let pubkey =
            XOnlyPublicKey::from_byte_array(self.record.writer_pubkey).map_err(Error::PublicKey)?;
        let digest = self.record.signing_digest()?;
        let signature = Signature::from_byte_array(self.signature);

        Secp256k1::verification_only()
            .verify_schnorr(&signature, &digest, &pubkey)
            .map_err(Error::Signature)?;

        Ok(pubkey)
    }

    /// Verifies the signature *and* that it was made by `expected`.
    ///
    /// `expected` is the oracle key the channel is bound to, so a valid
    /// signature from some other oracle is still rejected here.
    pub fn verify_from(&self, expected: &XOnlyPublicKey) -> Result<()> {
        let actual = self.verify()?;
        if &actual == expected {
            Ok(())
        } else {
            Err(Error::WrongWriter {
                expected: hex::encode(expected.serialize()),
                actual: hex::encode(actual.serialize()),
            })
        }
    }
}

/// The first message an oracle writes to its channel.
///
/// Publishing it is what creates the channel on Bedrock, which is also what
/// makes the publishing Ed25519 key the channel's sole accredited key. The
/// announcement records, in the log itself, which BIP-340 key the reader
/// should expect on every subsequent price record, and which Ed25519 key owns
/// the channel — so an indexer can bind both from the log alone.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct AnnounceBody {
    /// BIP-340 x-only attestation key of this oracle.
    pub writer_pubkey: [u8; 32],
    /// Ed25519 channel key that signs this channel's inscriptions on Bedrock.
    pub channel_pubkey: [u8; 32],
    /// The feed this channel carries.
    pub pair: String,
    /// Decimal scale used by every price record on this channel.
    pub decimals: u8,
    /// Announcement time, Unix seconds.
    pub timestamp: u64,
}

impl AnnounceBody {
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        Ok(tagged_hash(ANNOUNCE_TAG, &borsh::to_vec(self)?))
    }
}

/// An [`AnnounceBody`] plus its detached BIP-340 signature.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct OracleAnnounce {
    pub body: AnnounceBody,
    pub signature: [u8; 64],
}

impl OracleAnnounce {
    pub fn verify(&self) -> Result<XOnlyPublicKey> {
        let pubkey =
            XOnlyPublicKey::from_byte_array(self.body.writer_pubkey).map_err(Error::PublicKey)?;
        let digest = self.body.signing_digest()?;
        let signature = Signature::from_byte_array(self.signature);

        Secp256k1::verification_only()
            .verify_schnorr(&signature, &digest, &pubkey)
            .map_err(Error::Signature)?;

        Ok(pubkey)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum OracleMessage {
    Announce(OracleAnnounce),
    Price(SignedPriceRecord),
}

/// What actually goes into an inscription.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct OracleEnvelope {
    pub magic: [u8; 4],
    pub version: u8,
    pub message: OracleMessage,
}

impl OracleEnvelope {
    #[must_use]
    pub const fn new(message: OracleMessage) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            message,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(borsh::to_vec(self)?)
    }

    /// Decodes an inscription payload, rejecting anything that is not ours.
    ///
    /// Borsh is not self-describing, so a foreign payload can decode into
    /// nonsense rather than failing. The magic and version guards, plus the
    /// trailing-byte check, are what make a decode failure loud instead of
    /// silent.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = bytes;
        let envelope = Self::deserialize(&mut cursor)?;

        if envelope.magic != MAGIC {
            return Err(Error::BadMagic {
                expected: MAGIC,
                actual: envelope.magic,
            });
        }
        if envelope.version != VERSION {
            return Err(Error::BadVersion(envelope.version));
        }
        if !cursor.is_empty() {
            return Err(Error::TrailingBytes(cursor.len()));
        }

        Ok(envelope)
    }
}

/// Signs a price record with the oracle's BIP-340 key.
///
/// `writer_pubkey` is overwritten with the key that actually signs, so a
/// record can never name a key other than its signer.
pub fn sign_price_record(
    secp: &Secp256k1<SignOnly>,
    keypair: &Keypair,
    mut record: PriceRecord,
) -> Result<SignedPriceRecord> {
    let (xonly, _parity) = keypair.x_only_public_key();
    record.writer_pubkey = xonly.serialize();

    let digest = record.signing_digest()?;
    let signature = secp.sign_schnorr_no_aux_rand(&digest, keypair);

    Ok(SignedPriceRecord {
        record,
        signature: signature.to_byte_array(),
    })
}

/// Signs a channel announcement with the oracle's BIP-340 key.
pub fn sign_announce(
    secp: &Secp256k1<SignOnly>,
    keypair: &Keypair,
    mut body: AnnounceBody,
) -> Result<OracleAnnounce> {
    let (xonly, _parity) = keypair.x_only_public_key();
    body.writer_pubkey = xonly.serialize();

    let digest = body.signing_digest()?;
    let signature = secp.sign_schnorr_no_aux_rand(&digest, keypair);

    Ok(OracleAnnounce {
        body,
        signature: signature.to_byte_array(),
    })
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
#[must_use]
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash: [u8; 32] = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Renders a fixed-point integer with its decimal point.
#[must_use]
pub fn format_scaled(value: u64, decimals: u8) -> String {
    let decimals = usize::from(decimals);
    if decimals == 0 {
        return value.to_string();
    }

    let digits = format!("{value:0>width$}", width = decimals + 1);
    // ASCII digits only, so the split point is always a char boundary.
    let (integer_part, fractional_part) = digits.split_at(digits.len() - decimals);
    format!("{integer_part}.{fractional_part}")
}

#[cfg(test)]
mod tests {
    use secp256k1::SecretKey;

    use super::*;

    fn keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::signing_only();
        let secret = SecretKey::from_byte_array([seed; 32]).expect("valid scalar");
        Keypair::from_secret_key(&secp, &secret)
    }

    /// The BIP-340 primitives this crate signs with, checked against the
    /// official vectors from the BIP itself
    /// (<https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv>).
    /// Vectors 0-3 sign with `aux_rand`, which is exactly what
    /// `sign_schnorr_with_aux_rand` takes; the all-zero `aux_rand` of vector
    /// 0 is also what `sign_schnorr_no_aux_rand` uses, so that one pins the
    /// deterministic signing path this crate actually calls.
    #[test]
    fn bip340_official_signing_vectors() {
        // (secret key, public key, aux_rand, message, expected signature)
        const VECTORS: [(&str, &str, &str, &str, &str); 4] = [
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            ),
            (
                "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            ),
            (
                "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
                "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
                "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
                "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
                "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            ),
            (
                "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
                "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            ),
        ];

        let secp = Secp256k1::new();

        for (index, (sk_hex, pk_hex, aux_hex, msg_hex, sig_hex)) in VECTORS.iter().enumerate() {
            let sk_bytes: [u8; 32] = hex_array(sk_hex);
            let aux: [u8; 32] = hex_array(aux_hex);
            let msg: [u8; 32] = hex_array(msg_hex);
            let expected_sig: [u8; 64] = hex_array64(sig_hex);
            let expected_pk: [u8; 32] = hex_array(pk_hex);

            let secret = SecretKey::from_byte_array(sk_bytes).expect("valid scalar");
            let keypair = Keypair::from_secret_key(&secp, &secret);
            let (xonly, _parity) = keypair.x_only_public_key();

            assert_eq!(xonly.serialize(), expected_pk, "vector {index}: public key");

            let signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux);
            assert_eq!(
                signature.to_byte_array(),
                expected_sig,
                "vector {index}: signature"
            );

            secp.verify_schnorr(&signature, &msg, &xonly)
                .unwrap_or_else(|e| panic!("vector {index}: verify failed: {e}"));

            if aux == [0u8; 32] {
                let deterministic = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
                assert_eq!(
                    deterministic.to_byte_array(),
                    expected_sig,
                    "vector {index}: no-aux-rand signing must match aux_rand = 0"
                );
            }
        }
    }

    /// BIP-340 vectors that must be rejected. Catches a verifier that is too
    /// permissive about malformed keys and out-of-range signature scalars.
    #[test]
    fn bip340_official_failure_vectors() {
        // (public key, message, signature, why)
        const VECTORS: [(&str, &str, &str, &str); 3] = [
            (
                "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                "public key not on the curve",
            ),
            (
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
                "has_even_y(R) is false",
            ),
            (
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
                "negated message",
            ),
        ];

        let secp = Secp256k1::new();

        for (pk_hex, msg_hex, sig_hex, why) in VECTORS {
            let msg: [u8; 32] = hex_array(msg_hex);
            let signature = Signature::from_byte_array(hex_array64(sig_hex));

            let Ok(xonly) = XOnlyPublicKey::from_byte_array(hex_array(pk_hex)) else {
                // An off-curve key is rejected at parse time, which is the
                // correct outcome for that vector.
                assert_eq!(why, "public key not on the curve");
                continue;
            };

            assert!(
                secp.verify_schnorr(&signature, &msg, &xonly).is_err(),
                "must reject: {why}"
            );
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let secp = Secp256k1::signing_only();
        let keypair = keypair(7);
        let (xonly, _parity) = keypair.x_only_public_key();

        let record = PriceRecord {
            pair: "BTC/USD".to_owned(),
            price: HARDCODED_PRICE,
            decimals: 8,
            timestamp: 1_755_000_000,
            // Deliberately wrong: signing must overwrite it.
            writer_pubkey: [0u8; 32],
        };

        let signed = sign_price_record(&secp, &keypair, record).expect("signs");

        assert_eq!(signed.record.writer_pubkey, xonly.serialize());
        assert_eq!(signed.verify().expect("verifies"), xonly);
        signed.verify_from(&xonly).expect("writer matches");
    }

    #[test]
    fn signing_is_deterministic() {
        let secp = Secp256k1::signing_only();
        let keypair = keypair(9);
        let record = PriceRecord {
            pair: "BTC/USD".to_owned(),
            price: HARDCODED_PRICE,
            decimals: 8,
            timestamp: 42,
            writer_pubkey: [0u8; 32],
        };

        let first = sign_price_record(&secp, &keypair, record.clone()).expect("signs");
        let second = sign_price_record(&secp, &keypair, record).expect("signs");

        assert_eq!(
            first, second,
            "a re-published orphan must be byte-identical to the original"
        );
    }

    #[test]
    fn another_oracles_signature_is_rejected() {
        let secp = Secp256k1::signing_only();
        let ours = keypair(1);
        let theirs = keypair(2);
        let (our_pubkey, _parity) = ours.x_only_public_key();

        let record = PriceRecord {
            pair: "BTC/USD".to_owned(),
            price: HARDCODED_PRICE,
            decimals: 8,
            timestamp: 1,
            writer_pubkey: [0u8; 32],
        };
        let signed = sign_price_record(&secp, &theirs, record).expect("signs");

        // Self-consistent...
        signed.verify().expect("their signature is valid");
        // ...but not from the key this channel is bound to.
        assert!(matches!(
            signed.verify_from(&our_pubkey),
            Err(Error::WrongWriter { .. })
        ));
    }

    #[test]
    fn tampering_with_the_price_invalidates_the_signature() {
        let secp = Secp256k1::signing_only();
        let keypair = keypair(3);
        let record = PriceRecord {
            pair: "BTC/USD".to_owned(),
            price: HARDCODED_PRICE,
            decimals: 8,
            timestamp: 1,
            writer_pubkey: [0u8; 32],
        };

        let mut signed = sign_price_record(&secp, &keypair, record).expect("signs");
        signed.record.price += 1;

        assert!(matches!(signed.verify(), Err(Error::Signature(_))));
    }

    #[test]
    fn envelope_round_trip() {
        let secp = Secp256k1::signing_only();
        let keypair = keypair(5);
        let record = PriceRecord {
            pair: "BTC/USD".to_owned(),
            price: HARDCODED_PRICE,
            decimals: 8,
            timestamp: 123,
            writer_pubkey: [0u8; 32],
        };
        let signed = sign_price_record(&secp, &keypair, record).expect("signs");
        let envelope = OracleEnvelope::new(OracleMessage::Price(signed));

        let bytes = envelope.encode().expect("encodes");
        assert_eq!(&bytes[..4], &MAGIC, "magic must be the first four bytes");

        let decoded = OracleEnvelope::decode(&bytes).expect("decodes");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn foreign_payloads_are_rejected() {
        assert!(matches!(
            OracleEnvelope::decode(b"INSERT INTO items VALUES (1);"),
            Err(Error::BadMagic { .. } | Error::Borsh(_))
        ));

        let secp = Secp256k1::signing_only();
        let keypair = keypair(11);
        let record = PriceRecord {
            pair: "BTC/USD".to_owned(),
            price: HARDCODED_PRICE,
            decimals: 8,
            timestamp: 1,
            writer_pubkey: [0u8; 32],
        };
        let signed = sign_price_record(&secp, &keypair, record).expect("signs");
        let mut bytes = OracleEnvelope::new(OracleMessage::Price(signed))
            .encode()
            .expect("encodes");

        bytes.push(0xAB);
        assert!(matches!(
            OracleEnvelope::decode(&bytes),
            Err(Error::TrailingBytes(1))
        ));
    }

    #[test]
    fn hardcoded_price_renders_as_expected() {
        assert_eq!(format_scaled(HARDCODED_PRICE, 8), "94.12345000");
        assert_eq!(format_scaled(HARDCODED_PRICE, 0), "9412345000");
        assert_eq!(format_scaled(5, 8), "0.00000005");
    }

    fn hex_array(value: &str) -> [u8; 32] {
        let bytes = hex::decode(value).expect("valid hex");
        bytes.try_into().expect("32 bytes")
    }

    fn hex_array64(value: &str) -> [u8; 64] {
        let bytes = hex::decode(value).expect("valid hex");
        bytes.try_into().expect("64 bytes")
    }
}
