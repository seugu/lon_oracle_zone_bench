//! The two keys an oracle node holds, and the channel id they produce.
//!
//! An oracle carries two distinct identities, and conflating them is the
//! easiest way to get this design wrong:
//!
//! * **Channel key** — Ed25519, the Logos protocol-level identity. Bedrock
//!   checks it in `InscriptionOp::verify`, so it is what decides *who may
//!   write to the channel at all*. The first inscription on a fresh
//!   `ChannelId` installs its signer as the channel's sole accredited key,
//!   which is exactly the single-writer property we want — no
//!   `ChannelConfig` op is needed.
//! * **Attestation key** — secp256k1 / BIP-340, the oracle's data identity.
//!   It signs the price record itself, so a consumer can verify the number
//!   without trusting the node it read the log from, and the attestation
//!   stays valid if it is relayed off-chain.
//!
//! The channel id binds the two together:
//!
//! ```text
//! channel_id = SHA256( SHA256(tag) || SHA256(tag) || ed25519_pk || xonly_pk )
//! tag        = "LON/oracle-channel-id/v1"
//! ```
//!
//! so an oracle's channel address is a commitment to both of its keys, and a
//! node that swaps either key necessarily lands on a different channel rather
//! than silently continuing someone else's feed.

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use lb_core::mantle::ops::channel::ChannelId;
use lb_key_management_system_service::keys::{ED25519_SECRET_KEY_SIZE, Ed25519Key};
use secp256k1::{Keypair, Secp256k1, SecretKey, SignOnly, XOnlyPublicKey};

use crate::record::{CHANNEL_ID_TAG, tagged_hash};

/// Length of a BIP-340 secret key, in bytes.
pub const SECP256K1_SECRET_KEY_SIZE: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid key file {path}: expected {expected} bytes, got {actual}")]
    BadKeyLength {
        path: PathBuf,
        expected: usize,
        actual: usize,
    },
    #[error("invalid secp256k1 secret key in {path}: {source}")]
    BadSecretKey {
        path: PathBuf,
        #[source]
        source: secp256k1::Error,
    },
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("expected {expected} bytes of hex, got {actual}")]
    BadHexLength { expected: usize, actual: usize },
}

pub type Result<T> = std::result::Result<T, Error>;

/// An oracle node's identity: both keys plus the channel they determine.
pub struct OracleIdentity {
    /// Ed25519 key that signs inscriptions — the channel's accredited key.
    pub channel_key: Ed25519Key,
    /// secp256k1 key pair that signs price records.
    pub attestation_key: Keypair,
    /// Reusable signing context, so we do not rebuild it per record.
    pub secp: Secp256k1<SignOnly>,
    /// The channel this oracle writes to.
    pub channel_id: ChannelId,
}

impl OracleIdentity {
    /// Loads both keys, creating either if its file does not exist yet.
    ///
    /// `channel_id_override` lets an operator point the node at an existing
    /// channel instead of its derived one; without it the id is derived from
    /// the two public keys.
    pub fn load_or_create(
        channel_key_path: &Path,
        attestation_key_path: &Path,
        channel_id_override: Option<&str>,
    ) -> Result<Self> {
        let channel_key = load_or_create_channel_key(channel_key_path)?;
        let secp = Secp256k1::signing_only();
        let attestation_key = load_or_create_attestation_key(&secp, attestation_key_path)?;

        let channel_pubkey = channel_key.public_key().to_bytes();
        let (xonly, _parity) = attestation_key.x_only_public_key();

        let channel_id = match channel_id_override {
            Some(hex_id) => ChannelId::from(decode_fixed::<32>(hex_id)?),
            None => derive_channel_id(&channel_pubkey, &xonly.serialize()),
        };

        Ok(Self {
            channel_key,
            attestation_key,
            secp,
            channel_id,
        })
    }

    /// The Ed25519 public key that owns the channel.
    #[must_use]
    pub fn channel_pubkey(&self) -> [u8; 32] {
        self.channel_key.public_key().to_bytes()
    }

    /// The BIP-340 x-only public key that signs the price records.
    #[must_use]
    pub fn attestation_pubkey(&self) -> XOnlyPublicKey {
        let (xonly, _parity) = self.attestation_key.x_only_public_key();
        xonly
    }
}

/// Derives the channel id from the oracle's two public keys.
#[must_use]
pub fn derive_channel_id(channel_pubkey: &[u8; 32], attestation_pubkey: &[u8; 32]) -> ChannelId {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(channel_pubkey);
    preimage.extend_from_slice(attestation_pubkey);
    ChannelId::from(tagged_hash(CHANNEL_ID_TAG, &preimage))
}

/// Loads the Ed25519 channel key, generating one on first run.
pub fn load_or_create_channel_key(path: &Path) -> Result<Ed25519Key> {
    if let Some(bytes) = read_key_file::<ED25519_SECRET_KEY_SIZE>(path)? {
        return Ok(Ed25519Key::from_bytes(&bytes));
    }

    let mut bytes = [0u8; ED25519_SECRET_KEY_SIZE];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    write_key_file(path, &bytes)?;

    Ok(Ed25519Key::from_bytes(&bytes))
}

/// Loads the BIP-340 attestation key, generating one on first run.
///
/// Rejection sampling on the generated scalar: `SecretKey::from_byte_array`
/// fails for zero and for values at or above the curve order, and retrying is
/// the correct response rather than clamping into range.
pub fn load_or_create_attestation_key(
    secp: &Secp256k1<SignOnly>,
    path: &Path,
) -> Result<Keypair> {
    if let Some(bytes) = read_key_file::<SECP256K1_SECRET_KEY_SIZE>(path)? {
        let secret = SecretKey::from_byte_array(bytes).map_err(|source| Error::BadSecretKey {
            path: path.to_path_buf(),
            source,
        })?;
        return Ok(Keypair::from_secret_key(secp, &secret));
    }

    let mut bytes = [0u8; SECP256K1_SECRET_KEY_SIZE];
    let secret = loop {
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
        if let Ok(secret) = SecretKey::from_byte_array(bytes) {
            break secret;
        }
    };
    write_key_file(path, &bytes)?;

    Ok(Keypair::from_secret_key(secp, &secret))
}

/// Decodes a hex string into a fixed-size byte array.
pub fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value.trim())?;
    let actual = bytes.len();
    bytes.try_into().map_err(|_ignored: Vec<u8>| Error::BadHexLength {
        expected: N,
        actual,
    })
}

fn read_key_file<const N: usize>(path: &Path) -> Result<Option<[u8; N]>> {
    match fs::read(path) {
        Ok(bytes) => {
            let actual = bytes.len();
            let bytes: [u8; N] = bytes.try_into().map_err(|_ignored: Vec<u8>| {
                Error::BadKeyLength {
                    path: path.to_path_buf(),
                    expected: N,
                    actual,
                }
            })?;
            Ok(Some(bytes))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_key_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| Error::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    fs::write(path, bytes).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    restrict_permissions(path)?;

    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
const fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_binds_both_keys() {
        let ed = [1u8; 32];
        let xonly = [2u8; 32];

        let base = derive_channel_id(&ed, &xonly);

        assert_ne!(
            base,
            derive_channel_id(&[9u8; 32], &xonly),
            "changing the channel key must move the channel"
        );
        assert_ne!(
            base,
            derive_channel_id(&ed, &[9u8; 32]),
            "changing the attestation key must move the channel"
        );
        assert_eq!(
            base,
            derive_channel_id(&ed, &xonly),
            "derivation must be deterministic"
        );
        assert_ne!(
            base.as_ref(),
            &ed,
            "the channel id must not just be the raw channel key"
        );
    }

    /// The two halves of the pre-image are fixed-width, so no
    /// `(channel_pubkey, attestation_pubkey)` pair can be re-split to collide
    /// with another. Pinned here because a future variable-length field would
    /// quietly break it.
    #[test]
    fn channel_id_preimage_is_unambiguous() {
        assert_ne!(
            derive_channel_id(&[0xAB; 32], &[0xCD; 32]),
            derive_channel_id(&[0xCD; 32], &[0xAB; 32])
        );
    }

    #[test]
    fn keys_persist_across_restarts() {
        let dir = std::env::temp_dir().join(format!("lon-keys-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let channel_path = dir.join("channel.ed25519");
        let attest_path = dir.join("attest.bip340");

        let first = OracleIdentity::load_or_create(&channel_path, &attest_path, None)
            .expect("creates keys");
        let second = OracleIdentity::load_or_create(&channel_path, &attest_path, None)
            .expect("reloads keys");

        assert_eq!(first.channel_pubkey(), second.channel_pubkey());
        assert_eq!(
            first.attestation_pubkey().serialize(),
            second.attestation_pubkey().serialize()
        );
        assert_eq!(first.channel_id, second.channel_id);

        drop(fs::remove_dir_all(&dir));
    }

    #[test]
    fn hex_channel_id_override_is_length_checked() {
        assert!(matches!(
            decode_fixed::<32>("aabb"),
            Err(Error::BadHexLength {
                expected: 32,
                actual: 2
            })
        ));
        assert!(decode_fixed::<32>(&"ab".repeat(32)).is_ok());
    }
}
