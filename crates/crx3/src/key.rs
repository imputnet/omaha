use sha2::{Digest, Sha256};
use std::fmt;

/// SHA-256 of a DER-encoded SubjectPublicKeyInfo, which is how Chromium
/// pins and compares keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHash([u8; 32]);

impl KeyHash {
    /// A pinned hash, e.g. from a browser's source.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        KeyHash(bytes)
    }

    /// The raw 32-byte SHA-256 digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for KeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyHash(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        write!(f, ")")
    }
}

/// The hash of a key, as Chromium computes it.
pub fn key_hash(spki: &[u8]) -> KeyHash {
    KeyHash(Sha256::digest(spki).into())
}

/// SHA-256 of the data a CRX3 proof covers. Only this crate creates these,
/// so a [`Signer`] can't be handed any other hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedDataDigest([u8; 32]);

impl SignedDataDigest {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        SignedDataDigest(bytes)
    }

    /// The raw 32-byte SHA-256 digest a [`Signer`] signs.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The proof types CRX3 supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 (`sha256_with_rsa`).
    RsaPkcs1Sha256,
    /// ECDSA P-256 with SHA-256, DER-encoded signature (`sha256_with_ecdsa`).
    EcdsaP256Sha256,
}

/// Something that can produce a CRX3 proof: a key in memory, an HSM, or a
/// remote signing service.
///
/// Signers only ever see the SHA-256 of the signed data, never the archive.
pub trait Signer: Send + Sync {
    /// The proof type this signer produces, which picks the header field its
    /// proof goes in.
    fn algorithm(&self) -> Algorithm;
    /// The DER-encoded SubjectPublicKeyInfo of the signing key.
    fn public_key(&self) -> &[u8];
    /// Signs `digest` with the key's algorithm: RSASSA-PKCS1-v1_5 or ECDSA
    /// (DER) over SHA-256.
    fn sign(&self, digest: &SignedDataDigest) -> Result<Vec<u8>, SignError>;
}

/// A signer failed to produce a signature.
#[derive(Debug)]
pub struct SignError(Box<dyn std::error::Error + Send + Sync>);

impl SignError {
    /// Wraps the underlying error from a key, HSM or signing service, kept as
    /// the error's source.
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        SignError(source.into())
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signing failed: {}", self.0)
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}
