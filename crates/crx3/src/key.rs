use sha2::{Digest, Sha256};
use std::fmt;

/// SHA-256 of a DER-encoded SubjectPublicKeyInfo.
pub type KeyHash = [u8; 32];

/// The hash Chromium pins and compares keys by.
pub fn key_hash(spki: &[u8]) -> KeyHash {
    Sha256::digest(spki).into()
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
pub trait Signer {
    fn algorithm(&self) -> Algorithm;
    /// The DER-encoded SubjectPublicKeyInfo of the signing key.
    fn public_key(&self) -> &[u8];
    /// Signs `message` (not a digest of it) with the key's algorithm.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// A signer failed to produce a signature.
#[derive(Debug)]
pub struct SignError(Box<dyn std::error::Error + Send + Sync>);

impl SignError {
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
