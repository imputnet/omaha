//! Signers backed by aws-lc-rs.

use crate::key::{Algorithm, SignError, SignedDataDigest, Signer};
use aws_lc_rs::digest::{Digest, SHA256};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};

/// An error from aws-lc while creating or loading a key.
#[derive(Debug)]
pub struct KeyError(String);

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "key error: {}", self.0)
    }
}

impl std::error::Error for KeyError {}

fn key_err(e: impl std::fmt::Display) -> KeyError {
    KeyError(e.to_string())
}

fn sign_err(e: impl std::fmt::Display) -> SignError {
    SignError::new(e.to_string())
}

/// An RSA key signing with RSASSA-PKCS1-v1_5 and SHA-256.
pub struct RsaSigner {
    key: RsaKeyPair,
    spki: Vec<u8>,
}

impl RsaSigner {
    /// Generates a new 2048-bit key, the size Chromium's tools use.
    pub fn generate() -> Result<Self, KeyError> {
        Self::from_key(RsaKeyPair::generate(KeySize::Rsa2048).map_err(key_err)?)
    }

    /// Loads a PKCS#8 DER private key, e.g. an extension's `key.pem` after
    /// PEM decoding.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        Self::from_key(RsaKeyPair::from_pkcs8(der).map_err(key_err)?)
    }

    /// The private key as PKCS#8 DER. Handle with care.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.key.as_der().map_err(key_err)?.as_ref().to_vec())
    }

    fn from_key(key: RsaKeyPair) -> Result<Self, KeyError> {
        let spki = key
            .public_key()
            .as_der()
            .map_err(key_err)?
            .as_ref()
            .to_vec();
        Ok(RsaSigner { key, spki })
    }
}

impl Signer for RsaSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaPkcs1Sha256
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn sign(&self, digest: &SignedDataDigest) -> Result<Vec<u8>, SignError> {
        let digest = Digest::import_less_safe(digest.as_bytes(), &SHA256).map_err(sign_err)?;
        let mut sig = vec![0; self.key.public_modulus_len()];
        self.key
            .sign_digest(&RSA_PKCS1_SHA256, &digest, &mut sig)
            .map_err(sign_err)?;
        Ok(sig)
    }
}

/// An ECDSA P-256 key producing DER signatures over SHA-256.
pub struct EcdsaSigner {
    key: EcdsaKeyPair,
    spki: Vec<u8>,
}

impl EcdsaSigner {
    pub fn generate() -> Result<Self, KeyError> {
        Self::from_key(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map_err(key_err)?)
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        Self::from_key(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der).map_err(key_err)?,
        )
    }

    /// The private key as PKCS#8 DER. Handle with care.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.key.to_pkcs8v1().map_err(key_err)?.as_ref().to_vec())
    }

    fn from_key(key: EcdsaKeyPair) -> Result<Self, KeyError> {
        let spki = key
            .public_key()
            .as_der()
            .map_err(key_err)?
            .as_ref()
            .to_vec();
        Ok(EcdsaSigner { key, spki })
    }
}

impl Signer for EcdsaSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EcdsaP256Sha256
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn sign(&self, digest: &SignedDataDigest) -> Result<Vec<u8>, SignError> {
        let digest = Digest::import_less_safe(digest.as_bytes(), &SHA256).map_err(sign_err)?;
        let sig = self.key.sign_digest(&digest).map_err(sign_err)?;
        Ok(sig.as_ref().to_vec())
    }
}
