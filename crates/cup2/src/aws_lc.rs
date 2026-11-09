//! CUP signers backed by aws-lc-rs.

use crate::{KeyId, MLDSA44_SIGNATURE_LEN, ProofData, SignError, Signer};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, ML_DSA_44_SIGNING, PqdsaKeyPair,
};
use std::fmt;

/// An error from aws-lc while creating or loading a key.
#[derive(Debug)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key error: {}", self.0)
    }
}

impl std::error::Error for KeyError {}

pub(crate) fn key_err(e: impl fmt::Display) -> KeyError {
    KeyError(e.to_string())
}

/// An ML-DSA-44 key, the scheme current Chromium uses.
pub struct MlDsa44Signer {
    version: u32,
    key: PqdsaKeyPair,
    spki: Vec<u8>,
}

impl MlDsa44Signer {
    /// Generates a new key, served as key ID `ML-DSA-44-<version>`.
    pub fn generate(version: u32) -> Result<Self, KeyError> {
        Self::from_key(
            version,
            PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).map_err(key_err)?,
        )
    }

    /// Loads a PKCS#8 DER private key, in seed or expanded form.
    pub fn from_pkcs8(version: u32, der: &[u8]) -> Result<Self, KeyError> {
        Self::from_key(
            version,
            PqdsaKeyPair::from_pkcs8(&ML_DSA_44_SIGNING, der).map_err(key_err)?,
        )
    }

    /// The private key as PKCS#8 DER. Handle with care.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.key.to_pkcs8v1().map_err(key_err)?.as_ref().to_vec())
    }

    /// The public key as DER SubjectPublicKeyInfo, the form Chromium pins.
    pub fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn from_key(version: u32, key: PqdsaKeyPair) -> Result<Self, KeyError> {
        let spki = key
            .public_key()
            .as_der()
            .map_err(key_err)?
            .as_ref()
            .to_vec();
        Ok(MlDsa44Signer { version, key, spki })
    }
}

impl Signer for MlDsa44Signer {
    fn key_id(&self) -> KeyId {
        KeyId::MlDsa44(self.version)
    }

    fn sign(&self, proof_data: &ProofData) -> Result<Vec<u8>, SignError> {
        let mut sig = vec![0; MLDSA44_SIGNATURE_LEN];
        let len = self
            .key
            .sign(proof_data.as_bytes(), &mut sig)
            .map_err(|e| SignError::new(e.to_string()))?;
        sig.truncate(len);
        Ok(sig)
    }
}

/// An ECDSA P-256 key, for Chromium versions before ML-DSA.
pub struct EcdsaSigner {
    version: u32,
    key: EcdsaKeyPair,
    spki: Vec<u8>,
}

impl EcdsaSigner {
    /// Generates a new key, served as key ID `<version>`.
    pub fn generate(version: u32) -> Result<Self, KeyError> {
        Self::from_key(
            version,
            EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map_err(key_err)?,
        )
    }

    /// Loads a PKCS#8 DER private key.
    pub fn from_pkcs8(version: u32, der: &[u8]) -> Result<Self, KeyError> {
        Self::from_key(
            version,
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der).map_err(key_err)?,
        )
    }

    /// The private key as PKCS#8 DER. Handle with care.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.key.to_pkcs8v1().map_err(key_err)?.as_ref().to_vec())
    }

    /// The public key as DER SubjectPublicKeyInfo.
    pub fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn from_key(version: u32, key: EcdsaKeyPair) -> Result<Self, KeyError> {
        let spki = key
            .public_key()
            .as_der()
            .map_err(key_err)?
            .as_ref()
            .to_vec();
        Ok(EcdsaSigner { version, key, spki })
    }
}

impl Signer for EcdsaSigner {
    fn key_id(&self) -> KeyId {
        KeyId::Ecdsa(self.version)
    }

    fn sign(&self, proof_data: &ProofData) -> Result<Vec<u8>, SignError> {
        let sig = self
            .key
            .sign(&SystemRandom::new(), proof_data.as_bytes())
            .map_err(|e| SignError::new(e.to_string()))?;
        Ok(sig.as_ref().to_vec())
    }
}

/// Whichever signer a PKCS#8 key is for: ML-DSA-44, else ECDSA P-256.
pub struct AnySigner(Inner);

enum Inner {
    MlDsa44(MlDsa44Signer),
    Ecdsa(EcdsaSigner),
}

impl AnySigner {
    /// Loads a PKCS#8 DER private key of either algorithm, served as key
    /// version `version`.
    pub fn from_pkcs8(version: u32, der: &[u8]) -> Result<Self, KeyError> {
        match MlDsa44Signer::from_pkcs8(version, der) {
            Ok(signer) => Ok(AnySigner(Inner::MlDsa44(signer))),
            Err(_) => EcdsaSigner::from_pkcs8(version, der)
                .map(|signer| AnySigner(Inner::Ecdsa(signer)))
                .map_err(|_| key_err("not an ML-DSA-44 or ECDSA P-256 PKCS#8 key")),
        }
    }

    /// The public key as DER SubjectPublicKeyInfo.
    pub fn public_key(&self) -> &[u8] {
        match &self.0 {
            Inner::MlDsa44(signer) => signer.public_key(),
            Inner::Ecdsa(signer) => signer.public_key(),
        }
    }
}

impl Signer for AnySigner {
    fn key_id(&self) -> KeyId {
        match &self.0 {
            Inner::MlDsa44(signer) => signer.key_id(),
            Inner::Ecdsa(signer) => signer.key_id(),
        }
    }

    fn sign(&self, proof_data: &ProofData) -> Result<Vec<u8>, SignError> {
        match &self.0 {
            Inner::MlDsa44(signer) => signer.sign(proof_data),
            Inner::Ecdsa(signer) => signer.sign(proof_data),
        }
    }
}
