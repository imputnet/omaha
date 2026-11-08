//! ECDSA P-256 index keys backed by `aws-lc-rs`.

use super::{KeyId, SignError, Signer, SigningInput, Verifier};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, ParsedPublicKey,
};
use std::fmt;

/// aws-lc failed to generate, load, export or parse a key.
#[derive(Debug)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "index key: {}", self.0)
    }
}

impl std::error::Error for KeyError {}

fn key_err(e: impl fmt::Display) -> KeyError {
    KeyError(e.to_string())
}

/// An ECDSA P-256 signing key producing DER signatures over SHA-256.
pub struct EcdsaSigner {
    key: EcdsaKeyPair,
    spki: Vec<u8>,
}

impl EcdsaSigner {
    /// Generates a new P-256 key.
    pub fn generate() -> Result<Self, KeyError> {
        Self::from_key(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map_err(key_err)?)
    }

    /// Loads a PKCS#8 DER private key, which must be on P-256.
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
    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn sign(&self, input: &SigningInput) -> Result<Vec<u8>, SignError> {
        let signature = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(SignError::signer)?;
        Ok(signature.as_ref().to_vec())
    }
}

/// A trusted ECDSA P-256 public key.
pub struct EcdsaKey {
    id: KeyId,
    key: ParsedPublicKey,
}

impl EcdsaKey {
    /// From SubjectPublicKeyInfo DER.
    pub fn from_spki(spki: &[u8]) -> Result<Self, KeyError> {
        Ok(EcdsaKey {
            id: KeyId::of(spki),
            key: ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, spki).map_err(key_err)?,
        })
    }
}

impl Verifier for EcdsaKey {
    fn key_id(&self) -> &KeyId {
        &self.id
    }

    fn verify(&self, input: &SigningInput, signature: &[u8]) -> bool {
        self.key.verify_sig(input.as_bytes(), signature).is_ok()
    }
}
