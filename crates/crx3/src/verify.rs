use crate::container::{SplitError, contains_zip_token, signing_message, split};
use crate::id::id_from_hash;
use crate::key::{KeyHash, key_hash};
use crate::proto::{Proof, decode_header, decode_signed_data};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ParsedPublicKey, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    VerificationAlgorithm,
};
use std::fmt;

/// Extra requirements on top of a valid developer proof.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy<'a> {
    /// Every one of these keys must have a valid proof.
    pub required_keys: &'a [KeyHash],
    /// At least one of these keys must have a valid proof, if non-empty.
    /// This is how a store's publisher key is checked, e.g.
    /// [`crate::WEBSTORE_PUBLISHER_KEY_HASH`].
    pub any_of: &'a [KeyHash],
}

/// A verified CRX3 file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified<'a> {
    /// The extension ID.
    pub id: String,
    /// The developer key (DER SubjectPublicKeyInfo) whose hash is the ID.
    pub public_key: &'a [u8],
    /// Compressed `verified_contents`, if the header has them.
    pub verified_contents: Option<&'a [u8]>,
    pub diff: bool,
    pub archive: &'a [u8],
}

/// Mirrors Chromium's `crx_file::VerifierResult` errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    HeaderInvalid,
    /// A proof's key couldn't be used for its algorithm.
    SignatureInitializationFailed,
    /// No proof by the ID key, or a required key's proof is missing.
    RequiredProofMissing,
    SignatureVerificationFailed,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VerifyError::HeaderInvalid => "invalid CRX header",
            VerifyError::SignatureInitializationFailed => "unusable key in CRX proof",
            VerifyError::RequiredProofMissing => "required CRX proof missing",
            VerifyError::SignatureVerificationFailed => "CRX signature verification failed",
        })
    }
}

impl std::error::Error for VerifyError {}

impl From<SplitError> for VerifyError {
    fn from(_: SplitError) -> Self {
        VerifyError::HeaderInvalid
    }
}

/// Parses `spki` for `alg`, requiring a canonical DER SubjectPublicKeyInfo
/// like Chromium does (aws-lc also accepts raw key encodings).
fn parse_key(
    alg: &'static dyn VerificationAlgorithm,
    spki: &[u8],
) -> Result<ParsedPublicKey, VerifyError> {
    let key =
        ParsedPublicKey::new(alg, spki).map_err(|_| VerifyError::SignatureInitializationFailed)?;
    match key.as_der() {
        Ok(der) if der.as_ref() == spki => Ok(key),
        _ => Err(VerifyError::SignatureInitializationFailed),
    }
}

/// Verifies a CRX3 file the way Chromium's `crx_file::Verify` does.
///
/// Differences from Chromium: ECDSA proofs must use P-256 (Chromium accepts
/// any curve with SHA-256), and the whole file is in memory.
pub fn verify<'a>(crx: &'a [u8], policy: &Policy<'_>) -> Result<Verified<'a>, VerifyError> {
    let parts = split(crx)?;
    if contains_zip_token(parts.header) {
        return Err(VerifyError::HeaderInvalid);
    }
    let header = decode_header(parts.header).map_err(|_| VerifyError::HeaderInvalid)?;
    let crx_id =
        decode_signed_data(header.signed_header_data).map_err(|_| VerifyError::HeaderInvalid)?;

    let mut developer_key = None;
    let mut missing: Vec<&KeyHash> = policy.required_keys.iter().collect();
    let mut found_any_of = false;
    let mut checks: Vec<(ParsedPublicKey, &Proof<'a>)> = Vec::new();

    let proofs = header
        .sha256_with_rsa
        .iter()
        .map(|p| {
            (
                &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
                    as &'static dyn VerificationAlgorithm,
                p,
            )
        })
        .chain(
            header
                .sha256_with_ecdsa
                .iter()
                .map(|p| (&ECDSA_P256_SHA256_ASN1 as _, p)),
        );
    for (alg, proof) in proofs {
        let hash = key_hash(proof.public_key);
        if crx_id.len() == 16 && hash[..16] == *crx_id {
            developer_key = Some(proof.public_key);
        }
        missing.retain(|k| **k != hash);
        found_any_of |= policy.any_of.contains(&hash);
        checks.push((parse_key(alg, proof.public_key)?, proof));
    }

    let developer_key = developer_key.ok_or(VerifyError::RequiredProofMissing)?;
    if !missing.is_empty() || (!policy.any_of.is_empty() && !found_any_of) {
        return Err(VerifyError::RequiredProofMissing);
    }

    let message = signing_message(header.signed_header_data, parts.archive)
        .ok_or(VerifyError::HeaderInvalid)?;
    for (key, proof) in &checks {
        key.verify_sig(&message, proof.signature)
            .map_err(|_| VerifyError::SignatureVerificationFailed)?;
    }

    Ok(Verified {
        id: id_from_hash(crx_id),
        public_key: developer_key,
        verified_contents: header.verified_contents,
        diff: parts.diff,
        archive: parts.archive,
    })
}
