use crate::container::{MessageHasher, ReadError, contains_zip_token, read_header, stream};
use crate::id::id_from_hash;
use crate::key::{KeyHash, key_hash};
use crate::proto::{decode_header, decode_signed_data};
use aws_lc_rs::digest::{Digest as LcDigest, SHA256};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ParsedPublicKey, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    VerificationAlgorithm,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read};

/// Extra requirements on top of a valid developer proof.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct Policy<'a> {
    /// Every one of these keys must have a valid proof.
    pub required_keys: &'a [KeyHash],
    /// At least one of these keys must have a valid proof, if non-empty.
    /// This is how a store's publisher key is checked, e.g.
    /// [`crate::WEBSTORE_PUBLISHER_KEY_HASH`].
    pub any_of: &'a [KeyHash],
}

impl<'a> Policy<'a> {
    /// Only a valid developer proof is required.
    pub const fn new() -> Self {
        Policy {
            required_keys: &[],
            any_of: &[],
        }
    }

    /// Requires a valid proof by every one of `keys`.
    pub const fn required_keys(mut self, keys: &'a [KeyHash]) -> Self {
        self.required_keys = keys;
        self
    }

    /// Requires a valid proof by at least one of `keys`, if non-empty.
    pub const fn any_of(mut self, keys: &'a [KeyHash]) -> Self {
        self.any_of = keys;
        self
    }
}

/// A verified CRX3 file.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verified {
    /// The extension ID.
    pub id: String,
    /// The developer key (DER SubjectPublicKeyInfo) whose hash is the ID.
    pub public_key: Vec<u8>,
    /// Compressed `verified_contents`, if the header has them.
    pub verified_contents: Option<Vec<u8>>,
    /// Whether the file is a differential update (`CrOD`).
    pub diff: bool,
    /// Where the archive starts in the file.
    pub archive_offset: u64,
    /// SHA-256 of the whole file.
    pub file_sha256: [u8; 32],
}

/// Mirrors Chromium's `crx_file::VerifierResult` errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The prefix or header is malformed: bad magic or version, truncated,
    /// too large, contains a zip end-of-central-directory token, or the
    /// protobuf or signed header data doesn't parse.
    HeaderInvalid,
    /// A proof's key couldn't be used for its algorithm.
    SignatureInitializationFailed,
    /// No proof by the ID key, or a required key's proof is missing.
    RequiredProofMissing,
    /// A proof's signature doesn't match the signed data, or an RSA key is
    /// outside 1024 to 8192 bits.
    SignatureVerificationFailed,
    /// Reading the file failed.
    Io(io::ErrorKind),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::HeaderInvalid => f.write_str("invalid CRX header"),
            VerifyError::SignatureInitializationFailed => f.write_str("unusable key in CRX proof"),
            VerifyError::RequiredProofMissing => f.write_str("required CRX proof missing"),
            VerifyError::SignatureVerificationFailed => {
                f.write_str("CRX signature verification failed")
            }
            VerifyError::Io(kind) => write!(f, "reading CRX failed: {kind}"),
        }
    }
}

impl std::error::Error for VerifyError {}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
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

/// Verifies a CRX3 file in memory. See [`verify_reader`].
pub fn verify(crx: &[u8], policy: &Policy<'_>) -> Result<Verified, VerifyError> {
    verify_reader(crx, policy)
}

/// Verifies a CRX3 file the way Chromium's `crx_file::Verify` does, reading
/// it once. Memory use is bounded by the header size, at most
/// [`crate::MAX_HEADER_LEN`].
pub fn verify_reader(reader: impl Read, policy: &Policy<'_>) -> Result<Verified, VerifyError> {
    let mut reader = HashingReader {
        inner: reader,
        hasher: Sha256::new(),
    };
    let (diff, header_bytes, _) = read_header(&mut reader).map_err(|e| match e {
        ReadError::Invalid => VerifyError::HeaderInvalid,
        ReadError::Io(e) => VerifyError::Io(e.kind()),
    })?;

    if contains_zip_token(&header_bytes) {
        return Err(VerifyError::HeaderInvalid);
    }

    let header = decode_header(&header_bytes).map_err(|_| VerifyError::HeaderInvalid)?;
    let crx_id =
        decode_signed_data(header.signed_header_data).map_err(|_| VerifyError::HeaderInvalid)?;

    let mut developer_key = None;
    let mut missing: Vec<&KeyHash> = policy.required_keys.iter().collect();
    let mut found_any_of = false;
    let mut checks = Vec::new();

    let rsa: &'static dyn VerificationAlgorithm = &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY;
    let ecdsa: &'static dyn VerificationAlgorithm = &ECDSA_P256_SHA256_ASN1;
    let proofs = header
        .sha256_with_rsa
        .iter()
        .map(|p| (rsa, p))
        .chain(header.sha256_with_ecdsa.iter().map(|p| (ecdsa, p)));
    for (alg, proof) in proofs {
        let hash = key_hash(proof.public_key);

        if crx_id.len() == 16 && hash.as_bytes()[..16] == *crx_id {
            developer_key = Some(proof.public_key);
        }

        missing.retain(|k| **k != hash);
        found_any_of |= policy.any_of.contains(&hash);
        checks.push((parse_key(alg, proof.public_key)?, proof.signature));
    }

    let developer_key = developer_key.ok_or(VerifyError::RequiredProofMissing)?;

    if !missing.is_empty() || (!policy.any_of.is_empty() && !found_any_of) {
        return Err(VerifyError::RequiredProofMissing);
    }

    let mut hasher =
        MessageHasher::new(header.signed_header_data).ok_or(VerifyError::HeaderInvalid)?;
    stream(&mut reader, |chunk| hasher.update(chunk)).map_err(|e| VerifyError::Io(e.kind()))?;
    let digest = LcDigest::import_less_safe(hasher.finish().as_bytes(), &SHA256)
        .map_err(|_| VerifyError::SignatureVerificationFailed)?;
    for (key, signature) in &checks {
        key.verify_digest_sig(&digest, signature)
            .map_err(|_| VerifyError::SignatureVerificationFailed)?;
    }

    Ok(Verified {
        id: id_from_hash(crx_id),
        public_key: developer_key.to_vec(),
        verified_contents: header.verified_contents.map(<[u8]>::to_vec),
        diff,
        archive_offset: 12 + header_bytes.len() as u64,
        file_sha256: reader.hasher.finalize().into(),
    })
}
