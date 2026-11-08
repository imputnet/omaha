use crate::container::{contains_zip_token, join, signing_message, split};
use crate::key::{Algorithm, SignError, Signer, key_hash};
use crate::proto::{Header, Proof, decode_header, encode_header, encode_signed_data};
use std::fmt;

/// Builds a CRX3 file from a zip archive.
///
/// The first signer's key determines the extension ID. Further signers add
/// proofs over the same data, for example a store's publisher key.
pub struct Builder<'a> {
    archive: &'a [u8],
    verified_contents: Option<&'a [u8]>,
    signers: Vec<&'a dyn Signer>,
    diff: bool,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// No signer was given, so there is no ID key.
    NoSigner,
    Sign(SignError),
    /// The encoded header happens to contain a zip end-of-central-directory
    /// token, which Chromium rejects. With ECDSA, building again produces a
    /// different signature; with RSA the signature is deterministic.
    HeaderContainsZipToken,
    /// Header or signed data is larger than 4 GiB.
    TooLarge,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::NoSigner => f.write_str("no signer for the ID key"),
            BuildError::Sign(e) => e.fmt(f),
            BuildError::HeaderContainsZipToken => f.write_str("header contains a zip token"),
            BuildError::TooLarge => f.write_str("CRX header too large"),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BuildError::Sign(e) => Some(e),
            _ => None,
        }
    }
}

impl<'a> Builder<'a> {
    pub fn new(archive: &'a [u8]) -> Self {
        Builder {
            archive,
            verified_contents: None,
            signers: Vec::new(),
            diff: false,
        }
    }

    /// Adds a signer. The first one is the ID key.
    pub fn signer(mut self, signer: &'a dyn Signer) -> Self {
        self.signers.push(signer);
        self
    }

    /// Embeds compressed, signed `verified_contents` in the header.
    pub fn verified_contents(mut self, bytes: &'a [u8]) -> Self {
        self.verified_contents = Some(bytes);
        self
    }

    /// Builds a differential update (`CrOD`) instead of a full CRX.
    pub fn diff(mut self, diff: bool) -> Self {
        self.diff = diff;
        self
    }

    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let id_signer = self.signers.first().ok_or(BuildError::NoSigner)?;
        let crx_id = &key_hash(id_signer.public_key())[..16];
        let signed_header_data = encode_signed_data(crx_id);
        let message =
            signing_message(&signed_header_data, self.archive).ok_or(BuildError::TooLarge)?;

        let signatures = self
            .signers
            .iter()
            .map(|s| s.sign(&message))
            .collect::<Result<Vec<_>, _>>()
            .map_err(BuildError::Sign)?;

        let mut header = Header {
            verified_contents: self.verified_contents,
            signed_header_data: &signed_header_data,
            ..Default::default()
        };
        for (signer, signature) in self.signers.iter().zip(&signatures) {
            let proof = Proof {
                public_key: signer.public_key(),
                signature,
            };
            match signer.algorithm() {
                Algorithm::RsaPkcs1Sha256 => header.sha256_with_rsa.push(proof),
                Algorithm::EcdsaP256Sha256 => header.sha256_with_ecdsa.push(proof),
            }
        }
        finish(self.diff, &header, self.archive)
    }
}

fn finish(diff: bool, header: &Header<'_>, archive: &[u8]) -> Result<Vec<u8>, BuildError> {
    let header = encode_header(header);
    if contains_zip_token(&header) {
        return Err(BuildError::HeaderContainsZipToken);
    }
    join(diff, &header, archive).ok_or(BuildError::TooLarge)
}

#[derive(Debug)]
#[non_exhaustive]
pub enum AppendError {
    /// The input isn't a well-formed CRX3 file.
    Invalid,
    Build(BuildError),
}

impl fmt::Display for AppendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppendError::Invalid => f.write_str("invalid CRX3 file"),
            AppendError::Build(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for AppendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppendError::Build(e) => Some(e),
            AppendError::Invalid => None,
        }
    }
}

/// Adds a proof to an existing CRX3 file without touching the others, for
/// example a store's publisher proof on a developer-signed package. The ID
/// and existing signatures stay valid because proofs only sign the signed
/// header data and the archive.
///
/// This doesn't verify the existing proofs; verify the input first.
pub fn append_proof(crx: &[u8], signer: &dyn Signer) -> Result<Vec<u8>, AppendError> {
    let parts = split(crx).map_err(|_| AppendError::Invalid)?;
    let mut header = decode_header(parts.header).map_err(|_| AppendError::Invalid)?;
    let message = signing_message(header.signed_header_data, parts.archive)
        .ok_or(AppendError::Build(BuildError::TooLarge))?;
    let signature = signer
        .sign(&message)
        .map_err(|e| AppendError::Build(BuildError::Sign(e)))?;
    let proof = Proof {
        public_key: signer.public_key(),
        signature: &signature,
    };
    match signer.algorithm() {
        Algorithm::RsaPkcs1Sha256 => header.sha256_with_rsa.push(proof),
        Algorithm::EcdsaP256Sha256 => header.sha256_with_ecdsa.push(proof),
    }
    finish(parts.diff, &header, parts.archive).map_err(AppendError::Build)
}
