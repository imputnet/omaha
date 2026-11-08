use crate::container::{MessageHasher, contains_zip_token, read_header, stream, write_header};
use crate::key::{Algorithm, SignError, Signer, key_hash};
use crate::proto::{Header, Proof, decode_header, encode_header, encode_signed_data};
use std::fmt;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

/// Builds CRX3 files from zip archives.
///
/// The first signer's key determines the extension ID. Further signers add
/// proofs over the same data, for example a store's publisher key.
#[derive(Default)]
pub struct Builder<'a> {
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
    Io(io::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::NoSigner => f.write_str("no signer for the ID key"),
            BuildError::Sign(e) => e.fmt(f),
            BuildError::HeaderContainsZipToken => f.write_str("header contains a zip token"),
            BuildError::TooLarge => f.write_str("CRX header too large"),
            BuildError::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BuildError::Sign(e) => Some(e),
            BuildError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BuildError {
    fn from(e: io::Error) -> Self {
        BuildError::Io(e)
    }
}

impl<'a> Builder<'a> {
    pub fn new() -> Self {
        Self::default()
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

    /// Builds a CRX3 file in memory.
    pub fn build(&self, archive: &[u8]) -> Result<Vec<u8>, BuildError> {
        let mut out = Vec::with_capacity(archive.len() + 4096);
        self.write(Cursor::new(archive), &mut out)?;
        Ok(out)
    }

    /// Streams a CRX3 file to `out`. The archive is read twice from its
    /// current position: once to sign it, once to copy it.
    pub fn write(&self, mut archive: impl Read + Seek, out: impl Write) -> Result<(), BuildError> {
        let id_signer = self.signers.first().ok_or(BuildError::NoSigner)?;
        let id_key_hash = key_hash(id_signer.public_key());
        let signed_header_data = encode_signed_data(&id_key_hash.as_bytes()[..16]);

        let start = archive.stream_position()?;
        let mut hasher = MessageHasher::new(&signed_header_data).ok_or(BuildError::TooLarge)?;
        stream(&mut archive, |chunk| hasher.update(chunk))?;
        let digest = hasher.finish();

        let signatures = self
            .signers
            .iter()
            .map(|s| s.sign(&digest))
            .collect::<Result<Vec<_>, _>>()
            .map_err(BuildError::Sign)?;

        let mut header = Header {
            verified_contents: self.verified_contents,
            signed_header_data: &signed_header_data,
            ..Default::default()
        };
        for (signer, signature) in self.signers.iter().zip(&signatures) {
            add_proof(&mut header, *signer, signature);
        }

        archive.seek(SeekFrom::Start(start))?;
        finish(&header, self.diff, archive, out)
    }
}

fn add_proof<'a>(header: &mut Header<'a>, signer: &'a dyn Signer, signature: &'a [u8]) {
    let proof = Proof {
        public_key: signer.public_key(),
        signature,
    };
    match signer.algorithm() {
        Algorithm::RsaPkcs1Sha256 => header.sha256_with_rsa.push(proof),
        Algorithm::EcdsaP256Sha256 => header.sha256_with_ecdsa.push(proof),
    }
}

fn finish(
    header: &Header<'_>,
    diff: bool,
    mut archive: impl Read,
    mut out: impl Write,
) -> Result<(), BuildError> {
    let header = encode_header(header);

    if contains_zip_token(&header) {
        return Err(BuildError::HeaderContainsZipToken);
    }

    if u32::try_from(header.len()).is_err() {
        return Err(BuildError::TooLarge);
    }

    write_header(&mut out, diff, &header)?;
    io::copy(&mut archive, &mut out)?;
    Ok(())
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
    let mut out = Vec::with_capacity(crx.len() + 1024);
    append_proof_to(Cursor::new(crx), signer, &mut out)?;
    Ok(out)
}

/// Streaming [`append_proof`]. The archive part of `crx` is read twice.
pub fn append_proof_to(
    mut crx: impl Read + Seek,
    signer: &dyn Signer,
    out: impl Write,
) -> Result<(), AppendError> {
    let build = |e: io::Error| AppendError::Build(BuildError::Io(e));
    let (diff, header_bytes, _) = read_header(&mut crx).map_err(|e| match e {
        crate::container::ReadError::Io(e) => build(e),
        crate::container::ReadError::Invalid => AppendError::Invalid,
    })?;
    let mut header = decode_header(&header_bytes).map_err(|_| AppendError::Invalid)?;

    let start = crx.stream_position().map_err(build)?;
    let mut hasher = MessageHasher::new(header.signed_header_data)
        .ok_or(AppendError::Build(BuildError::TooLarge))?;
    stream(&mut crx, |chunk| hasher.update(chunk)).map_err(build)?;
    let signature = signer
        .sign(&hasher.finish())
        .map_err(|e| AppendError::Build(BuildError::Sign(e)))?;

    add_proof(&mut header, signer, &signature);
    crx.seek(SeekFrom::Start(start)).map_err(build)?;
    finish(&header, diff, crx, out).map_err(AppendError::Build)
}
