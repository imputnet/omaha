use crate::key::SignedDataDigest;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Write};

/// Magic bytes at the start of a CRX file.
pub const MAGIC: [u8; 4] = *b"Cr24";
/// Magic bytes at the start of a CRX differential update.
pub const MAGIC_DIFF: [u8; 4] = *b"CrOD";
/// Prefix of the data every CRX3 proof signs.
pub const SIGNATURE_CONTEXT: &[u8; 16] = b"CRX3 SignedData\0";
/// Largest header accepted when reading, which bounds memory use before any
/// signature is checked.
pub const MAX_HEADER_LEN: usize = 16 << 20;

pub(crate) const VERSION: u32 = 3;
const PREFIX_LEN: usize = 12;

/// A CRX3 file split into its parts, borrowing from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Crx<'a> {
    /// Whether this is a differential update (`CrOD`).
    pub diff: bool,
    /// The serialized `CrxFileHeader` protobuf.
    pub header: &'a [u8],
    /// The zip archive (or diff payload) after the header.
    pub archive: &'a [u8],
}

/// Why [`split`] rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SplitError {
    /// The file starts with neither `Cr24` nor `CrOD`.
    BadMagic,
    /// The format version isn't 3; holds the version found.
    UnsupportedVersion(u32),
    /// The file ends before the prefix or the header it declares is complete.
    Truncated,
    /// The declared header size exceeds [`MAX_HEADER_LEN`].
    HeaderTooLarge,
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitError::BadMagic => f.write_str("not a CRX file"),
            SplitError::UnsupportedVersion(v) => write!(f, "unsupported CRX version {v}"),
            SplitError::Truncated => f.write_str("truncated CRX file"),
            SplitError::HeaderTooLarge => f.write_str("CRX header too large"),
        }
    }
}

impl std::error::Error for SplitError {}

fn parse_prefix(prefix: &[u8; PREFIX_LEN]) -> Result<(bool, usize), SplitError> {
    let [m0, m1, m2, m3, v0, v1, v2, v3, l0, l1, l2, l3] = *prefix;
    let diff = match [m0, m1, m2, m3] {
        MAGIC => false,
        MAGIC_DIFF => true,
        _ => return Err(SplitError::BadMagic),
    };
    let version = u32::from_le_bytes([v0, v1, v2, v3]);

    if version != VERSION {
        return Err(SplitError::UnsupportedVersion(version));
    }

    let header_len = u32::from_le_bytes([l0, l1, l2, l3]) as usize;

    if header_len > MAX_HEADER_LEN {
        return Err(SplitError::HeaderTooLarge);
    }

    Ok((diff, header_len))
}

/// Splits a CRX3 file into header and archive. Does not parse or verify the
/// header.
pub fn split(bytes: &[u8]) -> Result<Crx<'_>, SplitError> {
    let (prefix, rest) = bytes
        .split_first_chunk::<PREFIX_LEN>()
        .ok_or(SplitError::Truncated)?;
    let (diff, header_len) = parse_prefix(prefix)?;

    if rest.len() < header_len {
        return Err(SplitError::Truncated);
    }

    let (header, archive) = rest.split_at(header_len);
    Ok(Crx {
        diff,
        header,
        archive,
    })
}

#[derive(Debug)]
pub(crate) enum ReadError {
    Invalid,
    Io(io::Error),
}

/// Reads the prefix and header, leaving `reader` at the start of the archive.
/// Returns whether it's a diff, the header, and the bytes read so far.
pub(crate) fn read_header(mut reader: impl Read) -> Result<(bool, Vec<u8>, Vec<u8>), ReadError> {
    let mut prefix = [0u8; PREFIX_LEN];
    read_exact(&mut reader, &mut prefix)?;
    let (diff, header_len) = parse_prefix(&prefix).map_err(|_| ReadError::Invalid)?;
    let mut header = vec![0u8; header_len];
    read_exact(&mut reader, &mut header)?;
    Ok((diff, header, prefix.to_vec()))
}

fn read_exact(mut reader: impl Read, buf: &mut [u8]) -> Result<(), ReadError> {
    reader.read_exact(buf).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => ReadError::Invalid,
        _ => ReadError::Io(e),
    })
}

/// Writes the prefix and header of a CRX3 file.
pub(crate) fn write_header(mut out: impl Write, diff: bool, header: &[u8]) -> io::Result<()> {
    let header_len = u32::try_from(header.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CRX header too large"))?;
    out.write_all(if diff { &MAGIC_DIFF } else { &MAGIC })?;
    out.write_all(&VERSION.to_le_bytes())?;
    out.write_all(&header_len.to_le_bytes())?;
    out.write_all(header)
}

/// SHA-256 of the data every proof signs: the signature context, the signed
/// header data and the archive, fed in as it streams.
pub(crate) struct MessageHasher(Sha256);

impl MessageHasher {
    pub(crate) fn new(signed_header_data: &[u8]) -> Option<Self> {
        let len = u32::try_from(signed_header_data.len()).ok()?;
        let mut h = Sha256::new();
        h.update(SIGNATURE_CONTEXT);
        h.update(len.to_le_bytes());
        h.update(signed_header_data);
        Some(MessageHasher(h))
    }

    pub(crate) fn update(&mut self, archive_chunk: &[u8]) {
        self.0.update(archive_chunk);
    }

    pub(crate) fn finish(self) -> SignedDataDigest {
        SignedDataDigest::new(self.0.finalize().into())
    }
}

/// Feeds the rest of `reader` to `f` in chunks, returning the number of
/// bytes read.
pub(crate) fn stream(mut reader: impl Read, mut f: impl FnMut(&[u8])) -> io::Result<u64> {
    let mut buf = vec![0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                f(&buf[..n]);
                total += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Zip end-of-central-directory tokens. Chromium rejects headers that contain
/// any of them, since a zip reader could find them before the real archive.
const ZIP_TOKENS: [[u8; 4]; 3] = [*b"PK\x05\x06", *b"PK\x06\x07", *b"PK\x06\x06"];

pub(crate) fn contains_zip_token(header: &[u8]) -> bool {
    header.windows(4).any(|w| ZIP_TOKENS.iter().any(|t| w == t))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join(diff: bool, header: &[u8], archive: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_header(&mut out, diff, header).unwrap();
        out.extend(archive);
        out
    }

    #[test]
    fn splits_and_joins() {
        let bytes = join(false, b"hdr", b"PK\x03\x04");
        let parts = split(&bytes).unwrap();
        assert!(!parts.diff);
        assert_eq!(parts.header, b"hdr");
        assert_eq!(parts.archive, b"PK\x03\x04");
        assert!(split(&join(true, b"", b"x")).unwrap().diff);
    }

    #[test]
    fn rejects() {
        assert_eq!(split(b"Cr24"), Err(SplitError::Truncated));
        let mut bad = join(false, b"", b"");
        bad[0] = b'X';
        assert_eq!(split(&bad), Err(SplitError::BadMagic));
        let mut v2 = join(false, b"", b"");
        v2[4] = 2;
        assert_eq!(split(&v2), Err(SplitError::UnsupportedVersion(2)));
        let mut short = join(false, b"header", b"");
        short.pop();
        assert_eq!(split(&short), Err(SplitError::Truncated));
        let mut huge = join(false, b"", b"");
        huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(split(&huge), Err(SplitError::HeaderTooLarge));
    }

    #[test]
    fn zip_tokens() {
        assert!(contains_zip_token(b"xxPK\x05\x06xx"));
        assert!(contains_zip_token(b"PK\x06\x07"));
        assert!(contains_zip_token(b"PK\x06\x06"));
        assert!(!contains_zip_token(b"PK\x03\x04PK\x05"));
    }

    #[test]
    fn message_hash_matches_concatenation() {
        let mut h = MessageHasher::new(b"signed").unwrap();
        h.update(b"arch");
        h.update(b"ive");
        let mut msg = SIGNATURE_CONTEXT.to_vec();
        msg.extend(6u32.to_le_bytes());
        msg.extend(b"signedarchive");
        assert_eq!(
            h.finish().as_bytes(),
            &<[u8; 32]>::from(Sha256::digest(&msg))
        );
    }
}
