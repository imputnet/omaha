use std::fmt;

/// Magic bytes at the start of a CRX file.
pub const MAGIC: [u8; 4] = *b"Cr24";
/// Magic bytes at the start of a CRX differential update.
pub const MAGIC_DIFF: [u8; 4] = *b"CrOD";
/// Prefix of the data every CRX3 proof signs.
pub const SIGNATURE_CONTEXT: &[u8; 16] = b"CRX3 SignedData\0";

pub(crate) const VERSION: u32 = 3;
const PREFIX_LEN: usize = 12;

/// A CRX3 file split into its parts, borrowing from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crx<'a> {
    /// Whether this is a differential update (`CrOD`).
    pub diff: bool,
    /// The serialized `CrxFileHeader` protobuf.
    pub header: &'a [u8],
    /// The zip archive (or diff payload) after the header.
    pub archive: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SplitError {
    BadMagic,
    UnsupportedVersion(u32),
    Truncated,
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitError::BadMagic => f.write_str("not a CRX file"),
            SplitError::UnsupportedVersion(v) => write!(f, "unsupported CRX version {v}"),
            SplitError::Truncated => f.write_str("truncated CRX file"),
        }
    }
}

impl std::error::Error for SplitError {}

/// Splits a CRX3 file into header and archive. Does not parse or verify the
/// header.
pub fn split(bytes: &[u8]) -> Result<Crx<'_>, SplitError> {
    let prefix = bytes.get(..PREFIX_LEN).ok_or(SplitError::Truncated)?;
    let diff = match &prefix[0..4] {
        m if m == MAGIC => false,
        m if m == MAGIC_DIFF => true,
        _ => return Err(SplitError::BadMagic),
    };
    let version = u32::from_le_bytes(prefix[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(SplitError::UnsupportedVersion(version));
    }
    let header_len = u32::from_le_bytes(prefix[8..12].try_into().unwrap()) as usize;
    let rest = &bytes[PREFIX_LEN..];
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

/// Writes a CRX3 file from its parts.
pub(crate) fn join(diff: bool, header: &[u8], archive: &[u8]) -> Option<Vec<u8>> {
    let header_len = u32::try_from(header.len()).ok()?;
    let mut out = Vec::with_capacity(PREFIX_LEN + header.len() + archive.len());
    out.extend(if diff { MAGIC_DIFF } else { MAGIC });
    out.extend(VERSION.to_le_bytes());
    out.extend(header_len.to_le_bytes());
    out.extend(header);
    out.extend(archive);
    Some(out)
}

/// The bytes every proof signs.
pub(crate) fn signing_message(signed_header_data: &[u8], archive: &[u8]) -> Option<Vec<u8>> {
    let len = u32::try_from(signed_header_data.len()).ok()?;
    let mut msg =
        Vec::with_capacity(SIGNATURE_CONTEXT.len() + 4 + signed_header_data.len() + archive.len());
    msg.extend(SIGNATURE_CONTEXT);
    msg.extend(len.to_le_bytes());
    msg.extend(signed_header_data);
    msg.extend(archive);
    Some(msg)
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

    #[test]
    fn splits_and_joins() {
        let bytes = join(false, b"hdr", b"PK\x03\x04").unwrap();
        let parts = split(&bytes).unwrap();
        assert!(!parts.diff);
        assert_eq!(parts.header, b"hdr");
        assert_eq!(parts.archive, b"PK\x03\x04");
        assert!(split(&join(true, b"", b"x").unwrap()).unwrap().diff);
    }

    #[test]
    fn rejects() {
        assert_eq!(split(b"Cr24"), Err(SplitError::Truncated));
        let mut bad = join(false, b"", b"").unwrap();
        bad[0] = b'X';
        assert_eq!(split(&bad), Err(SplitError::BadMagic));
        let mut v2 = join(false, b"", b"").unwrap();
        v2[4] = 2;
        assert_eq!(split(&v2), Err(SplitError::UnsupportedVersion(2)));
        let mut short = join(false, b"header", b"").unwrap();
        short.pop();
        assert_eq!(split(&short), Err(SplitError::Truncated));
    }

    #[test]
    fn zip_tokens() {
        assert!(contains_zip_token(b"xxPK\x05\x06xx"));
        assert!(contains_zip_token(b"PK\x06\x07"));
        assert!(contains_zip_token(b"PK\x06\x06"));
        assert!(!contains_zip_token(b"PK\x03\x04PK\x05"));
    }
}
