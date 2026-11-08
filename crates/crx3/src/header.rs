use std::fmt;

/// Magic bytes at the start of a CRX file.
pub const MAGIC: [u8; 4] = *b"Cr24";
/// Magic bytes at the start of a CRX differential update.
pub const MAGIC_DIFF: [u8; 4] = *b"CrOD";
/// Prefix of the data every CRX3 proof signs.
pub const SIGNATURE_CONTEXT: &[u8; 16] = b"CRX3 SignedData\0";

const VERSION: u32 = 3;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn crx(magic: &[u8; 4], version: u32, header: &[u8], archive: &[u8]) -> Vec<u8> {
        let mut out = magic.to_vec();
        out.extend(version.to_le_bytes());
        out.extend((header.len() as u32).to_le_bytes());
        out.extend(header);
        out.extend(archive);
        out
    }

    #[test]
    fn splits() {
        let bytes = crx(&MAGIC, 3, b"hdr", b"PK\x03\x04");
        let parts = split(&bytes).unwrap();
        assert!(!parts.diff);
        assert_eq!(parts.header, b"hdr");
        assert_eq!(parts.archive, b"PK\x03\x04");
    }

    #[test]
    fn splits_diff() {
        let bytes = crx(&MAGIC_DIFF, 3, b"", b"x");
        assert!(split(&bytes).unwrap().diff);
    }

    #[test]
    fn rejects() {
        assert_eq!(split(b"Cr24"), Err(SplitError::Truncated));
        assert_eq!(
            split(&crx(b"PK\x03\x04", 3, b"", b"")),
            Err(SplitError::BadMagic)
        );
        assert_eq!(
            split(&crx(&MAGIC, 2, b"", b"")),
            Err(SplitError::UnsupportedVersion(2))
        );
        let mut short = crx(&MAGIC, 3, b"header", b"");
        short.truncate(short.len() - 1);
        assert_eq!(split(&short), Err(SplitError::Truncated));
    }
}
