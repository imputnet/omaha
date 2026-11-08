use std::fmt;
use std::str::FromStr;

/// A SHA-256 hash, written as lowercase hex on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256([u8; 32]);

impl Sha256 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Sha256(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseHashError;

impl fmt::Display for ParseHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid SHA-256 hex")
    }
}

impl std::error::Error for ParseHashError {}

impl FromStr for Sha256 {
    type Err = ParseHashError;

    fn from_str(s: &str) -> Result<Self, ParseHashError> {
        let s = s.as_bytes();

        if s.len() != 64 {
            return Err(ParseHashError);
        }

        let mut out = [0u8; 32];
        for (i, pair) in s.chunks(2).enumerate() {
            let digit = |c: u8| char::from(c).to_digit(16).ok_or(ParseHashError);
            out[i] = (digit(pair[0])? * 16 + digit(pair[1])?) as u8;
        }
        Ok(Sha256(out))
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut hex = [0u8; 64];
        for (pair, byte) in hex.as_chunks_mut::<2>().0.iter_mut().zip(self.0) {
            *pair = [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 0xf)],
            ];
        }
        f.write_str(std::str::from_utf8(&hex).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let hex = "b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116";
        let h: Sha256 = hex.parse().unwrap();
        assert_eq!(h.to_string(), hex);
        assert_eq!(hex.to_uppercase().parse::<Sha256>(), Ok(h));
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "1234",
            &"g".repeat(64),
            &"0".repeat(63),
            &"0".repeat(65),
        ] {
            assert_eq!(bad.parse::<Sha256>(), Err(ParseHashError), "{bad:?}");
        }
    }
}
