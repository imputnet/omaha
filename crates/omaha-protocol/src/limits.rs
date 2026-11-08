use std::fmt;

/// Bounds applied while decoding untrusted requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest request body or update2 query string, in bytes. Decoding can
    /// take several times this much memory. Default: 256 KiB, about three
    /// times what a browser sends for 256 apps.
    pub max_body_len: usize,
    /// Most apps in one request. Default: 256.
    pub max_apps: usize,
    /// Longest string member, in bytes. Default: 1024.
    pub max_string_len: usize,
    /// Longest list member, such as `cached_items` or `acceptformat`. Default:
    /// 64.
    pub max_list_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_body_len: 256 << 10,
            max_apps: 256,
            max_string_len: 1024,
            max_list_len: 64,
        }
    }
}

/// Why a request or response couldn't be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The body exceeds [`Limits::max_body_len`].
    TooLarge,
    /// More apps than [`Limits::max_apps`].
    TooManyApps,
    /// A string or list field exceeds its limit.
    FieldTooLong(&'static str),
    /// Malformed JSON, with the parser's message.
    Syntax(String),
    /// A `protocol` other than `4.0`; empty if the request has none.
    UnsupportedProtocol(String),
    /// A required member, by name, is absent.
    Missing(&'static str),
    /// A member, by name, has a value that doesn't parse or isn't allowed.
    Invalid(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooLarge => f.write_str("request too large"),
            DecodeError::TooManyApps => f.write_str("too many apps"),
            DecodeError::FieldTooLong(field) => write!(f, "{field} too long"),
            DecodeError::Syntax(e) => write!(f, "malformed request: {e}"),
            DecodeError::UnsupportedProtocol(v) => write!(f, "unsupported protocol {v:?}"),
            DecodeError::Missing(field) => write!(f, "missing {field}"),
            DecodeError::Invalid(field) => write!(f, "invalid {field}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Limits {
    pub(crate) fn string(
        &self,
        field: &'static str,
        s: Option<String>,
    ) -> Result<Option<String>, DecodeError> {
        match s {
            Some(s) if s.len() > self.max_string_len => Err(DecodeError::FieldTooLong(field)),
            s => Ok(s.filter(|s| !s.is_empty())),
        }
    }

    pub(crate) fn list<T>(&self, field: &'static str, v: Vec<T>) -> Result<Vec<T>, DecodeError> {
        if v.len() > self.max_list_len {
            return Err(DecodeError::FieldTooLong(field));
        }

        Ok(v)
    }
}
