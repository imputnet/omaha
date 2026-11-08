use std::fmt;

/// Bounds applied while decoding untrusted requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_body_len: usize,
    pub max_apps: usize,
    pub max_string_len: usize,
    pub max_list_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_body_len: 1 << 20,
            max_apps: 256,
            max_string_len: 1024,
            max_list_len: 64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    TooLarge,
    TooManyApps,
    /// A string or list field exceeds its limit.
    FieldTooLong(&'static str),
    Syntax(String),
    UnsupportedProtocol(String),
    Missing(&'static str),
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
