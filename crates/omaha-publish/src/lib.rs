//! Building component feeds for Chromium's update protocol.

use std::collections::HashSet;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathError {
    /// Empty, absolute, or containing `.`/`..` segments, empty segments,
    /// backslashes or NUL.
    Unsafe(String),
    Duplicate(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Unsafe(p) => write!(f, "unsafe archive path {p:?}"),
            PathError::Duplicate(p) => write!(f, "duplicate archive path {p:?}"),
        }
    }
}

impl std::error::Error for PathError {}

fn is_safe(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\0'])
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Checks payload paths and returns them in the byte order used for
/// deterministic archives, so the same payload always packs to the same
/// bytes.
pub fn archive_order<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<&'a str>, PathError> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        if !is_safe(path) {
            return Err(PathError::Unsafe(path.to_owned()));
        }

        if !seen.insert(path) {
            return Err(PathError::Duplicate(path.to_owned()));
        }

        out.push(path);
    }
    out.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders() {
        assert_eq!(
            archive_order([
                "manifest.json",
                "_locales/en/messages.json",
                "Z.js",
                "a/b.js"
            ]),
            Ok(vec![
                "Z.js",
                "_locales/en/messages.json",
                "a/b.js",
                "manifest.json"
            ])
        );
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "./a",
            "a/",
            "a\\b",
            "a\0b",
        ] {
            assert_eq!(
                archive_order([bad]),
                Err(PathError::Unsafe(bad.to_owned())),
                "{bad:?}"
            );
        }
        assert_eq!(
            archive_order(["a", "a"]),
            Err(PathError::Duplicate("a".to_owned()))
        );
    }
}
