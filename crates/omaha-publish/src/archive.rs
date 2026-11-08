//! Deterministic zip archives, depending only on file paths and contents,
//! ready to be signed as a CRX.

use std::collections::HashSet;
use std::fmt;
use std::io::{Cursor, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

/// How archive entries are stored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compression {
    /// Uncompressed. Best for content that doesn't compress, and gives the
    /// same bytes with any version of this crate.
    Stored,
    /// Deflated at the highest level. The same inputs give the same bytes
    /// as long as the deflate implementation doesn't change.
    #[default]
    Deflated,
}

/// Why [`archive`] or [`read_dir`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArchiveError {
    /// A path can't go in an archive.
    Path(PathError),
    /// Reading the directory or one of its files failed.
    Io(std::io::Error),
    /// The zip writer failed; holds its message.
    Zip(String),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::Path(e) => e.fmt(f),
            ArchiveError::Io(e) => write!(f, "archive: {e}"),
            ArchiveError::Zip(e) => write!(f, "archive: {e}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<PathError> for ArchiveError {
    fn from(e: PathError) -> Self {
        ArchiveError::Path(e)
    }
}

impl From<std::io::Error> for ArchiveError {
    fn from(e: std::io::Error) -> Self {
        ArchiveError::Io(e)
    }
}

fn zip_err(e: impl fmt::Display) -> ArchiveError {
    ArchiveError::Zip(e.to_string())
}

/// Why a path can't go in an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathError {
    /// Empty, absolute, or containing `.`/`..` segments, empty segments,
    /// backslashes or NUL.
    Unsafe(String),
    /// The same path appears more than once.
    Duplicate(String),
    /// A directory entry that is neither a file nor a directory, such as a
    /// symlink.
    NotAFile(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Unsafe(p) => write!(f, "unsafe archive path {p:?}"),
            PathError::Duplicate(p) => write!(f, "duplicate archive path {p:?}"),
            PathError::NotAFile(p) => write!(f, "{p:?} is not a regular file"),
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

/// A zip archive of `files` that depends only on their paths and contents:
/// entries in byte order of their paths, a 1980-01-01 timestamp and `0644`
/// permissions.
pub fn archive<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    compression: Compression,
) -> Result<Vec<u8>, ArchiveError> {
    let files: Vec<(&str, &[u8])> = files.into_iter().collect();
    let order = archive_order(files.iter().map(|(path, _)| *path))?;
    let options = SimpleFileOptions::default()
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644)
        .large_file(false);
    let options = match compression {
        Compression::Stored => options.compression_method(CompressionMethod::Stored),
        Compression::Deflated => options
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(9)),
    };
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));

    for path in order {
        let data = files
            .iter()
            .find(|(p, _)| *p == path)
            .map_or(&[][..], |(_, data)| *data);
        zip.start_file(path, options).map_err(zip_err)?;
        zip.write_all(data)?;
    }

    Ok(zip.finish().map_err(zip_err)?.into_inner())
}

/// Every regular file below `dir`, as archive paths with their contents.
/// Symlinks and other special files are refused rather than followed.
pub fn read_dir(dir: &Path) -> Result<Vec<(String, Vec<u8>)>, ArchiveError> {
    let mut files = Vec::new();
    let mut pending = vec![(dir.to_path_buf(), String::new())];

    while let Some((path, prefix)) = pending.pop() {
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| PathError::Unsafe(name.to_string_lossy().into_owned()))?;
            let archive_path = format!("{prefix}{name}");
            let kind = entry.file_type()?;

            if kind.is_dir() {
                pending.push((entry.path(), format!("{archive_path}/")));
            } else if kind.is_file() {
                files.push((archive_path, std::fs::read(entry.path())?));
            } else {
                return Err(PathError::NotAFile(archive_path).into());
            }
        }
    }

    files.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(files)
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
