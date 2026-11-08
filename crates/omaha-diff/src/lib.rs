//! Differential updates for Chromium's update protocol: making patches with
//! Chromium's own `puffin` and `zucchini` tools.
//!
//! Neither tool has a Rust implementation, so [`Differ`] runs a binary built
//! from the Chromium tree. Every patch is applied again with the same
//! binary and must reproduce the target exactly before it is returned.

// Compile the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Patch formats Chromium's update client can apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// `puffin` patches (operation type `puff`), for CRX files: deflate
    /// streams in the archive are decoded before diffing, so patches stay
    /// small.
    Puffin,
    /// `zucchini` patches (operation type `zucc`), for executables.
    Zucchini,
}

impl Format {
    /// The operation `type` in an Omaha 4 pipeline.
    pub fn operation_type(self) -> &'static str {
        match self {
            Format::Puffin => "puff",
            Format::Zucchini => "zucc",
        }
    }
}

/// Why [`Differ::diff`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum DiffError {
    /// Writing the inputs to the temporary directory, starting the tool, or
    /// reading its output failed. A missing binary ends up here.
    Io(std::io::Error),
    /// The tool exited unsuccessfully.
    Failed {
        /// `"make"` when creating the patch, `"apply"` when checking it.
        step: &'static str,
        /// The tool's exit status as displayed, e.g. `exit status: 1`.
        status: String,
        /// The tool's standard error, lossily decoded and trimmed.
        stderr: String,
    },
    /// Applying the patch didn't give back the target.
    Mismatch,
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiffError::Io(e) => write!(f, "diff: {e}"),
            DiffError::Failed {
                step,
                status,
                stderr,
            } => write!(f, "diff: {step} failed ({status}): {stderr}"),
            DiffError::Mismatch => f.write_str("diff: the patch doesn't reproduce the target"),
        }
    }
}

impl std::error::Error for DiffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DiffError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DiffError {
    fn from(e: std::io::Error) -> Self {
        DiffError::Io(e)
    }
}

/// Makes patches with one of Chromium's patch tools.
#[derive(Clone, Debug)]
pub struct Differ {
    format: Format,
    binary: PathBuf,
}

impl Differ {
    /// `binary` is Chromium's `puffin` (`third_party/puffin`).
    pub fn puffin(binary: impl Into<PathBuf>) -> Self {
        Differ {
            format: Format::Puffin,
            binary: binary.into(),
        }
    }

    /// `binary` is Chromium's `zucchini` (`components/zucchini`).
    pub fn zucchini(binary: impl Into<PathBuf>) -> Self {
        Differ {
            format: Format::Zucchini,
            binary: binary.into(),
        }
    }

    /// The patch format this differ makes, set by [`Differ::puffin`] or
    /// [`Differ::zucchini`].
    pub fn format(&self) -> Format {
        self.format
    }

    /// A patch turning the CRX `from` into the CRX `to`, checked by applying
    /// it.
    pub fn diff(&self, from: &[u8], to: &[u8]) -> Result<Vec<u8>, DiffError> {
        let dir = tempfile::tempdir()?;
        let old = dir.path().join("old.crx3");
        let new = dir.path().join("new.crx3");
        let patch = dir.path().join("patch");
        let check = dir.path().join("check.crx3");
        std::fs::write(&old, from)?;
        std::fs::write(&new, to)?;

        let (old, new, patch, check) = (&*old, &*new, &*patch, &*check);
        let (make, apply) = match self.format {
            Format::Puffin => (
                [Path::new("-puffdiff"), old, new, patch],
                [Path::new("-puffpatch"), old, check, patch],
            ),
            Format::Zucchini => (
                [Path::new("-gen"), old, new, patch],
                [Path::new("-apply"), old, patch, check],
            ),
        };
        self.run("make", &make, dir.path())?;
        self.run("apply", &apply, dir.path())?;

        if std::fs::read(check)? != to {
            return Err(DiffError::Mismatch);
        }

        Ok(std::fs::read(patch)?)
    }

    fn run(&self, step: &'static str, args: &[&Path], dir: &Path) -> Result<(), DiffError> {
        let Output { status, stderr, .. } = Command::new(&self.binary)
            .args(args)
            .current_dir(dir)
            .env_clear()
            .output()?;

        if status.success() {
            return Ok(());
        }

        Err(DiffError::Failed {
            step,
            status: status.to_string(),
            stderr: String::from_utf8_lossy(&stderr).trim().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_types() {
        assert_eq!(Format::Puffin.operation_type(), "puff");
        assert_eq!(Format::Zucchini.operation_type(), "zucc");
    }

    #[test]
    fn reports_a_missing_binary() {
        let differ = Differ::puffin("/nonexistent/puffin");
        assert!(matches!(differ.diff(b"a", b"b"), Err(DiffError::Io(_))));
    }
}
