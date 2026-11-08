//! A signed list of the releases a server offers, and how to answer update
//! checks from it.
//!
//! An index is JSON wrapped in a [DSSE] envelope:
//!
//! ```json
//! {
//!   "format": 1,
//!   "serial": 42,
//!   "expires": 1767225600,
//!   "apps": {
//!     "hfnkpimlhhgieaddgfemjhofmfblmnib": [
//!       {
//!         "version": "9001",
//!         "crx": { "path": "crlset/9001.crx3", "sha256": "…", "size": 1234 },
//!         "requires": { "prodversionmin": "120", "os": ["win", "mac", "linux"] },
//!         "patches": [
//!           { "format": "puff", "from": "…", "path": "crlset/9000-9001.puff", "sha256": "…", "size": 120 }
//!         ],
//!         "attributes": { "_example": "value" }
//!       }
//!     ]
//!   }
//! }
//! ```
//!
//! - `serial` must grow with every publish, so a server can refuse to go
//!   back to an older index.
//! - `expires` (Unix seconds) bounds how long an old index can be replayed
//!   to a server that has nothing loaded yet.
//! - Paths are relative. The server joins them to its download bases, so
//!   moving or mirroring the files doesn't need a new signature: the
//!   hashes pin the content.
//! - Unknown fields are rejected, so a server never ignores a requirement
//!   it doesn't understand.
//!
//! [DSSE]: https://github.com/secure-systems-lab/dsse

mod answer;
#[cfg(feature = "aws-lc")]
pub mod aws_lc;
mod envelope;

pub use envelope::{KeyId, OpenError, SignError, Signer, SigningInput, Verifier};

use omaha_protocol::{AppId, AttributeName, Sha256, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The index format this crate reads and writes.
pub const FORMAT: u32 = 1;

/// The DSSE payload type of an index.
pub const PAYLOAD_TYPE: &str = "application/vnd.omaha.index+json";

const MAX_PATH_LEN: usize = 1024;

/// A list of releases per app: the document inside the signed envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    /// Publish counter. Each new index needs a higher one, since
    /// [`StaticIndex`](crate::StaticIndex) refuses to go back to a lower
    /// serial.
    pub serial: u64,
    /// Unix seconds after which the index is no longer loaded.
    pub expires: u64,
    /// Every release of each app. Order doesn't matter.
    pub apps: BTreeMap<AppId, Vec<Release>>,
}

/// One version of an app, with the files that install it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// The version offered as `nextversion`, compared with the installed one.
    pub version: Version,
    /// The full CRX3 package.
    pub crx: File,
    /// What a client needs for this release to be offered. Empty by default,
    /// which offers it to every client.
    pub requires: Requirements,
    /// Patches to this release, in order of preference.
    pub patches: Vec<Patch>,
    /// Application-specific members sent with the update check result.
    pub attributes: BTreeMap<AttributeName, String>,
}

impl Release {
    /// A release with no requirements, patches or attributes.
    pub fn new(version: Version, crx: File) -> Self {
        Release {
            version,
            crx,
            requires: Requirements::default(),
            patches: Vec::new(),
            attributes: BTreeMap::new(),
        }
    }
}

/// A file the client downloads, by path and expected content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    /// Relative to the server's download bases.
    pub path: String,
    /// SHA-256 of the file's contents, which the client checks after
    /// downloading.
    pub sha256: Sha256,
    /// Size in bytes. Must not be zero.
    pub size: u64,
}

/// What a client needs to be offered a release. Empty lists allow any
/// value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Requirements {
    /// Lowest browser version (`prodversion`) offered the release. A client
    /// that doesn't send its version doesn't qualify.
    pub prodversionmin: Option<Version>,
    /// Values of the request's `@os`, e.g. `win`, `mac`, `linux`.
    pub os: Vec<String>,
    /// Values of the request's `arch`, the browser's architecture, e.g.
    /// `x64`, `arm64`.
    pub arch: Vec<String>,
}

/// A differential update to a release from an earlier CRX.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    /// Offered only to clients that list this format in `acceptformat`.
    pub format: PatchFormat,
    /// The SHA-256 of the CRX the patch applies to.
    pub from: Sha256,
    /// The patch file itself.
    pub file: File,
}

/// Differential patch formats Chromium's update client can apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PatchFormat {
    /// Made by Chromium's `puffin`, operation type `puff`.
    Puff,
    /// Made by Chromium's `zucchini`, operation type `zucc`.
    Zucc,
}

impl PatchFormat {
    /// The operation type in `acceptformat` and pipelines.
    pub fn as_str(self) -> &'static str {
        match self {
            PatchFormat::Puff => "puff",
            PatchFormat::Zucc => "zucc",
        }
    }
}

/// Why an index document doesn't parse or doesn't pass [`Index::check`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexError {
    /// The document isn't JSON of the index's shape, for example with a
    /// missing, mistyped or unknown field. Holds the parser's message.
    Json(String),
    /// `format` isn't [`FORMAT`]; holds the value found.
    UnsupportedFormat(u64),
    /// A value doesn't parse (app ID, version, hash, attribute name, patch
    /// format) or [`Index::check`] failed. Holds what was wrong, prefixed
    /// with the app ID where there is one.
    Invalid(String),
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexError::Json(e) => write!(f, "index: {e}"),
            IndexError::UnsupportedFormat(n) => write!(f, "index: unsupported format {n}"),
            IndexError::Invalid(e) => write!(f, "index: {e}"),
        }
    }
}

impl std::error::Error for IndexError {}

impl Index {
    /// An index with no apps. `expires` is in Unix seconds.
    pub fn new(serial: u64, expires: u64) -> Self {
        Index {
            serial,
            expires,
            apps: BTreeMap::new(),
        }
    }

    /// Parses and checks an unsigned index document.
    pub fn from_json(json: &[u8]) -> Result<Self, IndexError> {
        let format: wire::Format =
            serde_json::from_slice(json).map_err(|e| IndexError::Json(e.to_string()))?;

        if format.format != u64::from(FORMAT) {
            return Err(IndexError::UnsupportedFormat(format.format));
        }

        let doc: wire::Index =
            serde_json::from_slice(json).map_err(|e| IndexError::Json(e.to_string()))?;
        let index = Index::try_from(doc)?;
        index.check()?;
        Ok(index)
    }

    /// The unsigned index document.
    pub fn to_json(&self) -> Result<Vec<u8>, IndexError> {
        self.check()?;
        serde_json::to_vec_pretty(&wire::Index::from(self))
            .map_err(|e| IndexError::Json(e.to_string()))
    }

    /// Checks what the types can't: unique versions, safe relative paths,
    /// non-empty files, and patches that don't patch a CRX into itself.
    pub fn check(&self) -> Result<(), IndexError> {
        for (appid, releases) in &self.apps {
            let invalid = |what: String| IndexError::Invalid(format!("{appid}: {what}"));

            for (i, release) in releases.iter().enumerate() {
                if releases[..i].iter().any(|r| r.version == release.version) {
                    return Err(invalid(format!("duplicate version {}", release.version)));
                }

                check_file(&release.crx).map_err(invalid)?;

                for patch in &release.patches {
                    check_file(&patch.file).map_err(invalid)?;

                    if patch.from == release.crx.sha256 {
                        return Err(invalid(format!("{} patches to itself", release.version)));
                    }
                }

                let requires = &release.requires;
                let names = requires.os.iter().chain(&requires.arch);

                if let Some(bad) = names.into_iter().find(|n| !is_name(n)) {
                    return Err(invalid(format!("invalid os or arch {bad:?}")));
                }
            }
        }

        Ok(())
    }
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn check_file(file: &File) -> Result<(), String> {
    if file.size == 0 {
        return Err(format!("{} is empty", file.path));
    }

    if !is_relative_path(&file.path) {
        return Err(format!("invalid path {:?}", file.path));
    }

    Ok(())
}

/// A path made of non-empty, non-dot segments of URL-safe characters, so
/// that joining it to a base URL can't leave the base.
fn is_relative_path(path: &str) -> bool {
    path.len() <= MAX_PATH_LEN
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        })
}

impl TryFrom<wire::Index> for Index {
    type Error = IndexError;

    fn try_from(doc: wire::Index) -> Result<Self, IndexError> {
        let mut apps = BTreeMap::new();

        for (appid, releases) in doc.apps {
            let id = AppId::new(appid.clone())
                .ok_or_else(|| IndexError::Invalid(format!("invalid app ID {appid:?}")))?;
            let invalid = |what: String| IndexError::Invalid(format!("{appid}: {what}"));
            let releases = releases
                .into_iter()
                .map(|r| r.try_into().map_err(invalid))
                .collect::<Result<_, _>>()?;
            apps.insert(id, releases);
        }

        Ok(Index {
            serial: doc.serial,
            expires: doc.expires,
            apps,
        })
    }
}

impl TryFrom<wire::Release> for Release {
    type Error = String;

    fn try_from(r: wire::Release) -> Result<Self, String> {
        let version: Version = r
            .version
            .parse()
            .map_err(|_| format!("invalid version {:?}", r.version))?;
        let prodversionmin = r
            .requires
            .prodversionmin
            .map(|v| {
                v.parse()
                    .map_err(|_| format!("invalid prodversionmin {v:?}"))
            })
            .transpose()?;
        let attributes = r
            .attributes
            .into_iter()
            .map(|(name, value)| {
                AttributeName::new(name.clone())
                    .map(|n| (n, value))
                    .ok_or_else(|| format!("invalid attribute name {name:?}"))
            })
            .collect::<Result<_, _>>()?;
        let patches = r
            .patches
            .into_iter()
            .map(|p| {
                let format = match p.format.as_str() {
                    "puff" => PatchFormat::Puff,
                    "zucc" => PatchFormat::Zucc,
                    other => return Err(format!("unknown patch format {other:?}")),
                };
                Ok(Patch {
                    format,
                    from: parse_hash(&p.from)?,
                    file: File {
                        sha256: parse_hash(&p.sha256)?,
                        path: p.path,
                        size: p.size,
                    },
                })
            })
            .collect::<Result<_, String>>()?;

        Ok(Release {
            version,
            crx: r.crx.try_into()?,
            requires: Requirements {
                prodversionmin,
                os: r.requires.os,
                arch: r.requires.arch,
            },
            patches,
            attributes,
        })
    }
}

impl TryFrom<wire::File> for File {
    type Error = String;

    fn try_from(f: wire::File) -> Result<Self, String> {
        Ok(File {
            sha256: parse_hash(&f.sha256)?,
            path: f.path,
            size: f.size,
        })
    }
}

fn parse_hash(s: &str) -> Result<Sha256, String> {
    s.parse().map_err(|_| format!("invalid sha256 {s:?}"))
}

impl From<&Index> for wire::Index {
    fn from(index: &Index) -> Self {
        let file = |f: &File| wire::File {
            path: f.path.clone(),
            sha256: f.sha256.to_string(),
            size: f.size,
        };
        let release = |r: &Release| wire::Release {
            version: r.version.to_string(),
            crx: file(&r.crx),
            requires: wire::Requirements {
                prodversionmin: r.requires.prodversionmin.as_ref().map(Version::to_string),
                os: r.requires.os.clone(),
                arch: r.requires.arch.clone(),
            },
            patches: r
                .patches
                .iter()
                .map(|p| wire::Patch {
                    format: p.format.as_str().to_owned(),
                    from: p.from.to_string(),
                    path: p.file.path.clone(),
                    sha256: p.file.sha256.to_string(),
                    size: p.file.size,
                })
                .collect(),
            attributes: r
                .attributes
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.clone()))
                .collect(),
        };

        wire::Index {
            format: u64::from(FORMAT),
            serial: index.serial,
            expires: index.expires,
            apps: index
                .apps
                .iter()
                .map(|(id, releases)| {
                    (
                        id.as_str().to_owned(),
                        releases.iter().map(release).collect(),
                    )
                })
                .collect(),
        }
    }
}

mod wire {
    use super::*;

    #[derive(Deserialize)]
    pub struct Format {
        pub format: u64,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Index {
        pub format: u64,
        pub serial: u64,
        pub expires: u64,
        pub apps: BTreeMap<String, Vec<Release>>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Release {
        pub version: String,
        pub crx: File,
        #[serde(default, skip_serializing_if = "Requirements::is_empty")]
        pub requires: Requirements,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub patches: Vec<Patch>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub attributes: BTreeMap<String, String>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct File {
        pub path: String,
        pub sha256: String,
        pub size: u64,
    }

    #[derive(Default, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Requirements {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prodversionmin: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub os: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub arch: Vec<String>,
    }

    impl Requirements {
        fn is_empty(&self) -> bool {
            self.prodversionmin.is_none() && self.os.is_empty() && self.arch.is_empty()
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Patch {
        pub format: String,
        pub from: String,
        pub path: String,
        pub sha256: String,
        pub size: u64,
    }
}
