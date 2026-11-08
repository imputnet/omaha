//! Working out the next index for a new CRX: its serial and expiry, which
//! releases to keep, and patches from earlier CRXs.

use omaha_diff::{DiffError, Differ, Format};
use omaha_protocol::{AppId, AttributeName, Sha256, Version};
use omaha_server::index::{File, Index, IndexError, Patch, PatchFormat, Release, Requirements};
use serde::Deserialize;
use sha2::Digest;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_MANIFEST_LEN: u64 = 1 << 20;

/// How releases are kept and patched.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Releases kept per app, including the new one. The newest release for
    /// each distinct set of requirements is kept beyond this.
    pub keep: usize,
    /// How many of the newest earlier releases to make patches from.
    pub patch_from: usize,
    /// Patches at least this fraction of the CRX's size are dropped.
    pub max_patch_ratio: f64,
    /// How long a published index stays valid.
    pub lifetime: Duration,
    /// Build on the stored index even if it has expired. Off by default,
    /// since an expired index in the store can be an old one put back by
    /// someone with write access, which publishing would sign anew.
    pub accept_expired: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            keep: 5,
            patch_from: 3,
            max_patch_ratio: 0.8,
            lifetime: Duration::from_secs(14 * 86400),
            accept_expired: false,
        }
    }
}

/// Why a CRX can't be added to an index, or an index refreshed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReleaseError {
    /// The CRX doesn't verify or its ID isn't a valid app ID; holds the
    /// reason.
    Crx(String),
    /// The archive has no readable `manifest.json` within 1 MiB, or its
    /// `version` is missing or invalid; holds the reason.
    Manifest(String),
    /// The app already has a release with this version.
    VersionExists(Version),
    /// A fetched CRX doesn't match its hash in the index.
    SourceMismatch(String),
    /// A patch tool failed, or its patch didn't reproduce the CRX.
    Diff(DiffError),
    /// The new index fails [`Index::check`].
    Index(IndexError),
    /// The previous index's serial is `u64::MAX`, so there is no next one.
    SerialOverflow,
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseError::Crx(e) => write!(f, "crx: {e}"),
            ReleaseError::Manifest(e) => write!(f, "manifest.json: {e}"),
            ReleaseError::VersionExists(v) => write!(f, "version {v} is already published"),
            ReleaseError::SourceMismatch(path) => write!(f, "{path} doesn't match its hash"),
            ReleaseError::Diff(e) => e.fmt(f),
            ReleaseError::Index(e) => e.fmt(f),
            ReleaseError::SerialOverflow => f.write_str("index serial overflow"),
        }
    }
}

impl std::error::Error for ReleaseError {}

/// A CRX ready to be added to an index.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// The extension ID, from the CRX's developer key.
    pub appid: AppId,
    /// The `version` in the archive's `manifest.json`.
    pub version: Version,
    /// SHA-256 of the whole CRX file.
    pub sha256: Sha256,
    /// The CRX file as given.
    pub crx: Vec<u8>,
}

impl Candidate {
    /// Verifies the CRX and reads its ID and its `manifest.json` version.
    pub fn new(crx: Vec<u8>) -> Result<Self, ReleaseError> {
        let verified = crx3::verify(&crx, &crx3::Policy::default())
            .map_err(|e| ReleaseError::Crx(e.to_string()))?;
        let appid = AppId::new(verified.id.to_string())
            .ok_or_else(|| ReleaseError::Crx("invalid ID".into()))?;
        let archive = crx3::split(&crx).map_err(|e| ReleaseError::Crx(e.to_string()))?;
        let version = manifest_version(archive.archive)?;
        Ok(Candidate {
            appid,
            version,
            sha256: sha256(&crx),
            crx,
        })
    }
}

fn manifest_version(archive: &[u8]) -> Result<Version, ReleaseError> {
    let err = |e: &dyn fmt::Display| ReleaseError::Manifest(e.to_string());
    let mut zip = zip::ZipArchive::new(Cursor::new(archive)).map_err(|e| err(&e))?;
    let mut json = Vec::new();
    zip.by_name("manifest.json")
        .map_err(|e| err(&e))?
        .take(MAX_MANIFEST_LEN)
        .read_to_end(&mut json)
        .map_err(|e| err(&e))?;

    #[derive(serde::Deserialize)]
    struct Manifest {
        version: String,
    }

    // Chromium reads manifests with JSON_PARSE_CHROMIUM_EXTENSIONS: comments,
    // `\x` escapes and newlines in strings, after an optional UTF-8 BOM.
    let json = json.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&json);
    let mut de = serde_json_lenient::Deserializer::from_slice_with_options(
        json, false, true, false, false, true,
    );
    de.set_allow_comments(true);
    let manifest = Manifest::deserialize(&mut de).map_err(|e| err(&e))?;
    de.end().map_err(|e| err(&e))?;
    manifest
        .version
        .parse()
        .map_err(|_| ReleaseError::Manifest(format!("invalid version {:?}", manifest.version)))
}

fn sha256(bytes: &[u8]) -> Sha256 {
    Sha256::from_bytes(sha2::Sha256::digest(bytes).into())
}

/// A file to upload before the index that refers to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upload {
    /// Path in the store: `<appid>/<sha256>.crx3` for a CRX,
    /// `<appid>/<sha256>/<from sha256>.<puff|zucc>` for a patch.
    pub path: String,
    /// The file's contents.
    pub bytes: Vec<u8>,
}

/// The next index, and the new files it refers to.
#[derive(Clone, Debug)]
pub struct Plan {
    /// The next index, with its serial and expiry set. Not yet signed.
    pub index: Index,
    /// The new CRX, then its patches, smallest first.
    pub uploads: Vec<Upload>,
}

/// What to publish alongside a CRX.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// What a client needs to be offered the release. Empty by default, which
    /// offers it to every client.
    pub requires: Requirements,
    /// Application-specific members sent with the update check result.
    pub attributes: BTreeMap<AttributeName, String>,
}

fn crx_path(appid: &AppId, sha256: &Sha256) -> String {
    format!("{appid}/{sha256}.crx3")
}

fn patch_path(appid: &AppId, to: &Sha256, from: &Sha256, format: Format) -> String {
    format!("{appid}/{to}/{from}.{}", format.operation_type())
}

fn expiry(now: SystemTime, lifetime: Duration) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(lifetime)
        .as_secs()
}

fn next(previous: Option<&Index>, policy: &Policy, now: SystemTime) -> Result<Index, ReleaseError> {
    let serial = match previous {
        Some(index) => index
            .serial
            .checked_add(1)
            .ok_or(ReleaseError::SerialOverflow)?,
        None => 1,
    };
    let mut index = previous.cloned().unwrap_or_else(|| Index::new(0, 0));
    index.serial = serial;
    index.expires = expiry(now, policy.lifetime);
    Ok(index)
}

/// The same index with the next serial and a new expiry, for re-signing
/// before it expires.
pub fn refresh(previous: &Index, policy: &Policy, now: SystemTime) -> Result<Index, ReleaseError> {
    next(Some(previous), policy, now)
}

/// The earlier CRXs of the candidate's app to make patches from: the newest
/// `patch_from` releases older than it.
pub fn patch_sources(
    previous: Option<&Index>,
    candidate: &Candidate,
    policy: &Policy,
) -> Vec<File> {
    let Some(releases) = previous.and_then(|index| index.apps.get(&candidate.appid)) else {
        return Vec::new();
    };

    let mut older: Vec<&Release> = releases
        .iter()
        .filter(|r| r.version < candidate.version)
        .collect();
    older.sort_by(|a, b| b.version.cmp(&a.version));
    older
        .into_iter()
        .take(policy.patch_from)
        .map(|r| r.crx.clone())
        .collect()
}

/// Adds `candidate` to the index, with patches from `sources` (the files
/// [`patch_sources`] named, with their contents) made by each of
/// `differs`.
///
/// The new release is always kept, as is the newest release for each
/// distinct set of requirements, so no client loses the last release it can
/// install. The newest others fill up to `policy.keep`. Files of dropped
/// releases are not deleted, since clients may still be downloading them.
pub fn add(
    previous: Option<&Index>,
    candidate: Candidate,
    options: Options,
    sources: &[(File, Vec<u8>)],
    differs: &[Differ],
    policy: &Policy,
    now: SystemTime,
) -> Result<Plan, ReleaseError> {
    let mut index = next(previous, policy, now)?;
    let releases = index.apps.entry(candidate.appid.clone()).or_default();

    if releases.iter().any(|r| r.version == candidate.version) {
        return Err(ReleaseError::VersionExists(candidate.version));
    }

    for (file, bytes) in sources {
        if sha256(bytes) != file.sha256 {
            return Err(ReleaseError::SourceMismatch(file.path.clone()));
        }
    }

    let patches = make_patches(&candidate, sources, differs, policy)?;
    let mut uploads = vec![Upload {
        path: crx_path(&candidate.appid, &candidate.sha256),
        bytes: candidate.crx.clone(),
    }];
    let mut release = Release::new(
        candidate.version.clone(),
        File {
            path: crx_path(&candidate.appid, &candidate.sha256),
            sha256: candidate.sha256,
            size: candidate.crx.len() as u64,
        },
    );
    release.requires = options.requires;
    release.attributes = options.attributes;

    for (format, from, bytes) in patches {
        let path = patch_path(&candidate.appid, &candidate.sha256, &from, format);
        release.patches.push(Patch {
            format: match format {
                Format::Puffin => PatchFormat::Puff,
                Format::Zucchini => PatchFormat::Zucc,
            },
            from,
            file: File {
                path: path.clone(),
                sha256: sha256(&bytes),
                size: bytes.len() as u64,
            },
        });
        uploads.push(Upload { path, bytes });
    }

    retain(releases, release, policy.keep);
    index.check().map_err(ReleaseError::Index)?;
    Ok(Plan { index, uploads })
}

fn retain(releases: &mut Vec<Release>, new: Release, keep: usize) {
    releases.sort_by(|a, b| b.version.cmp(&a.version));
    let mut kept = vec![new];
    let mut others = Vec::new();

    for release in releases.drain(..) {
        if kept.iter().any(|k| k.requires == release.requires) {
            others.push(release);
        } else {
            kept.push(release);
        }
    }

    let room = keep.saturating_sub(kept.len());
    kept.extend(others.into_iter().take(room));
    kept.sort_by(|a, b| b.version.cmp(&a.version));
    *releases = kept;
}

/// Every patch under the size limit, smallest first.
fn make_patches(
    candidate: &Candidate,
    sources: &[(File, Vec<u8>)],
    differs: &[Differ],
    policy: &Policy,
) -> Result<Vec<(Format, Sha256, Vec<u8>)>, ReleaseError> {
    let jobs: Vec<(&Differ, &File, &[u8])> = sources
        .iter()
        .filter(|(file, _)| file.sha256 != candidate.sha256)
        .flat_map(|(file, bytes)| differs.iter().map(move |d| (d, file, bytes.as_slice())))
        .collect();
    let results: Vec<Result<Vec<u8>, DiffError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .iter()
            .map(|(differ, _, from)| scope.spawn(|| differ.diff(from, &candidate.crx)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| {
                    Err(DiffError::Io(std::io::Error::other(
                        "patch thread panicked",
                    )))
                })
            })
            .collect()
    });

    let limit = candidate.crx.len() as f64 * policy.max_patch_ratio;
    let mut patches = Vec::new();

    for ((differ, file, _), result) in jobs.iter().zip(results) {
        let bytes = result.map_err(ReleaseError::Diff)?;

        if (bytes.len() as f64) < limit {
            patches.push((differ.format(), file.sha256, bytes));
        }
    }

    patches.sort_by_key(|(_, _, bytes)| bytes.len());
    Ok(patches)
}
