use crate::release::{self, Candidate, Options, Plan, Policy, ReleaseError, Upload, patch_sources};
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use omaha_diff::Differ;
use omaha_server::index::{File, Index, MAX_ENVELOPE_LEN, OpenError, SignError, Signer, Verifier};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Why reading or writing a feed failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// The object store failed, a path isn't a valid object path, or
    /// [`Store::refresh`] found no index.
    Store(object_store::Error),
    /// The stored index isn't signed by a trusted key or isn't a valid index.
    Index(OpenError),
    /// Signing the new index failed.
    Sign(SignError),
    /// The CRX couldn't be added or the index couldn't be refreshed.
    Release(ReleaseError),
    /// A file already exists at a path with different contents.
    Conflict(String),
    /// Someone else published since the current index was read.
    Raced,
    /// The stored index has expired, and the policy doesn't accept
    /// building on an expired one.
    Expired {
        /// When it expired, in Unix seconds.
        expires: u64,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Store(e) => e.fmt(f),
            StoreError::Index(e) => e.fmt(f),
            StoreError::Sign(e) => e.fmt(f),
            StoreError::Release(e) => e.fmt(f),
            StoreError::Conflict(path) => write!(f, "{path} exists with other contents"),
            StoreError::Raced => f.write_str("the index changed while publishing; try again"),
            StoreError::Expired { expires } => write!(
                f,
                "the stored index expired at {expires}; check it wasn't replaced with an old one, \
                 then accept it explicitly"
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<object_store::Error> for StoreError {
    fn from(e: object_store::Error) -> Self {
        StoreError::Store(e)
    }
}

impl From<ReleaseError> for StoreError {
    fn from(e: ReleaseError) -> Self {
        StoreError::Release(e)
    }
}

fn unexpired(
    current: Option<&Current>,
    policy: &Policy,
    now: SystemTime,
) -> Result<(), StoreError> {
    let now = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());

    match current {
        Some(c) if !policy.accept_expired && now >= c.index.expires => Err(StoreError::Expired {
            expires: c.index.expires,
        }),
        _ => Ok(()),
    }
}

/// The index currently in a store, and the version to replace.
pub struct Current {
    /// The stored index. Its signature is checked, its expiry isn't.
    pub index: Index,
    version: UpdateVersion,
}

/// A feed in object storage: content-addressed files that are never
/// overwritten, and one signed index referring to them.
pub struct Store {
    store: Arc<dyn ObjectStore>,
    index: Path,
}

impl Store {
    /// A feed in `store` with its index at `index_path`. Fails if
    /// `index_path` isn't a valid object path.
    pub fn new(store: Arc<dyn ObjectStore>, index_path: &str) -> Result<Self, StoreError> {
        Ok(Store {
            store,
            index: Path::parse(index_path).map_err(object_store::Error::from)?,
        })
    }

    /// The current index, checked against `trusted` but not for expiry, so
    /// an expired index can still be replaced.
    pub async fn current(&self, trusted: &[&dyn Verifier]) -> Result<Option<Current>, StoreError> {
        let result = match self.store.get(&self.index).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if result.meta.size > MAX_ENVELOPE_LEN {
            return Err(StoreError::Index(OpenError::Envelope(
                "larger than 16 MiB".into(),
            )));
        }

        let version = UpdateVersion {
            e_tag: result.meta.e_tag.clone(),
            version: result.meta.version.clone(),
        };
        let bytes = result.bytes().await?;
        let index = Index::verify(&bytes, trusted).map_err(StoreError::Index)?;
        Ok(Some(Current { index, version }))
    }

    /// The contents of a file the index refers to. Its size must match the
    /// index; its hash isn't checked here.
    pub async fn fetch(&self, file: &File) -> Result<Vec<u8>, StoreError> {
        let path = Path::parse(&file.path).map_err(object_store::Error::from)?;
        let result = self.store.get(&path).await?;

        if result.meta.size != file.size {
            return Err(ReleaseError::SourceMismatch(file.path.clone()).into());
        }

        Ok(result.bytes().await?.to_vec())
    }

    /// Writes a file unless it exists. An existing file must have the same
    /// contents.
    pub async fn upload(&self, upload: &Upload) -> Result<(), StoreError> {
        let path = Path::parse(&upload.path).map_err(object_store::Error::from)?;
        let options = PutOptions {
            mode: PutMode::Create,
            ..PutOptions::default()
        };

        match self
            .store
            .put_opts(&path, PutPayload::from(upload.bytes.clone()), options)
            .await
        {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let existing = self.store.get(&path).await?.bytes().await?;

                if existing.as_ref() == upload.bytes.as_slice() {
                    Ok(())
                } else {
                    Err(StoreError::Conflict(upload.path.clone()))
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Signs `index` and writes it, if the stored index is still `replacing`.
    /// Stores without conditional writes, such as the local filesystem,
    /// overwrite instead, so two publishers must not run at once there.
    pub async fn write_index(
        &self,
        index: &Index,
        signers: &[&dyn Signer],
        replacing: Option<&Current>,
    ) -> Result<(), StoreError> {
        let signed = index.sign(signers).map_err(StoreError::Sign)?;
        let mode = match replacing {
            Some(current) => PutMode::Update(current.version.clone()),
            None => PutMode::Create,
        };
        let put = |mode| {
            let options = PutOptions {
                mode,
                ..PutOptions::default()
            };
            self.store
                .put_opts(&self.index, PutPayload::from(signed.clone()), options)
        };

        match put(mode).await {
            Ok(_) => Ok(()),
            Err(object_store::Error::NotImplemented { .. }) => {
                put(PutMode::Overwrite).await?;
                Ok(())
            }
            Err(
                object_store::Error::AlreadyExists { .. }
                | object_store::Error::Precondition { .. },
            ) => Err(StoreError::Raced),
            Err(e) => Err(e.into()),
        }
    }

    /// Adds a CRX to the feed: uploads it and its patches, then the new
    /// index. Patches are made on the calling thread.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish(
        &self,
        crx: Vec<u8>,
        options: Options,
        signers: &[&dyn Signer],
        trusted: &[&dyn Verifier],
        differs: &[Differ],
        policy: &Policy,
        now: SystemTime,
    ) -> Result<Plan, StoreError> {
        let current = self.current(trusted).await?;
        unexpired(current.as_ref(), policy, now)?;
        let previous = current.as_ref().map(|c| &c.index);
        let candidate = Candidate::new(crx)?;
        let mut sources = Vec::new();

        if !differs.is_empty() {
            for file in patch_sources(previous, &candidate, policy) {
                let bytes = self.fetch(&file).await?;
                sources.push((file, bytes));
            }
        }

        let plan = release::add(previous, candidate, options, &sources, differs, policy, now)?;

        for upload in &plan.uploads {
            self.upload(upload).await?;
        }

        self.write_index(&plan.index, signers, current.as_ref())
            .await?;
        Ok(plan)
    }

    /// Re-signs the current index with the next serial and a new expiry.
    pub async fn refresh(
        &self,
        signers: &[&dyn Signer],
        trusted: &[&dyn Verifier],
        policy: &Policy,
        now: SystemTime,
    ) -> Result<Index, StoreError> {
        let current = self.current(trusted).await?.ok_or(StoreError::Store(
            object_store::Error::NotFound {
                path: self.index.to_string(),
                source: "no index to refresh".into(),
            },
        ))?;
        unexpired(Some(&current), policy, now)?;
        let index = release::refresh(&current.index, policy, now)?;
        self.write_index(&index, signers, Some(&current)).await?;
        Ok(index)
    }
}
