use crate::index::{Index, OpenError, Verifier};
use crate::source::{BoxFuture, Check, Source};
use omaha_protocol::{AppId, AppResponse};
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// A [`Source`] answering from a signed [`Index`], which can be replaced
/// while the server runs.
///
/// Clones share the loaded index, so keep one to call
/// [`replace`](Self::replace) after handing another to an endpoint. The
/// index decides which apps it knows, so it usually goes in as the
/// endpoint's fallback.
///
/// Before the first index is loaded, every app is answered with
/// `error-internal`. An index that expires after it was loaded keeps
/// being served, and [`is_stale`](Self::is_stale) reports it.
#[derive(Clone)]
pub struct StaticIndex {
    inner: Arc<Inner>,
}

struct Inner {
    trusted: Vec<Box<dyn Verifier + Send + Sync>>,
    bases: Vec<String>,
    clock: fn() -> SystemTime,
    current: RwLock<Option<Arc<Index>>>,
}

/// What [`StaticIndex::replace`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replaced {
    /// The index is now served.
    Loaded {
        /// Serial of the newly loaded index.
        serial: u64,
    },
    /// The index was the one already loaded.
    Unchanged,
}

/// Why [`StaticIndex::replace`] kept the loaded index.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplaceError {
    /// The envelope didn't open: malformed, not signed by a trusted key, or
    /// expired.
    Open(OpenError),
    /// The index is older than the one loaded.
    Rollback {
        /// Serial of the index being served.
        loaded: u64,
        /// Serial of the rejected index.
        offered: u64,
    },
    /// The index has the loaded serial but different contents.
    Conflict {
        /// The serial both indexes share.
        serial: u64,
    },
}

impl fmt::Display for ReplaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplaceError::Open(e) => e.fmt(f),
            ReplaceError::Rollback { loaded, offered } => {
                write!(
                    f,
                    "index serial {offered} is older than the loaded {loaded}"
                )
            }
            ReplaceError::Conflict { serial } => {
                write!(
                    f,
                    "index serial {serial} is already loaded with other contents"
                )
            }
        }
    }
}

impl std::error::Error for ReplaceError {}

/// Configures a [`StaticIndex`].
pub struct StaticIndexBuilder {
    inner: Inner,
}

impl StaticIndex {
    /// Download URLs are an index path joined to each of `bases` in turn.
    pub fn builder<B: Into<String>>(bases: impl IntoIterator<Item = B>) -> StaticIndexBuilder {
        let bases = bases
            .into_iter()
            .map(|base| {
                let mut base = base.into();

                if !base.ends_with('/') {
                    base.push('/');
                }

                base
            })
            .collect();

        StaticIndexBuilder {
            inner: Inner {
                trusted: Vec::new(),
                bases,
                clock: SystemTime::now,
                current: RwLock::new(None),
            },
        }
    }
}

impl StaticIndexBuilder {
    /// Accepts indexes signed by `key`.
    pub fn trust(mut self, key: impl Verifier + Send + Sync + 'static) -> Self {
        self.inner.trusted.push(Box::new(key));
        self
    }

    /// The clock used to check expiry.
    pub fn clock(mut self, clock: fn() -> SystemTime) -> Self {
        self.inner.clock = clock;
        self
    }

    /// Finishes the source. It answers every app with `error-internal` until
    /// [`StaticIndex::replace`] loads an index.
    pub fn build(self) -> StaticIndex {
        StaticIndex {
            inner: Arc::new(self.inner),
        }
    }
}

impl StaticIndex {
    /// Opens a signed index and serves it if its serial is higher than the
    /// loaded one's.
    pub fn replace(&self, envelope: &[u8]) -> Result<Replaced, ReplaceError> {
        let inner = &self.inner;
        let trusted: Vec<&dyn Verifier> = inner
            .trusted
            .iter()
            .map(|k| k.as_ref() as &dyn Verifier)
            .collect();
        let index = Index::open(envelope, &trusted, (inner.clock)()).map_err(ReplaceError::Open)?;
        let mut current = inner
            .current
            .write()
            .unwrap_or_else(PoisonError::into_inner);

        if let Some(loaded) = current.as_deref() {
            if index.serial < loaded.serial {
                return Err(ReplaceError::Rollback {
                    loaded: loaded.serial,
                    offered: index.serial,
                });
            }

            if index.serial == loaded.serial && index == *loaded {
                return Ok(Replaced::Unchanged);
            }

            if index.serial == loaded.serial {
                return Err(ReplaceError::Conflict {
                    serial: index.serial,
                });
            }
        }

        let serial = index.serial;
        *current = Some(Arc::new(index));
        Ok(Replaced::Loaded { serial })
    }

    /// The loaded index, if any.
    pub fn current(&self) -> Option<Arc<Index>> {
        self.inner
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the loaded index has expired, meaning no newer one has been
    /// loaded in time.
    pub fn is_stale(&self) -> bool {
        let now = (self.inner.clock)()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.current().is_some_and(|index| now >= index.expires)
    }
}

impl Source for StaticIndex {
    fn check<'a>(&'a self, check: Check<'a>) -> BoxFuture<'a, Vec<AppResponse>> {
        let answers: Vec<AppResponse> = match self.current() {
            Some(index) => check
                .apps
                .iter()
                .map(|app| index.answer(check.protocol, check.client, app, &self.inner.bases))
                .collect(),
            None => Vec::new(),
        };
        Box::pin(async move { answers })
    }

    fn labels_app(&self, appid: &AppId) -> bool {
        self.current()
            .is_some_and(|index| index.apps.contains_key(appid))
    }
}
