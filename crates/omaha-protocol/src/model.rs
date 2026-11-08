use crate::{AppId, Sha256, Version};
use std::collections::BTreeMap;
use std::fmt;

/// The wire format a request arrived in, and the one to answer in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Omaha 4 JSON (POST).
    V4,
    /// Legacy update2 (GET with `x=` parameters), answered with `gupdate`
    /// XML or, for installs, a redirect.
    Update2,
}

/// An update check, without any per-client identifiers: session and request
/// IDs, install IDs, install dates and ping data are never decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The wire format it arrived in, which the answer must use.
    pub protocol: Protocol,
    /// Request-level members, sent once for all apps.
    pub client: Client,
    /// The apps to check, or to report on in a ping-back.
    pub apps: Vec<App>,
}

/// Request-level members: which updater sent the request and where it runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Client {
    /// `@updater`, e.g. `chrome` or `chromecrx`.
    pub updater: Option<String>,
    /// The browser version.
    pub prodversion: Option<Version>,
    /// The updater's own version. Chromium's browser sends its version here
    /// too.
    pub updaterversion: Option<Version>,
    /// `@os`, e.g. `win`, `mac`, `linux`.
    pub os: Option<String>,
    /// Architecture of the updater itself, e.g. `x86`, `x64` or `arm64`. Under
    /// emulation it differs from the OS architecture in [`Platform::arch`].
    pub arch: Option<String>,
    /// The `os` object: platform, version and architecture.
    pub platform: Option<Platform>,
    /// Operation types the client can run, e.g. `crx3`, `download`, `puff`.
    pub acceptformat: Vec<String>,
    /// The browser's channel, e.g. `stable` or `beta`.
    pub prodchannel: Option<String>,
    /// The updater's distribution channel, e.g. `stable`, `beta`, `dev`,
    /// `canary` or `extended`.
    pub updaterchannel: Option<String>,
    /// Whether the updater is installed system-wide rather than per user.
    /// Unknown (`-1`) reads as `false`.
    pub ismachine: bool,
    /// Whether an x86 client runs on x64 Windows. Chromium sends it only when
    /// true.
    pub wow64: bool,
    /// Whether the device is enterprise-managed and follows group or cloud
    /// policy.
    pub domainjoined: Option<bool>,
    /// Download preference, e.g. `cacheable`.
    pub dlpref: Option<String>,
    /// CPU features and memory (`hw`).
    pub hw: Option<Hardware>,
}

impl Client {
    /// Whether `operation` is listed in `acceptformat`.
    pub fn accepts(&self, operation: &str) -> bool {
        self.acceptformat.iter().any(|f| f == operation)
    }
}

/// The `os` object: the operating system the client runs in. Spellings vary
/// between clients.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Platform {
    /// OS family, e.g. `win`, `mac`, `linux` or `Android`.
    pub platform: Option<String>,
    /// OS version, as the client formats it.
    pub version: Option<String>,
    /// OS architecture, e.g. `x86`, `x86_64`, `x64` or `arm64`.
    pub arch: Option<String>,
    /// `sp`: the service pack, e.g. `Service Pack 2` on Windows.
    pub service_pack: Option<String>,
    /// `deviceformfactor`, e.g. `desktop`, `phone`, `tablet` or `tv`.
    pub device_form_factor: Option<String>,
}

/// Hardware capabilities. `None` means unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hardware {
    /// Whether the CPU supports SSE.
    pub sse: Option<bool>,
    /// Whether the CPU supports SSE2.
    pub sse2: Option<bool>,
    /// Whether the CPU supports SSE3.
    pub sse3: Option<bool>,
    /// Whether the CPU supports SSE4.1.
    pub sse41: Option<bool>,
    /// Whether the CPU supports SSE4.2.
    pub sse42: Option<bool>,
    /// Whether the CPU supports SSSE3.
    pub ssse3: Option<bool>,
    /// Whether the CPU supports AVX.
    pub avx: Option<bool>,
    /// Physical memory in GiB, rounded down.
    pub physmemory: Option<u32>,
}

/// One app of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    /// The only member a client must send.
    pub appid: AppId,
    /// The installed version (update2's `v`). New installs send `0`.
    pub version: Option<Version>,
    /// Additional parameters: an opaque string the server uses to tell apart
    /// variants chosen at install time.
    pub ap: Option<String>,
    /// Brand code of the partner promotion behind the install, usually four
    /// uppercase letters.
    pub brand: Option<String>,
    /// The app's display language as a BCP 47 tag. update2 sends one `lang` for
    /// all apps.
    pub lang: Option<String>,
    /// The immediate cause of this request, e.g. `ondemand` for a
    /// user-initiated check; `None` for a background update.
    pub installsource: Option<String>,
    /// The original cause of the install. Chromium's extension updater sends
    /// `internal`, `external`, `policy` or `other`.
    pub installedby: Option<String>,
    /// The channel the app is switching to, e.g. `stable` or `beta`.
    pub release_channel: Option<String>,
    /// The cohort the server last assigned.
    pub cohort: Cohort,
    /// Whether the app is enabled, for apps such as extensions that can be
    /// disabled without being uninstalled. `None` if unknown.
    pub enabled: Option<bool>,
    /// `disabled[].reason` codes, whose meaning is client-specific. `0` means
    /// no reason.
    pub disabled_reasons: Vec<i64>,
    /// Hashes of payloads the client has cached, for differential updates.
    pub cached: Vec<Sha256>,
    /// `None` if the client won't act on an update, as in a ping-back.
    pub updatecheck: Option<UpdateCheck>,
    /// Requests for app-specific data, such as installer data.
    pub data: Vec<DataRequest>,
    /// Reports from a ping-back.
    pub events: Vec<Event>,
}

impl App {
    /// Whether this app is in a ping-back rather than an update check: it
    /// reports events and asks for no update check.
    pub fn is_pingback(&self) -> bool {
        self.updatecheck.is_none() && !self.events.is_empty()
    }

    /// An app with only its ID set.
    pub fn new(appid: AppId) -> Self {
        App {
            appid,
            version: None,
            ap: None,
            brand: None,
            lang: None,
            installsource: None,
            installedby: None,
            release_channel: None,
            cohort: Cohort::default(),
            enabled: None,
            disabled_reasons: Vec::new(),
            cached: Vec::new(),
            updatecheck: None,
            data: Vec::new(),
            events: Vec::new(),
        }
    }
}

/// A ping-back report about one operation of an update session. The
/// download URL that clients include is never decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// What the event reports on (`eventtype`).
    pub kind: EventType,
    /// `eventresult`. Default: error.
    pub result: EventResult,
    /// `errorcat`: the class of `error_code`, e.g. 1 for download, 3 for
    /// install and 5 for update check errors. `0` for none.
    pub error_category: i64,
    /// `errorcode`, whose meaning depends on `error_category`. `0` means
    /// success.
    pub error_code: i64,
    /// `extracode1`: more detail on the result, whose meaning depends on the
    /// error category and code.
    pub extra_code1: i64,
    /// `previousversion`: the version before the update, whether or not it
    /// succeeded.
    pub previous_version: Option<Version>,
    /// `nextversion`: the version the client tried to reach, whether or not it
    /// succeeded.
    pub next_version: Option<Version>,
    /// The `pipeline_id` of the pipeline the operation belongs to.
    pub pipeline_id: Option<String>,
    /// Statistics of a `download` event; `None` for other event types.
    pub download: Option<DownloadStats>,
}

impl Event {
    /// An event with no error codes, versions, pipeline or download statistics.
    pub fn new(kind: EventType, result: EventResult) -> Self {
        Event {
            kind,
            result,
            error_category: 0,
            error_code: 0,
            extra_code1: 0,
            previous_version: None,
            next_version: None,
            pipeline_id: None,
            download: None,
        }
    }
}

/// The `eventtype` of an [`Event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventType {
    /// `2`: an install session.
    Install,
    /// `3`: an update session.
    Update,
    /// `4`: an uninstall session.
    Uninstall,
    /// `14`: a `download` operation.
    Download,
    /// `60`: an `xz` operation.
    Xz,
    /// `61`: a `zucc` patch.
    Zucc,
    /// `62`: a `puff` patch.
    Puff,
    /// `63`: a `crx3` install.
    Crx3,
    /// `64`: an operation of an unknown type.
    UnknownOperation,
    /// `41`: an app command completed.
    AppCommand,
    /// `42`: a `run` operation.
    Run,
    /// A code the spec doesn't list.
    Other(i64),
}

impl EventType {
    /// The numeric `eventtype`.
    pub fn code(self) -> i64 {
        match self {
            EventType::Install => 2,
            EventType::Update => 3,
            EventType::Uninstall => 4,
            EventType::Download => 14,
            EventType::AppCommand => 41,
            EventType::Run => 42,
            EventType::Xz => 60,
            EventType::Zucc => 61,
            EventType::Puff => 62,
            EventType::Crx3 => 63,
            EventType::UnknownOperation => 64,
            EventType::Other(code) => code,
        }
    }

    /// Maps an `eventtype`, keeping unknown codes as [`EventType::Other`].
    pub fn from_code(code: i64) -> Self {
        match code {
            2 => EventType::Install,
            3 => EventType::Update,
            4 => EventType::Uninstall,
            14 => EventType::Download,
            41 => EventType::AppCommand,
            42 => EventType::Run,
            60 => EventType::Xz,
            61 => EventType::Zucc,
            62 => EventType::Puff,
            63 => EventType::Crx3,
            64 => EventType::UnknownOperation,
            other => EventType::Other(other),
        }
    }
}

/// The `eventresult` of an [`Event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventResult {
    /// `0`: the operation failed.
    Error,
    /// `1`: the operation succeeded.
    Success,
    /// `4`: the operation was cancelled, e.g. by the user.
    Cancelled,
    /// A code the spec doesn't list.
    Other(i64),
}

impl EventResult {
    /// The numeric `eventresult`.
    pub fn code(self) -> i64 {
        match self {
            EventResult::Error => 0,
            EventResult::Success => 1,
            EventResult::Cancelled => 4,
            EventResult::Other(code) => code,
        }
    }

    /// Maps an `eventresult`, keeping unknown codes as [`EventResult::Other`].
    pub fn from_code(code: i64) -> Self {
        match code {
            0 => EventResult::Error,
            1 => EventResult::Success,
            4 => EventResult::Cancelled,
            other => EventResult::Other(other),
        }
    }
}

/// Statistics a `download` event reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DownloadStats {
    /// `download_time_ms`: how long the download took, in milliseconds. `None`
    /// if unavailable.
    pub time_ms: Option<u64>,
    /// Bytes received from the download server.
    pub downloaded: u64,
    /// Size of the payload at the URL, in bytes.
    pub total: u64,
    /// The download stack, e.g. `direct` (Chromium's network stack), `bits` or
    /// `nsurlsession_background`.
    pub downloader: Option<String>,
}

/// An app's release cohort, as assigned by the server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cohort {
    /// `cohort`: an opaque, machine-readable ID of up to 1024 printable ASCII
    /// characters.
    pub id: Option<String>,
    /// `cohortname`: a human-readable name, which may be shown to the user.
    pub name: Option<String>,
    /// `cohorthint`: a request to move to another cohort, with app-specific
    /// values.
    pub hint: Option<String>,
}

/// The `updatecheck` object of a request: the client's intent to update.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateCheck {
    /// The client will ignore any update it's offered.
    pub updatedisabled: bool,
    /// The client accepts a downgrade, usually together with
    /// `targetversionprefix`.
    pub rollback_allowed: bool,
    /// The client asks to be updated to the version it has, e.g. for a repair,
    /// instead of `noupdate`.
    pub sameversionupdate: bool,
    /// Updates must match this prefix component by component: `1.2.3` matches
    /// `1.2.3.4` but not `1.2.34`.
    pub targetversionprefix: Option<String>,
}

/// A `data` object of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataRequest {
    /// `install`: asks for installer data, which the server hands back for
    /// the installer to use.
    Install {
        /// The key the server looks the data up by.
        index: String,
    },
    /// `untrusted`: free-form, unverified data, such as a metainstaller tag's
    /// `untrusteddata`.
    Untrusted {
        /// Sent as `#text`.
        text: String,
    },
}

/// The server's answer to a [`Request`], for an update check or a ping-back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// One per app in the request.
    pub apps: Vec<AppResponse>,
    /// The server's date, which clients store for user counting.
    pub daystart: Option<DayStart>,
    /// Identifies the server for diagnostics, e.g. `production` or `test`.
    pub server: Option<String>,
}

/// The server's current date, which clients send back on later requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayStart {
    /// Days since 2007-01-01 in the server's timezone.
    pub elapsed_days: u32,
    /// Seconds since the server's midnight. Part of update2's `daystart`;
    /// Chromium's extension downloader only uses it for update URLs on
    /// google.com, to date its pings.
    pub elapsed_seconds: Option<u32>,
}

/// The answer for one app of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppResponse {
    /// Echoes the request's app ID.
    pub appid: AppId,
    /// Whether the server recognized the app. Clients read the other members
    /// only for `ok`.
    pub status: AppStatus,
    /// New cohort values the client should store.
    pub cohort: Cohort,
    /// Answers to the request's `data` objects.
    pub data: Vec<DataResponse>,
    /// The answer to the request's `updatecheck`, if it had one.
    pub updatecheck: Option<UpdateCheckResponse>,
    /// Acknowledgements of a ping-back's events, one per event.
    pub events: Vec<EventStatus>,
}

impl AppResponse {
    /// An answer with no cohort, data, update check or events.
    pub fn new(appid: AppId, status: AppStatus) -> Self {
        AppResponse {
            appid,
            status,
            cohort: Cohort::default(),
            data: Vec::new(),
            updatecheck: None,
            events: Vec::new(),
        }
    }

    /// The answer to a ping-back: every event acknowledged.
    pub fn pingback(app: &App) -> Self {
        let mut response = AppResponse::new(app.appid.clone(), AppStatus::Ok);
        response.events = vec![EventStatus::Ok; app.events.len()];
        response
    }
}

/// The server's acknowledgement of one ping-back event.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventStatus {
    /// `ok`: the event was received.
    Ok,
    /// Any other status.
    Other(String),
}

impl EventStatus {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            EventStatus::Ok => "ok",
            EventStatus::Other(s) => s,
        }
    }
}

/// Whether the server recognized an app.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AppStatus {
    /// `ok`: the app is recognized.
    Ok,
    /// `restricted`: recognized, but policy such as export law keeps the server
    /// from answering.
    Restricted,
    /// `error-unknownApplication`: the server doesn't know the app ID.
    UnknownApplication,
    /// A status the spec doesn't list.
    Other(String),
}

impl AppStatus {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            AppStatus::Ok => "ok",
            AppStatus::Restricted => "restricted",
            AppStatus::UnknownApplication => "error-unknownApplication",
            AppStatus::Other(s) => s,
        }
    }

    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "ok" => AppStatus::Ok,
            "restricted" => AppStatus::Restricted,
            "error-unknownApplication" => AppStatus::UnknownApplication,
            other => AppStatus::Other(other.to_owned()),
        }
    }
}

/// The `updatecheck` object of a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateCheckResponse {
    /// The `status`, and for `ok`, what to update to.
    pub outcome: Outcome,
    /// Why the server answered as it did, for debugging, e.g. `update disabled
    /// by client`.
    pub info: Option<String>,
    /// Application-specific `_`-prefixed string members.
    pub attributes: BTreeMap<AttributeName, String>,
}

impl UpdateCheckResponse {
    /// An answer with no `info` or attributes.
    pub fn new(outcome: Outcome) -> Self {
        UpdateCheckResponse {
            outcome,
            info: None,
            attributes: BTreeMap::new(),
        }
    }
}

/// The outcome of an update check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `noupdate`: no update is available now.
    NoUpdate,
    /// `ok`: an update is available.
    Update {
        /// The version every pipeline leads to.
        nextversion: Version,
        /// Ways to get there, in order of preference; the client tries each
        /// until one succeeds.
        pipelines: Vec<Pipeline>,
    },
    /// An `error-*` status.
    Error(UpdateCheckError),
}

/// An `error-*` status of an update check.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateCheckError {
    /// `error-internal`: an unspecified server error.
    Internal,
    /// `error-hash`: the server has an update but no valid hash for it.
    Hash,
    /// `error-osnotsupported`: the client's OS can't run any version of the
    /// app.
    OsNotSupported,
    /// `error-hwnotsupported`: the client's hardware can't run any version of
    /// the app.
    HwNotSupported,
    /// `error-unsupportedprotocol`: the app needs a protocol feature this
    /// version lacks.
    UnsupportedProtocol,
    /// `error-inexpressible`: no pipeline can be built from the client's
    /// `acceptformat`.
    Inexpressible,
    /// A status the spec doesn't list.
    Other(String),
}

impl UpdateCheckError {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            UpdateCheckError::Internal => "error-internal",
            UpdateCheckError::Hash => "error-hash",
            UpdateCheckError::OsNotSupported => "error-osnotsupported",
            UpdateCheckError::HwNotSupported => "error-hwnotsupported",
            UpdateCheckError::UnsupportedProtocol => "error-unsupportedprotocol",
            UpdateCheckError::Inexpressible => "error-inexpressible",
            UpdateCheckError::Other(s) => s,
        }
    }

    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "error-internal" => UpdateCheckError::Internal,
            "error-hash" => UpdateCheckError::Hash,
            "error-osnotsupported" => UpdateCheckError::OsNotSupported,
            "error-hwnotsupported" => UpdateCheckError::HwNotSupported,
            "error-unsupportedprotocol" => UpdateCheckError::UnsupportedProtocol,
            "error-inexpressible" => UpdateCheckError::Inexpressible,
            other => UpdateCheckError::Other(other.to_owned()),
        }
    }
}

/// The name of an application-specific member, which must start with `_`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AttributeName(String);

impl AttributeName {
    /// Returns `None` unless `name` is `_` followed by ASCII letters, digits
    /// and underscores.
    pub fn new(name: impl Into<String>) -> Option<Self> {
        let name = name.into();
        let valid = name.len() > 1
            && name.starts_with('_')
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        valid.then_some(AttributeName(name))
    }

    /// The name, including the leading `_`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AttributeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Ways to reach the same result, in order of preference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pipeline {
    /// `pipeline_id`: names the strategy, e.g. `zucc:h1sha256->h2sha256`.
    /// Clients echo it in events; it needn't be unique.
    pub id: String,
    /// Run in order, each on the previous one's output.
    pub operations: Vec<Operation>,
}

impl Pipeline {
    /// The URLs, hash and size of the full CRX, if this pipeline is a plain
    /// download followed by a `crx3` install.
    pub fn full_crx(&self) -> Option<(&[String], &Sha256, u64)> {
        match self.operations.as_slice() {
            [
                Operation::Download { size, out, urls },
                Operation::Crx3 { input, .. },
            ] if out == input => Some((urls, out, *size)),
            _ => None,
        }
    }
}

/// One step of a [`Pipeline`]. The wire `type` is the variant name in
/// lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    /// Download the payload.
    Download {
        /// Payload size in bytes; must be greater than 0.
        size: u64,
        /// Expected hash of the downloaded bytes.
        out: Sha256,
        /// URLs to try in order, falling back to the next on a network or HTTP
        /// error or a hash or size mismatch.
        urls: Vec<String>,
    },
    /// Decompress the previous operation's output.
    Xz,
    /// Apply a Puffin patch from the previous operation to a cached file.
    Puff {
        /// Hash of the cached file to patch.
        previous: Sha256,
        /// Hash of the patched file.
        out: Sha256,
    },
    /// Apply a Zucchini patch from the previous operation to a cached file.
    Zucc {
        /// Hash of the cached file to patch.
        previous: Sha256,
        /// Hash of the patched file.
        out: Sha256,
    },
    /// Unpack and install the CRX3 from the previous operation.
    Crx3 {
        /// `in`: expected hash of the CRX3.
        input: Sha256,
        /// Size of the CRX3 in bytes.
        size: Option<u64>,
        /// Installer executable, or on macOS the directory holding the install
        /// scripts, relative to the CRX root. Clients that don't run
        /// installers, such as the extension updater, ignore it.
        path: Option<String>,
        /// Command line for the installer, as one string.
        arguments: Option<String>,
    },
    /// Run a binary of the installed app.
    Run {
        /// Path relative to the app's install directory, after any update
        /// earlier in the pipeline.
        path: String,
        /// Command line, as one string.
        arguments: Option<String>,
    },
    /// An operation type this crate doesn't know.
    Other {
        /// The wire `type`.
        kind: String,
    },
}

/// The answer to one [`DataRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataResponse {
    /// Echoes the request's `name`, e.g. `install`.
    pub name: String,
    /// Echoes the request's `index`, if it was valid.
    pub index: Option<String>,
    /// The outcome of the lookup. Default: `ok`.
    pub status: DataStatus,
    /// `#text`: the requested data.
    pub text: Option<String>,
}

/// The outcome of a data lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataStatus {
    /// `ok`: `text` holds the data, which may be empty.
    Ok,
    /// `error-invalidargs`: the request couldn't be parsed or understood.
    InvalidArgs,
    /// `error-nodata`: nothing is stored under that index, as opposed to an
    /// empty value.
    NoData,
    /// A status the spec doesn't list.
    Other(String),
}

impl DataStatus {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            DataStatus::Ok => "ok",
            DataStatus::InvalidArgs => "error-invalidargs",
            DataStatus::NoData => "error-nodata",
            DataStatus::Other(s) => s,
        }
    }

    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "ok" => DataStatus::Ok,
            "error-invalidargs" => DataStatus::InvalidArgs,
            "error-nodata" => DataStatus::NoData,
            other => DataStatus::Other(other.to_owned()),
        }
    }
}
