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
    pub protocol: Protocol,
    pub client: Client,
    pub apps: Vec<App>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Client {
    /// `@updater`, e.g. `chrome` or `chromecrx`.
    pub updater: Option<String>,
    /// The browser version.
    pub prodversion: Option<Version>,
    pub updaterversion: Option<Version>,
    /// `@os`, e.g. `win`, `mac`, `linux`.
    pub os: Option<String>,
    pub arch: Option<String>,
    /// The `os` object: platform, version and architecture.
    pub platform: Option<Platform>,
    /// Operation types the client can run, e.g. `crx3`, `download`, `puff`.
    pub acceptformat: Vec<String>,
    pub prodchannel: Option<String>,
    pub updaterchannel: Option<String>,
    pub ismachine: bool,
    pub wow64: bool,
    pub domainjoined: Option<bool>,
    /// Download preference, e.g. `cacheable`.
    pub dlpref: Option<String>,
    pub hw: Option<Hardware>,
}

impl Client {
    pub fn accepts(&self, operation: &str) -> bool {
        self.acceptformat.iter().any(|f| f == operation)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Platform {
    pub platform: Option<String>,
    pub version: Option<String>,
    pub arch: Option<String>,
    pub service_pack: Option<String>,
    pub device_form_factor: Option<String>,
}

/// Hardware capabilities. `None` means unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hardware {
    pub sse: Option<bool>,
    pub sse2: Option<bool>,
    pub sse3: Option<bool>,
    pub sse41: Option<bool>,
    pub sse42: Option<bool>,
    pub ssse3: Option<bool>,
    pub avx: Option<bool>,
    /// Physical memory in GiB, rounded down.
    pub physmemory: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    pub appid: AppId,
    pub version: Option<Version>,
    pub ap: Option<String>,
    pub brand: Option<String>,
    pub lang: Option<String>,
    pub installsource: Option<String>,
    pub installedby: Option<String>,
    pub release_channel: Option<String>,
    pub cohort: Cohort,
    pub enabled: Option<bool>,
    pub disabled_reasons: Vec<i64>,
    /// Hashes of payloads the client has cached, for differential updates.
    pub cached: Vec<Sha256>,
    pub updatecheck: Option<UpdateCheck>,
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
    pub kind: EventType,
    pub result: EventResult,
    pub error_category: i64,
    pub error_code: i64,
    pub extra_code1: i64,
    pub previous_version: Option<Version>,
    pub next_version: Option<Version>,
    pub pipeline_id: Option<String>,
    pub download: Option<DownloadStats>,
}

impl Event {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventType {
    Install,
    Update,
    Uninstall,
    Download,
    Xz,
    Zucc,
    Puff,
    Crx3,
    UnknownOperation,
    AppCommand,
    Run,
    Other(i64),
}

impl EventType {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventResult {
    Error,
    Success,
    Cancelled,
    Other(i64),
}

impl EventResult {
    pub fn code(self) -> i64 {
        match self {
            EventResult::Error => 0,
            EventResult::Success => 1,
            EventResult::Cancelled => 4,
            EventResult::Other(code) => code,
        }
    }

    pub fn from_code(code: i64) -> Self {
        match code {
            0 => EventResult::Error,
            1 => EventResult::Success,
            4 => EventResult::Cancelled,
            other => EventResult::Other(other),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DownloadStats {
    pub time_ms: Option<u64>,
    pub downloaded: u64,
    pub total: u64,
    pub downloader: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cohort {
    pub id: Option<String>,
    pub name: Option<String>,
    pub hint: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateCheck {
    pub updatedisabled: bool,
    pub rollback_allowed: bool,
    pub sameversionupdate: bool,
    pub targetversionprefix: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataRequest {
    Install { index: String },
    Untrusted { text: String },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    pub apps: Vec<AppResponse>,
    pub daystart: Option<DayStart>,
    pub server: Option<String>,
}

/// The server's current date, which clients send back on later requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayStart {
    /// Days since 2007-01-01 in the server's timezone.
    pub elapsed_days: u32,
    /// Seconds since the server's midnight. Chromium's extension downloader
    /// reads it from update2 responses.
    pub elapsed_seconds: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppResponse {
    pub appid: AppId,
    pub status: AppStatus,
    pub cohort: Cohort,
    pub data: Vec<DataResponse>,
    pub updatecheck: Option<UpdateCheckResponse>,
    /// Acknowledgements of a ping-back's events, one per event.
    pub events: Vec<EventStatus>,
}

impl AppResponse {
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventStatus {
    Ok,
    Other(String),
}

impl EventStatus {
    pub fn as_str(&self) -> &str {
        match self {
            EventStatus::Ok => "ok",
            EventStatus::Other(s) => s,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AppStatus {
    Ok,
    Restricted,
    UnknownApplication,
    Other(String),
}

impl AppStatus {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateCheckResponse {
    pub outcome: Outcome,
    pub info: Option<String>,
    /// Application-specific `_`-prefixed string members.
    pub attributes: BTreeMap<AttributeName, String>,
}

impl UpdateCheckResponse {
    pub fn new(outcome: Outcome) -> Self {
        UpdateCheckResponse {
            outcome,
            info: None,
            attributes: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    NoUpdate,
    Update {
        nextversion: Version,
        pipelines: Vec<Pipeline>,
    },
    Error(UpdateCheckError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateCheckError {
    Internal,
    Hash,
    OsNotSupported,
    HwNotSupported,
    UnsupportedProtocol,
    Inexpressible,
    Other(String),
}

impl UpdateCheckError {
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
    pub fn new(name: impl Into<String>) -> Option<Self> {
        let name = name.into();
        let valid = name.len() > 1
            && name.starts_with('_')
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        valid.then_some(AttributeName(name))
    }

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
    pub id: String,
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    Download {
        size: u64,
        out: Sha256,
        urls: Vec<String>,
    },
    Xz,
    Puff {
        previous: Sha256,
        out: Sha256,
    },
    Zucc {
        previous: Sha256,
        out: Sha256,
    },
    Crx3 {
        input: Sha256,
        size: Option<u64>,
        path: Option<String>,
        arguments: Option<String>,
    },
    Run {
        path: String,
        arguments: Option<String>,
    },
    /// An operation type this crate doesn't know.
    Other {
        kind: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataResponse {
    pub name: String,
    pub index: Option<String>,
    pub status: DataStatus,
    pub text: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataStatus {
    Ok,
    InvalidArgs,
    NoData,
    Other(String),
}

impl DataStatus {
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
