//! Omaha 4 JSON, as specified in Chromium's `docs/updater/protocol_4.md`.

use crate::limits::{DecodeError, Limits};
use crate::model::*;
use crate::validate::{EncodeError, is_http_url, validate};
use crate::{AppId, Sha256, Version};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};

/// Prefix of every JSON response, so it can't be run as a script.
pub const SAFE_JSON_PREFIX: &str = ")]}'\n";
const PROTOCOL: &str = "4.0";

#[derive(Deserialize)]
struct WireRoot {
    request: WireRequest,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct WireRequest {
    protocol: Option<String>,
    #[serde(rename = "@updater")]
    updater: Option<String>,
    prodversion: Option<String>,
    updaterversion: Option<String>,
    #[serde(rename = "@os")]
    os: Option<String>,
    arch: Option<String>,
    #[serde(rename = "os")]
    platform: Option<WirePlatform>,
    acceptformat: Option<String>,
    prodchannel: Option<String>,
    updaterchannel: Option<String>,
    #[serde(deserialize_with = "boolish")]
    ismachine: Option<bool>,
    #[serde(deserialize_with = "boolish")]
    wow64: Option<bool>,
    #[serde(deserialize_with = "boolish")]
    domainjoined: Option<bool>,
    dlpref: Option<String>,
    hw: Option<Value>,
    apps: Vec<WireApp>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct WirePlatform {
    platform: Option<String>,
    version: Option<String>,
    arch: Option<String>,
    sp: Option<String>,
    deviceformfactor: Option<String>,
}

#[derive(Deserialize)]
struct WireApp {
    appid: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    ap: Option<String>,
    #[serde(default)]
    brand: Option<String>,
    #[serde(default)]
    lang: Option<String>,
    #[serde(default)]
    installsource: Option<String>,
    #[serde(default)]
    installedby: Option<String>,
    #[serde(default)]
    release_channel: Option<String>,
    #[serde(default)]
    cohort: Option<String>,
    #[serde(default)]
    cohortname: Option<String>,
    #[serde(default)]
    cohorthint: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "boolish")]
    enabled: Option<bool>,
    #[serde(default)]
    disabled: Vec<WireDisabled>,
    #[serde(default)]
    cached_items: Vec<WireHash>,
    #[serde(default)]
    updatecheck: Option<WireUpdateCheck>,
    #[serde(default)]
    data: Vec<WireData>,
    #[serde(default)]
    events: Vec<Value>,
}

#[derive(Deserialize)]
struct WireDisabled {
    #[serde(deserialize_with = "integerish")]
    reason: i64,
}

#[derive(Deserialize)]
struct WireHash {
    sha256: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct WireUpdateCheck {
    #[serde(deserialize_with = "boolish")]
    updatedisabled: Option<bool>,
    #[serde(deserialize_with = "boolish")]
    rollback_allowed: Option<bool>,
    #[serde(deserialize_with = "boolish")]
    sameversionupdate: Option<bool>,
    targetversionprefix: Option<String>,
}

#[derive(Deserialize)]
struct WireData {
    name: String,
    #[serde(default)]
    index: Option<String>,
    #[serde(rename = "#text", default)]
    text: Option<String>,
}

fn version(
    limits: &Limits,
    field: &'static str,
    s: Option<String>,
) -> Result<Option<Version>, DecodeError> {
    limits
        .string(field, s)?
        .map(|s| s.parse().map_err(|_| DecodeError::Invalid(field)))
        .transpose()
}

/// Decodes an update check request body.
pub fn decode_request(body: &[u8], limits: &Limits) -> Result<Request, DecodeError> {
    if body.len() > limits.max_body_len {
        return Err(DecodeError::TooLarge);
    }

    let root: WireRoot =
        serde_json::from_slice(body).map_err(|e| DecodeError::Syntax(e.to_string()))?;
    let r = root.request;
    match r.protocol.as_deref() {
        Some(PROTOCOL) => {}
        other => {
            return Err(DecodeError::UnsupportedProtocol(
                other.unwrap_or("").to_owned(),
            ));
        }
    }

    if r.apps.len() > limits.max_apps {
        return Err(DecodeError::TooManyApps);
    }

    let platform = r
        .platform
        .map(|p| {
            Ok::<_, DecodeError>(Platform {
                platform: limits.string("os.platform", p.platform)?,
                version: limits.string("os.version", p.version)?,
                arch: limits.string("os.arch", p.arch)?,
                service_pack: limits.string("os.sp", p.sp)?,
                device_form_factor: limits.string("os.deviceformfactor", p.deviceformfactor)?,
            })
        })
        .transpose()?;
    let acceptformat = limits
        .string("acceptformat", r.acceptformat)?
        .map(|f| f.split(',').map(str::to_owned).collect())
        .unwrap_or_default();
    let client = Client {
        updater: limits.string("@updater", r.updater)?,
        prodversion: version(limits, "prodversion", r.prodversion)?,
        updaterversion: version(limits, "updaterversion", r.updaterversion)?,
        os: limits.string("@os", r.os)?,
        arch: limits.string("arch", r.arch)?,
        platform,
        acceptformat: limits.list("acceptformat", acceptformat)?,
        prodchannel: limits.string("prodchannel", r.prodchannel)?,
        updaterchannel: limits.string("updaterchannel", r.updaterchannel)?,
        ismachine: r.ismachine.unwrap_or(false),
        wow64: r.wow64.unwrap_or(false),
        domainjoined: r.domainjoined,
        dlpref: limits.string("dlpref", r.dlpref)?,
        hw: r.hw.as_ref().map(decode_hw).transpose()?,
    };
    let apps = r
        .apps
        .into_iter()
        .map(|a| decode_app(a, limits))
        .collect::<Result<_, _>>()?;
    Ok(Request {
        protocol: Protocol::V4,
        client,
        apps,
    })
}

/// A boolean in any form Chromium or protocol_4.md uses: JSON `true` and
/// `false`, `1`, `0` and `-1` (unknown) as numbers or strings, or `"true"`
/// and `"false"`.
fn parse_flag(v: &Value) -> Option<Result<bool, ()>> {
    match v {
        Value::Null => None,
        Value::Bool(b) => Some(Ok(*b)),
        Value::Number(n) => match n.as_i64() {
            Some(1) => Some(Ok(true)),
            Some(0) => Some(Ok(false)),
            Some(-1) => None,
            _ => Some(Err(())),
        },
        Value::String(s) => match s.as_str() {
            "1" | "true" => Some(Ok(true)),
            "0" | "false" => Some(Ok(false)),
            "-1" => None,
            _ => Some(Err(())),
        },
        _ => Some(Err(())),
    }
}

fn boolish<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    match Option::<Value>::deserialize(d)?
        .as_ref()
        .and_then(parse_flag)
    {
        None => Ok(None),
        Some(Ok(b)) => Ok(Some(b)),
        Some(Err(())) => Err(serde::de::Error::custom("invalid boolean")),
    }
}

fn integerish<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    match Value::deserialize(d)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
    .ok_or_else(|| serde::de::Error::custom("invalid integer"))
}

fn flag(v: Option<&Value>) -> Result<Option<bool>, DecodeError> {
    v.and_then(parse_flag)
        .transpose()
        .map_err(|()| DecodeError::Invalid("hw"))
}

fn decode_hw(v: &Value) -> Result<Hardware, DecodeError> {
    if !v.is_object() {
        return Err(DecodeError::Invalid("hw"));
    }

    let physmemory = match v.get("physmemory") {
        None | Some(Value::Null) => None,
        Some(m) => {
            let n = m
                .as_i64()
                .or_else(|| m.as_str().and_then(|s| s.parse().ok()))
                .ok_or(DecodeError::Invalid("hw.physmemory"))?;
            u32::try_from(n).ok()
        }
    };
    Ok(Hardware {
        sse: flag(v.get("sse"))?,
        sse2: flag(v.get("sse2"))?,
        sse3: flag(v.get("sse3"))?,
        sse41: flag(v.get("sse41"))?,
        sse42: flag(v.get("sse42"))?,
        ssse3: flag(v.get("ssse3"))?,
        avx: flag(v.get("avx"))?,
        physmemory,
    })
}

fn decode_event(v: &Value, limits: &Limits) -> Result<Event, DecodeError> {
    let int = |key: &str| v.get(key).and_then(Value::as_i64);
    let kind = int("eventtype").ok_or(DecodeError::Invalid("events"))?;
    let lenient_version = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
    };
    let mut event = Event::new(
        EventType::from_code(kind),
        EventResult::from_code(int("eventresult").unwrap_or(0)),
    );
    event.error_category = int("errorcat").unwrap_or(0);
    event.error_code = int("errorcode").unwrap_or(0);
    event.extra_code1 = int("extracode1").unwrap_or(0);
    event.previous_version = lenient_version("previousversion");
    event.next_version = lenient_version("nextversion");
    event.pipeline_id = limits.string(
        "events.pipeline_id",
        v.get("pipeline_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )?;

    if event.kind == EventType::Download {
        let unsigned = |key: &str| v.get(key).and_then(Value::as_u64);
        event.download = Some(DownloadStats {
            time_ms: unsigned("download_time_ms"),
            downloaded: unsigned("downloaded").unwrap_or(0),
            total: unsigned("total").unwrap_or(0),
            downloader: limits.string(
                "events.downloader",
                v.get("downloader")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )?,
        });
    }

    Ok(event)
}

fn decode_app(a: WireApp, limits: &Limits) -> Result<App, DecodeError> {
    let appid = limits
        .string("appid", Some(a.appid))?
        .and_then(AppId::new)
        .ok_or(DecodeError::Invalid("appid"))?;
    let cached = limits
        .list("cached_items", a.cached_items)?
        .into_iter()
        .map(|h| {
            h.sha256
                .parse()
                .map_err(|_| DecodeError::Invalid("cached_items"))
        })
        .collect::<Result<_, _>>()?;
    let data = limits
        .list("data", a.data)?
        .into_iter()
        .filter_map(|d| match d.name.as_str() {
            "install" => Some(
                limits
                    .string("data.index", d.index)
                    .map(|i| DataRequest::Install {
                        index: i.unwrap_or_default(),
                    }),
            ),
            "untrusted" => {
                Some(
                    limits
                        .string("data.#text", d.text)
                        .map(|t| DataRequest::Untrusted {
                            text: t.unwrap_or_default(),
                        }),
                )
            }
            _ => None,
        })
        .collect::<Result<_, _>>()?;
    let updatecheck = a
        .updatecheck
        .map(|u| {
            Ok::<_, DecodeError>(UpdateCheck {
                updatedisabled: u.updatedisabled.unwrap_or(false),
                rollback_allowed: u.rollback_allowed.unwrap_or(false),
                sameversionupdate: u.sameversionupdate.unwrap_or(false),
                targetversionprefix: limits.string("targetversionprefix", u.targetversionprefix)?,
            })
        })
        .transpose()?;
    Ok(App {
        appid,
        version: version(limits, "version", a.version)?,
        ap: limits.string("ap", a.ap)?,
        brand: limits.string("brand", a.brand)?,
        lang: limits.string("lang", a.lang)?,
        installsource: limits.string("installsource", a.installsource)?,
        installedby: limits.string("installedby", a.installedby)?,
        release_channel: limits.string("release_channel", a.release_channel)?,
        cohort: Cohort {
            id: limits.string("cohort", a.cohort)?,
            name: limits.string("cohortname", a.cohortname)?,
            hint: limits.string("cohorthint", a.cohorthint)?,
        },
        enabled: a.enabled,
        disabled_reasons: limits
            .list("disabled", a.disabled)?
            .into_iter()
            .map(|d| d.reason)
            .collect(),
        cached,
        updatecheck,
        data,
        events: limits
            .list("events", a.events)?
            .iter()
            .map(|e| decode_event(e, limits))
            .collect::<Result<_, _>>()?,
    })
}

fn hash_object(h: &Sha256) -> Value {
    json!({ "sha256": h.to_string() })
}

fn encode_operation(op: &Operation) -> Value {
    match op {
        Operation::Download { size, out, urls } => json!({
            "type": "download",
            "size": size,
            "out": hash_object(out),
            "urls": urls.iter().map(|u| json!({ "url": u })).collect::<Vec<_>>(),
        }),
        Operation::Xz => json!({ "type": "xz" }),
        Operation::Puff { previous, out } => {
            json!({ "type": "puff", "previous": hash_object(previous), "out": hash_object(out) })
        }
        Operation::Zucc { previous, out } => {
            json!({ "type": "zucc", "previous": hash_object(previous), "out": hash_object(out) })
        }
        Operation::Crx3 {
            input,
            size,
            path,
            arguments,
        } => {
            let mut m = Map::new();
            m.insert("type".into(), "crx3".into());
            m.insert("in".into(), hash_object(input));

            if let Some(size) = size {
                m.insert("size".into(), (*size).into());
            }

            if let Some(path) = path {
                m.insert("path".into(), path.as_str().into());
            }

            if let Some(arguments) = arguments {
                m.insert("arguments".into(), arguments.as_str().into());
            }

            Value::Object(m)
        }
        Operation::Run { path, arguments } => {
            let mut m = Map::new();
            m.insert("type".into(), "run".into());
            m.insert("path".into(), path.as_str().into());

            if let Some(arguments) = arguments {
                m.insert("arguments".into(), arguments.as_str().into());
            }

            Value::Object(m)
        }
        Operation::Other { kind } => json!({ "type": kind }),
    }
}

fn insert_cohort(m: &mut Map<String, Value>, cohort: &Cohort) {
    for (key, value) in [
        ("cohort", &cohort.id),
        ("cohortname", &cohort.name),
        ("cohorthint", &cohort.hint),
    ] {
        if let Some(v) = value {
            m.insert(key.into(), v.as_str().into());
        }
    }
}

fn encode_updatecheck(u: &UpdateCheckResponse) -> Value {
    let mut m = Map::new();
    match &u.outcome {
        Outcome::NoUpdate => {
            m.insert("status".into(), "noupdate".into());
        }
        Outcome::Update {
            nextversion,
            pipelines,
        } => {
            m.insert("status".into(), "ok".into());
            m.insert("nextversion".into(), nextversion.to_string().into());
            let pipelines = pipelines
                .iter()
                .map(|p| {
                    json!({
                        "pipeline_id": p.id,
                        "operations": p.operations.iter().map(encode_operation).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>();
            m.insert("pipelines".into(), pipelines.into());
        }
        Outcome::Error(e) => {
            m.insert("status".into(), e.as_str().into());
        }
    }

    if let Some(info) = &u.info {
        m.insert("info".into(), info.as_str().into());
    }

    for (name, value) in &u.attributes {
        m.insert(name.as_str().into(), value.as_str().into());
    }
    Value::Object(m)
}

fn encode_app(app: &AppResponse) -> Value {
    let mut m = Map::new();
    m.insert("appid".into(), app.appid.as_str().into());
    m.insert("status".into(), app.status.as_str().into());
    insert_cohort(&mut m, &app.cohort);

    if !app.data.is_empty() {
        let data = app
            .data
            .iter()
            .map(|d| {
                let mut dm = Map::new();
                dm.insert("name".into(), d.name.as_str().into());

                if let Some(index) = &d.index {
                    dm.insert("index".into(), index.as_str().into());
                }

                dm.insert("status".into(), d.status.as_str().into());

                if let Some(text) = &d.text {
                    dm.insert("#text".into(), text.as_str().into());
                }

                Value::Object(dm)
            })
            .collect::<Vec<_>>();
        m.insert("data".into(), data.into());
    }

    if let Some(u) = &app.updatecheck {
        m.insert("updatecheck".into(), encode_updatecheck(u));
    }

    if !app.events.is_empty() {
        let events = app
            .events
            .iter()
            .map(|e| json!({ "status": e.as_str() }))
            .collect::<Vec<_>>();
        m.insert("events".into(), events.into());
    }

    Value::Object(m)
}

/// Encodes a response body, including [`SAFE_JSON_PREFIX`], after checking
/// it with [`validate`](crate::validate).
pub fn encode_response(response: &Response) -> Result<Vec<u8>, EncodeError> {
    validate(response)?;
    let mut m = Map::new();
    m.insert("protocol".into(), PROTOCOL.into());

    if let Some(server) = &response.server {
        m.insert("server".into(), server.as_str().into());
    }

    if let Some(d) = response.daystart {
        let mut dm = Map::new();
        dm.insert("elapsed_days".into(), d.elapsed_days.into());

        if let Some(seconds) = d.elapsed_seconds {
            dm.insert("elapsed_seconds".into(), seconds.into());
        }

        m.insert("daystart".into(), Value::Object(dm));
    }

    m.insert(
        "apps".into(),
        response
            .apps
            .iter()
            .map(encode_app)
            .collect::<Vec<_>>()
            .into(),
    );
    let mut out = SAFE_JSON_PREFIX.as_bytes().to_vec();
    serde_json::to_writer(&mut out, &json!({ "response": m }))
        .map_err(|e| EncodeError::Serialize(e.to_string()))?;
    Ok(out)
}

fn encode_event(e: &Event) -> Value {
    let mut m = Map::new();
    m.insert("eventtype".into(), e.kind.code().into());
    m.insert("eventresult".into(), e.result.code().into());
    for (key, value) in [
        ("errorcat", e.error_category),
        ("errorcode", e.error_code),
        ("extracode1", e.extra_code1),
    ] {
        if value != 0 {
            m.insert(key.into(), value.into());
        }
    }

    if let Some(v) = &e.previous_version {
        m.insert("previousversion".into(), v.to_string().into());
    }

    if let Some(v) = &e.next_version {
        m.insert("nextversion".into(), v.to_string().into());
    }

    if let Some(id) = &e.pipeline_id {
        m.insert("pipeline_id".into(), id.as_str().into());
    }

    if let Some(d) = &e.download {
        if let Some(ms) = d.time_ms {
            m.insert("download_time_ms".into(), ms.into());
        }

        m.insert("downloaded".into(), d.downloaded.into());
        m.insert("total".into(), d.total.into());

        if let Some(downloader) = &d.downloader {
            m.insert("downloader".into(), downloader.as_str().into());
        }
    }

    Value::Object(m)
}

/// IDs a client sends with each request. Servers built on this crate never
/// read them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestIds {
    pub session_id: String,
    pub request_id: String,
}

/// Encodes a request body, as a client would send it.
pub fn encode_request(request: &Request, ids: Option<&RequestIds>) -> Result<Vec<u8>, EncodeError> {
    let c = &request.client;
    let mut m = Map::new();
    m.insert("protocol".into(), PROTOCOL.into());
    m.insert("ismachine".into(), c.ismachine.into());
    m.insert("dedup".into(), "cr".into());

    if !c.acceptformat.is_empty() {
        m.insert("acceptformat".into(), c.acceptformat.join(",").into());
    }

    if let Some(ids) = ids {
        m.insert("sessionid".into(), ids.session_id.as_str().into());
        m.insert("requestid".into(), ids.request_id.as_str().into());
    }

    let strings = [
        ("@updater", &c.updater),
        ("@os", &c.os),
        ("arch", &c.arch),
        ("prodchannel", &c.prodchannel),
        ("updaterchannel", &c.updaterchannel),
        ("dlpref", &c.dlpref),
    ];
    for (key, value) in strings {
        if let Some(v) = value {
            m.insert(key.into(), v.as_str().into());
        }
    }

    if c.wow64 {
        m.insert("wow64".into(), true.into());
    }

    if let Some(joined) = c.domainjoined {
        m.insert("domainjoined".into(), joined.into());
    }

    if let Some(hw) = &c.hw {
        let mut hm = Map::new();
        let flags = [
            ("sse", hw.sse),
            ("sse2", hw.sse2),
            ("sse3", hw.sse3),
            ("sse41", hw.sse41),
            ("sse42", hw.sse42),
            ("ssse3", hw.ssse3),
            ("avx", hw.avx),
        ];
        for (key, value) in flags {
            if let Some(v) = value {
                hm.insert(key.into(), v.into());
            }
        }

        if let Some(gib) = hw.physmemory {
            hm.insert("physmemory".into(), gib.into());
        }

        m.insert("hw".into(), Value::Object(hm));
    }

    if let Some(v) = &c.prodversion {
        m.insert("prodversion".into(), v.to_string().into());
    }

    if let Some(v) = &c.updaterversion {
        m.insert("updaterversion".into(), v.to_string().into());
    }

    if let Some(p) = &c.platform {
        let mut pm = Map::new();
        for (key, value) in [
            ("platform", &p.platform),
            ("version", &p.version),
            ("arch", &p.arch),
            ("sp", &p.service_pack),
            ("deviceformfactor", &p.device_form_factor),
        ] {
            if let Some(v) = value {
                pm.insert(key.into(), v.as_str().into());
            }
        }
        m.insert("os".into(), Value::Object(pm));
    }

    let apps = request
        .apps
        .iter()
        .map(|a| {
            let mut am = Map::new();
            am.insert("appid".into(), a.appid.as_str().into());

            if let Some(v) = &a.version {
                am.insert("version".into(), v.to_string().into());
            }

            let strings = [
                ("ap", &a.ap),
                ("brand", &a.brand),
                ("lang", &a.lang),
                ("installsource", &a.installsource),
                ("installedby", &a.installedby),
                ("release_channel", &a.release_channel),
            ];
            for (key, value) in strings {
                if let Some(v) = value {
                    am.insert(key.into(), v.as_str().into());
                }
            }
            insert_cohort(&mut am, &a.cohort);

            if let Some(enabled) = a.enabled {
                am.insert("enabled".into(), enabled.into());
            }

            if !a.disabled_reasons.is_empty() {
                let reasons = a
                    .disabled_reasons
                    .iter()
                    .map(|r| json!({ "reason": r }))
                    .collect::<Vec<_>>();
                am.insert("disabled".into(), reasons.into());
            }

            if !a.cached.is_empty() {
                am.insert(
                    "cached_items".into(),
                    a.cached.iter().map(hash_object).collect::<Vec<_>>().into(),
                );
            }

            if let Some(u) = &a.updatecheck {
                let mut um = Map::new();
                for (key, set) in [
                    ("updatedisabled", u.updatedisabled),
                    ("rollback_allowed", u.rollback_allowed),
                    ("sameversionupdate", u.sameversionupdate),
                ] {
                    if set {
                        um.insert(key.into(), true.into());
                    }
                }

                if let Some(prefix) = &u.targetversionprefix {
                    um.insert("targetversionprefix".into(), prefix.as_str().into());
                }

                am.insert("updatecheck".into(), Value::Object(um));
            }

            if !a.data.is_empty() {
                let data = a
                    .data
                    .iter()
                    .map(|d| match d {
                        DataRequest::Install { index } => {
                            json!({ "name": "install", "index": index })
                        }
                        DataRequest::Untrusted { text } => {
                            json!({ "name": "untrusted", "#text": text })
                        }
                    })
                    .collect::<Vec<_>>();
                am.insert("data".into(), data.into());
            }

            if !a.events.is_empty() {
                am.insert(
                    "events".into(),
                    a.events.iter().map(encode_event).collect::<Vec<_>>().into(),
                );
            }

            Value::Object(am)
        })
        .collect::<Vec<_>>();
    m.insert("apps".into(), apps.into());
    serde_json::to_vec(&json!({ "request": m })).map_err(|e| EncodeError::Serialize(e.to_string()))
}

/// A decoded response. Like Chromium, apps that fail to parse are skipped and
/// reported in `errors` instead of failing the whole response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedResponse {
    pub response: Response,
    pub errors: Vec<String>,
}

/// Decodes a response body, which must start with the `)]}'` prefix.
pub fn decode_response(body: &[u8]) -> Result<DecodedResponse, DecodeError> {
    let body = body
        .strip_prefix(b")]}'")
        .ok_or(DecodeError::Missing("safe JSON prefix"))?;
    let doc: Value =
        serde_json::from_slice(body).map_err(|e| DecodeError::Syntax(e.to_string()))?;
    let r = doc
        .get("response")
        .and_then(Value::as_object)
        .ok_or(DecodeError::Missing("response"))?;
    match r.get("protocol").and_then(Value::as_str) {
        Some(PROTOCOL) => {}
        Some(other) => return Err(DecodeError::UnsupportedProtocol(other.to_owned())),
        None => return Err(DecodeError::Missing("protocol")),
    }
    let mut response = Response {
        apps: Vec::new(),
        daystart: r.get("daystart").and_then(|d| {
            let field = |key: &str| {
                d.get(key)
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
            };
            Some(DayStart {
                elapsed_days: field("elapsed_days")?,
                elapsed_seconds: field("elapsed_seconds"),
            })
        }),
        server: r.get("server").and_then(Value::as_str).map(str::to_owned),
    };
    let mut errors = Vec::new();
    for app in r
        .get("apps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match decode_app_response(app) {
            Ok(app) => response.apps.push(app),
            Err(e) => errors.push(e),
        }
    }
    Ok(DecodedResponse { response, errors })
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn hash_field(v: &Value, key: &str) -> Result<Sha256, String> {
    v.get(key)
        .and_then(|h| h.get("sha256"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {key}.sha256"))?
        .parse()
        .map_err(|_| format!("invalid {key}.sha256"))
}

/// Like Chromium: a number from 0 up to 2^53, anything else counts as 0.
fn size_field(v: &Value, key: &str) -> u64 {
    v.get(key)
        .and_then(Value::as_f64)
        .filter(|s| (0.0..9007199254740992.0).contains(s))
        .map_or(0, |s| s as u64)
}

fn decode_operation(v: &Value) -> Result<Operation, String> {
    if !v.is_object() {
        return Err("operation is not an object".into());
    }

    let kind = str_field(v, "type").ok_or("missing operation type")?;
    Ok(match kind.as_str() {
        "download" => {
            let urls = v
                .get("urls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|u| {
                    let url = u.get("url").and_then(Value::as_str).ok_or("missing url")?;
                    is_http_url(url)
                        .then(|| url.to_owned())
                        .ok_or("invalid url")
                })
                .collect::<Result<Vec<_>, _>>()?;
            Operation::Download {
                size: size_field(v, "size"),
                out: hash_field(v, "out")?,
                urls,
            }
        }
        "xz" => Operation::Xz,
        "puff" => Operation::Puff {
            previous: hash_field(v, "previous")?,
            out: hash_field(v, "out")?,
        },
        "zucc" => Operation::Zucc {
            previous: hash_field(v, "previous")?,
            out: hash_field(v, "out")?,
        },
        "crx3" => Operation::Crx3 {
            input: hash_field(v, "in")?,
            size: v.get("size").map(|_| size_field(v, "size")),
            path: str_field(v, "path"),
            arguments: str_field(v, "arguments"),
        },
        "run" => Operation::Run {
            path: str_field(v, "path").ok_or("missing run path")?,
            arguments: str_field(v, "arguments"),
        },
        _ => Operation::Other { kind },
    })
}

fn decode_app_response(v: &Value) -> Result<AppResponse, String> {
    if !v.is_object() {
        return Err("app is not an object".into());
    }

    let appid = str_field(v, "appid").ok_or("missing appid")?;
    let appid = AppId::new(appid.clone()).ok_or_else(|| format!("invalid appid {appid:?}"))?;
    let status = str_field(v, "status").ok_or_else(|| format!("{appid}: missing status"))?;
    let mut app = AppResponse::new(appid, AppStatus::parse(&status));
    app.cohort = Cohort {
        id: str_field(v, "cohort"),
        name: str_field(v, "cohortname"),
        hint: str_field(v, "cohorthint"),
    };

    if app.status != AppStatus::Ok {
        return Ok(app);
    }

    if let (Some(events), None) = (
        v.get("events").and_then(Value::as_array),
        v.get("updatecheck"),
    ) {
        app.events = events
            .iter()
            .map(|e| match e.get("status").and_then(Value::as_str) {
                Some("ok") => EventStatus::Ok,
                other => EventStatus::Other(other.unwrap_or_default().to_owned()),
            })
            .collect();
        return Ok(app);
    }
    app.data = v
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|d| d.is_object())
        .map(|d| DataResponse {
            name: str_field(d, "name").unwrap_or_default(),
            index: str_field(d, "index"),
            status: DataStatus::parse(&str_field(d, "status").unwrap_or_else(|| "ok".into())),
            text: str_field(d, "#text"),
        })
        .collect();
    let id = app.appid.clone();
    let u = match v.get("updatecheck") {
        None => return Ok(app),
        Some(u) if u.is_object() => u,
        Some(_) => return Err(format!("{id}: updatecheck is not an object")),
    };
    let status =
        str_field(u, "status").ok_or_else(|| format!("{id}: missing updatecheck status"))?;
    let outcome = match status.as_str() {
        "noupdate" => Outcome::NoUpdate,
        "ok" => {
            let nextversion = str_field(u, "nextversion")
                .ok_or_else(|| format!("{id}: missing nextversion"))?
                .parse::<Version>()
                .map_err(|_| format!("{id}: invalid nextversion"))?;
            let pipelines = u
                .get("pipelines")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|p| {
                    if !p.is_object() {
                        return Err("pipeline is not an object".to_owned());
                    }

                    let operations = p
                        .get("operations")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .map(decode_operation)
                        .collect::<Result<_, _>>()?;
                    Ok(Pipeline {
                        id: str_field(p, "pipeline_id").unwrap_or_default(),
                        operations,
                    })
                })
                .collect::<Result<_, String>>()
                .map_err(|e| format!("{id}: {e}"))?;
            Outcome::Update {
                nextversion,
                pipelines,
            }
        }
        other => Outcome::Error(UpdateCheckError::parse(other)),
    };
    let mut check = UpdateCheckResponse::new(outcome);
    check.info = str_field(u, "info");

    if let Some(obj) = u.as_object() {
        for (k, val) in obj {
            if let (Some(name), Some(val)) = (AttributeName::new(k.as_str()), val.as_str()) {
                check.attributes.insert(name, val.to_owned());
            }
        }
    }

    app.updatecheck = Some(check);
    Ok(app)
}
