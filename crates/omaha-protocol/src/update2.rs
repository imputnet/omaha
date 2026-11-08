//! The legacy update2 protocol of Chromium's extension downloader: a GET with
//! one `x=` parameter per extension, answered with `gupdate` XML or, for
//! installs (`response=redirect`), a redirect to the package.

use crate::limits::{DecodeError, Limits};
use crate::model::*;
use crate::validate::{EncodeError, validate};
use crate::{AppId, Version};
use std::fmt::Write;

/// How the client wants the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseMode {
    /// A `gupdate` XML document.
    Xml,
    /// An HTTP redirect to the package; see [`redirect_url`].
    Redirect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update2Request {
    pub request: Request,
    pub mode: ResponseMode,
}

/// Decodes the query string of an update2 request (without the leading `?`).
pub fn decode_query(query: &str, limits: &Limits) -> Result<Update2Request, DecodeError> {
    if query.len() > limits.max_body_len {
        return Err(DecodeError::TooLarge);
    }
    let mut client = Client::default();
    let mut lang = None;
    let mut mode = ResponseMode::Xml;
    let mut xs = Vec::new();
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key == "x" {
            if xs.len() == limits.max_apps {
                return Err(DecodeError::TooManyApps);
            }
            xs.push(value.into_owned());
            continue;
        }
        let value = Some(value.into_owned());
        match &*key {
            "os" => client.os = limits.string("os", value)?,
            "arch" => client.arch = limits.string("arch", value)?,
            "prod" => client.updater = limits.string("prod", value)?,
            "prodchannel" => client.prodchannel = limits.string("prodchannel", value)?,
            "lang" => lang = limits.string("lang", value)?,
            "prodversion" => {
                client.prodversion = limits
                    .string("prodversion", value)?
                    .map(|v| {
                        v.parse::<Version>()
                            .map_err(|_| DecodeError::Invalid("prodversion"))
                    })
                    .transpose()?;
            }
            "acceptformat" => {
                let formats = limits
                    .string("acceptformat", value)?
                    .map(|f| f.split(',').map(str::to_owned).collect())
                    .unwrap_or_default();
                client.acceptformat = limits.list("acceptformat", formats)?;
            }
            "response" if value.as_deref() == Some("redirect") => mode = ResponseMode::Redirect,
            _ => {}
        }
    }
    match (mode, xs.len()) {
        (_, 0) => return Err(DecodeError::Missing("x")),
        (ResponseMode::Redirect, n) if n > 1 => return Err(DecodeError::Invalid("x")),
        _ => {}
    }
    let apps = xs
        .iter()
        .map(|x| decode_x(x, &lang, limits))
        .collect::<Result<_, _>>()?;
    Ok(Update2Request {
        request: Request {
            protocol: Protocol::Update2,
            client,
            apps,
        },
        mode,
    })
}

fn decode_x(x: &str, lang: &Option<String>, limits: &Limits) -> Result<App, DecodeError> {
    let mut id = None;
    let mut app_version = None;
    let mut fields = App::new(AppId::new("x").expect("valid placeholder"));
    let mut uc = false;
    for (key, value) in form_urlencoded::parse(x.as_bytes()) {
        let value = Some(value.into_owned());
        match &*key {
            "id" => id = limits.string("id", value)?,
            "v" => app_version = limits.string("v", value)?,
            "installsource" => fields.installsource = limits.string("installsource", value)?,
            "installedby" => fields.installedby = limits.string("installedby", value)?,
            "ap" => fields.ap = limits.string("ap", value)?,
            "brand" => fields.brand = limits.string("brand", value)?,
            "uc" => uc = true,
            _ => {}
        }
    }
    fields.appid = id.and_then(AppId::new).ok_or(DecodeError::Invalid("id"))?;
    fields.version = app_version
        .map(|v| v.parse::<Version>().map_err(|_| DecodeError::Invalid("v")))
        .transpose()?;
    fields.lang = lang.clone();
    fields.updatecheck = uc.then(UpdateCheck::default);
    Ok(fields)
}

const XMLNS: &str = "http://www.google.com/update2/response";

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => {
                let _ = write!(out, "&#{};", u32::from(c));
            }
            c if c.is_control() => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

fn attr(out: &mut String, name: &str, value: &str) {
    let _ = write!(out, " {name}=\"{}\"", escape(value));
}

/// The full package of an update: the first pipeline that is a plain
/// download followed by a `crx3` install.
fn full_package(pipelines: &[Pipeline]) -> Option<(&[String], &crate::Sha256, u64)> {
    pipelines
        .iter()
        .find_map(Pipeline::full_crx)
        .filter(|(urls, _, _)| !urls.is_empty())
}

/// Renders a response as `gupdate` XML, after checking it with
/// [`validate`](crate::validate). Updates are expressed with their full
/// package; one without a full `download` + `crx3` pipeline is answered with
/// `error-inexpressible`.
pub fn encode_xml(response: &Response) -> Result<String, EncodeError> {
    validate(response)?;
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str("<gupdate");
    attr(&mut out, "xmlns", XMLNS);
    attr(&mut out, "protocol", "2.0");
    if let Some(server) = &response.server {
        attr(&mut out, "server", server);
    }
    out.push('>');
    if let Some(d) = response.daystart {
        let _ = write!(out, "<daystart elapsed_days=\"{}\"", d.elapsed_days);
        if let Some(seconds) = d.elapsed_seconds {
            let _ = write!(out, " elapsed_seconds=\"{seconds}\"");
        }
        out.push_str("/>");
    }
    for app in &response.apps {
        out.push_str("<app");
        attr(&mut out, "appid", app.appid.as_str());
        attr(&mut out, "status", app.status.as_str());
        match (&app.status, &app.updatecheck) {
            (AppStatus::Ok, Some(u)) => {
                out.push('>');
                encode_updatecheck(&mut out, u);
                out.push_str("</app>");
            }
            _ => out.push_str("/>"),
        }
    }
    out.push_str("</gupdate>");
    Ok(out)
}

fn encode_updatecheck(out: &mut String, u: &UpdateCheckResponse) {
    out.push_str("<updatecheck");
    match &u.outcome {
        Outcome::NoUpdate => attr(out, "status", "noupdate"),
        Outcome::Update {
            nextversion,
            pipelines,
        } => match full_package(pipelines) {
            Some((urls, hash, size)) => {
                attr(out, "status", "ok");
                attr(out, "codebase", &urls[0]);
                attr(out, "version", &nextversion.to_string());
                attr(out, "hash_sha256", &hash.to_string());
                if i32::try_from(size).is_ok_and(|s| s > 0) {
                    attr(out, "size", &size.to_string());
                }
            }
            None => attr(out, "status", UpdateCheckError::Inexpressible.as_str()),
        },
        Outcome::Error(e) => attr(out, "status", e.as_str()),
    }
    if let Some(info) = &u.info {
        attr(out, "info", info);
    }
    for (name, value) in &u.attributes {
        attr(out, name.as_str(), value);
    }
    out.push_str("/>");
}

/// Where to redirect a `response=redirect` request: the full package's first
/// URL, if the (single) app has an update.
pub fn redirect_url(response: &Response) -> Option<&str> {
    let app = response.apps.first()?;
    match (&app.status, &app.updatecheck) {
        (
            AppStatus::Ok,
            Some(UpdateCheckResponse {
                outcome: Outcome::Update { pipelines, .. },
                ..
            }),
        ) => full_package(pipelines).map(|(urls, _, _)| urls[0].as_str()),
        _ => None,
    }
}
