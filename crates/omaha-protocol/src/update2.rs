//! The legacy update2 protocol of Chromium's extension downloader: a GET with
//! one `x=` parameter per extension, answered with `gupdate` XML or, for
//! installs (`response=redirect`), a redirect to the package.

use crate::limits::{DecodeError, Limits};
use crate::model::*;
use crate::validate::{EncodeError, validate};
use crate::{AppId, Version};
use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use std::borrow::Cow;

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
    let (mut id, mut version, mut installsource, mut installedby, mut ap, mut brand) =
        (None, None, None, None, None, None);
    let mut uc = false;
    for (key, value) in form_urlencoded::parse(x.as_bytes()) {
        let value = Some(value.into_owned());
        match &*key {
            "id" => id = limits.string("id", value)?,
            "v" => version = limits.string("v", value)?,
            "installsource" => installsource = limits.string("installsource", value)?,
            "installedby" => installedby = limits.string("installedby", value)?,
            "ap" => ap = limits.string("ap", value)?,
            "brand" => brand = limits.string("brand", value)?,
            "uc" => uc = true,
            _ => {}
        }
    }

    let mut app = App::new(id.and_then(AppId::new).ok_or(DecodeError::Invalid("id"))?);
    app.version = version
        .map(|v| v.parse::<Version>().map_err(|_| DecodeError::Invalid("v")))
        .transpose()?;
    app.installsource = installsource;
    app.installedby = installedby;
    app.ap = ap;
    app.brand = brand;
    app.lang = lang.clone();
    app.updatecheck = uc.then(UpdateCheck::default);
    Ok(app)
}

const XMLNS: &str = "http://www.google.com/update2/response";

/// Prepares an attribute value: characters XML 1.0 doesn't allow (most C0
/// controls, U+FFFE, U+FFFF) become U+FFFD, and tabs and line breaks become
/// spaces, which is what XML parsers turn them into in attribute values.
/// Escaping itself is left to quick-xml.
fn clean(s: &str) -> Cow<'_, str> {
    let map = |c: char| match c {
        '\t' | '\n' | '\r' => ' ',
        c if c < ' ' || matches!(c, '\u{fffe}' | '\u{ffff}') => '\u{fffd}',
        c => c,
    };

    if s.chars().all(|c| map(c) == c) {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.chars().map(map).collect())
    }
}

fn attr(element: &mut BytesStart<'_>, name: &str, value: &str) {
    element.push_attribute((name, &*clean(value)));
}

fn write<'a>(w: &mut Writer<Vec<u8>>, event: impl Into<Event<'a>>) -> Result<(), EncodeError> {
    w.write_event(event)
        .map_err(|e| EncodeError::Serialize(e.to_string()))
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
    let mut w = Writer::new(Vec::new());
    write(
        &mut w,
        Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)),
    )?;
    let mut root = BytesStart::new("gupdate");
    attr(&mut root, "xmlns", XMLNS);
    attr(&mut root, "protocol", "2.0");

    if let Some(server) = &response.server {
        attr(&mut root, "server", server);
    }

    write(&mut w, Event::Start(root))?;

    if let Some(d) = response.daystart {
        let mut daystart = BytesStart::new("daystart");
        attr(&mut daystart, "elapsed_days", &d.elapsed_days.to_string());

        if let Some(seconds) = d.elapsed_seconds {
            attr(&mut daystart, "elapsed_seconds", &seconds.to_string());
        }

        write(&mut w, Event::Empty(daystart))?;
    }

    for app in &response.apps {
        let mut element = BytesStart::new("app");
        attr(&mut element, "appid", app.appid.as_str());
        attr(&mut element, "status", app.status.as_str());
        match (&app.status, &app.updatecheck) {
            (AppStatus::Ok, Some(u)) => {
                write(&mut w, Event::Start(element))?;
                write(&mut w, Event::Empty(updatecheck(u)))?;
                write(&mut w, Event::End(BytesEnd::new("app")))?;
            }
            _ => write(&mut w, Event::Empty(element))?,
        }
    }
    write(&mut w, Event::End(BytesEnd::new("gupdate")))?;
    String::from_utf8(w.into_inner()).map_err(|e| EncodeError::Serialize(e.to_string()))
}

fn updatecheck(u: &UpdateCheckResponse) -> BytesStart<'static> {
    let mut e = BytesStart::new("updatecheck");
    match &u.outcome {
        Outcome::NoUpdate => attr(&mut e, "status", "noupdate"),
        Outcome::Update {
            nextversion,
            pipelines,
        } => match full_package(pipelines) {
            Some((urls, hash, size)) => {
                attr(&mut e, "status", "ok");
                attr(&mut e, "codebase", &urls[0]);
                attr(&mut e, "version", &nextversion.to_string());
                attr(&mut e, "hash_sha256", &hash.to_string());

                if i32::try_from(size).is_ok_and(|s| s > 0) {
                    attr(&mut e, "size", &size.to_string());
                }
            }
            None => attr(&mut e, "status", UpdateCheckError::Inexpressible.as_str()),
        },
        Outcome::Error(err) => attr(&mut e, "status", err.as_str()),
    }

    if let Some(info) = &u.info {
        attr(&mut e, "info", info);
    }

    for (name, value) in &u.attributes {
        attr(&mut e, name.as_str(), value);
    }
    e
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
