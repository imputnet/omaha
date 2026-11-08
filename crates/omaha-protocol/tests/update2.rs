//! Decoding update2 queries and encoding gupdate XML and redirects.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use omaha_protocol::update2::{self, ResponseMode};
use omaha_protocol::*;

const H1: &str = "b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116";

fn id(s: &str) -> AppId {
    AppId::new(s).unwrap()
}

#[test]
fn decodes_chromium_documented_example() {
    let q = "x=id%3Daaaa%26v%3D1.1%26uc&x=id%3Dbbbb%26v%3D2.0%26uc";
    let r = update2::decode_query(q, &Limits::default()).unwrap();
    assert_eq!(r.mode, ResponseMode::Xml);
    assert_eq!(r.request.protocol, Protocol::Update2);
    let apps: Vec<_> = r
        .request
        .apps
        .iter()
        .map(|a| (a.appid.as_str(), a.version.clone()))
        .collect();
    assert_eq!(
        apps,
        [
            ("aaaa", Some("1.1".parse().unwrap())),
            ("bbbb", Some("2.0".parse().unwrap()))
        ]
    );
    assert!(r.request.apps.iter().all(|a| a.updatecheck.is_some()));
}

/// Shaped like Chromium's extension downloader: common parameters from
/// UpdateQueryParams, then one `x=` per extension with nested escaping.
#[test]
fn decodes_extension_downloader_query() {
    let q = "os=linux&arch=x64&os_arch=x86_64&nacl_arch=x86-64&prod=chromiumcrx&prodchannel=\
             &prodversion=157.0.8103.38&lang=en-US&acceptformat=crx3,puff\
             &x=id%3Dddkjiahejlhfcafbddmgiahcphecmpfh%26v%3D2026.1103.1743\
             %26installsource%3Dnotfromwebstore%26installedby%3Dinternal%26uc\
             %26ap%3Dsome%2520data%253D1%26brand%3DHLM1%26ping%3Dr%253D-2%2526e%253D1";
    let r = update2::decode_query(q, &Limits::default()).unwrap();
    let c = &r.request.client;
    assert_eq!(c.os.as_deref(), Some("linux"));
    assert_eq!(c.updater.as_deref(), Some("chromiumcrx"));
    assert_eq!(c.prodchannel, None);
    assert_eq!(c.prodversion, Some("157.0.8103.38".parse().unwrap()));
    assert!(c.accepts("crx3") && c.accepts("puff"));
    let app = &r.request.apps[0];
    assert_eq!(app.appid, id("ddkjiahejlhfcafbddmgiahcphecmpfh"));
    assert_eq!(app.installsource.as_deref(), Some("notfromwebstore"));
    assert_eq!(app.installedby.as_deref(), Some("internal"));
    assert_eq!(app.ap.as_deref(), Some("some data=1"));
    assert_eq!(app.brand.as_deref(), Some("HLM1"));
    assert_eq!(app.lang.as_deref(), Some("en-US"));
}

#[test]
fn decodes_redirect_requests() {
    let q = "response=redirect&prodversion=157.0.8103.38\
             &x=id%3Dddkjiahejlhfcafbddmgiahcphecmpfh%26installsource%3Dondemand%26uc";
    let r = update2::decode_query(q, &Limits::default()).unwrap();
    assert_eq!(r.mode, ResponseMode::Redirect);
    assert_eq!(r.request.apps[0].version, None);

    let two = "response=redirect&x=id%3Daaaa%26uc&x=id%3Dbbbb%26uc";
    assert_eq!(
        update2::decode_query(two, &Limits::default()),
        Err(DecodeError::Invalid("x"))
    );
}

#[test]
fn rejects_bad_queries() {
    let limits = Limits::default();
    assert_eq!(
        update2::decode_query("os=win", &limits),
        Err(DecodeError::Missing("x"))
    );
    assert_eq!(
        update2::decode_query("x=v%3D1", &limits),
        Err(DecodeError::Invalid("id"))
    );
    assert_eq!(
        update2::decode_query("x=id%3Da%26v%3D1.x", &limits),
        Err(DecodeError::Invalid("v"))
    );
    assert_eq!(
        update2::decode_query(
            "x=id%3Da&x=id%3Db",
            &Limits {
                max_apps: 1,
                ..limits
            }
        ),
        Err(DecodeError::TooManyApps)
    );
    assert_eq!(
        update2::decode_query("prodversion=nope&x=id%3Da", &limits),
        Err(DecodeError::Invalid("prodversion"))
    );
}

fn update(urls: &[&str], size: u64) -> UpdateCheckResponse {
    let h: Sha256 = H1.parse().unwrap();
    UpdateCheckResponse::new(Outcome::Update {
        nextversion: "2.0".parse().unwrap(),
        pipelines: vec![Pipeline {
            id: "full".into(),
            operations: vec![
                Operation::Download {
                    size,
                    out: h,
                    urls: urls.iter().map(|u| u.to_string()).collect(),
                },
                Operation::Crx3 {
                    input: h,
                    size: None,
                    path: None,
                    arguments: None,
                },
            ],
        }],
    })
}

#[test]
fn renders_gupdate_xml() {
    let mut ok = AppResponse::new(id("aaaa"), AppStatus::Ok);
    let mut check = update(&["https://cdn.example/a.crx?x=1&y=\"2\""], 1234);
    check
        .attributes
        .insert(AttributeName::new("_exts_block").unwrap(), "malware".into());
    ok.updatecheck = Some(check);
    let mut noupdate = AppResponse::new(id("bbbb"), AppStatus::Ok);
    noupdate.updatecheck = Some(UpdateCheckResponse::new(Outcome::NoUpdate));
    let unknown = AppResponse::new(id("cccc"), AppStatus::UnknownApplication);
    let response = Response {
        apps: vec![ok, noupdate, unknown],
        daystart: Some(DayStart {
            elapsed_days: 7251,
            elapsed_seconds: Some(43200),
        }),
        server: None,
    };

    assert_eq!(
        update2::encode_xml(&response).unwrap(),
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">"#,
            r#"<daystart elapsed_days="7251" elapsed_seconds="43200"/>"#,
            r#"<app appid="aaaa" status="ok"><updatecheck status="ok" "#,
            r#"codebase="https://cdn.example/a.crx?x=1&amp;y=&quot;2&quot;" version="2.0" "#,
            r#"hash_sha256="b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116" "#,
            r#"size="1234" _exts_block="malware"/></app>"#,
            r#"<app appid="bbbb" status="ok"><updatecheck status="noupdate"/></app>"#,
            r#"<app appid="cccc" status="error-unknownApplication"/>"#,
            r#"</gupdate>"#,
        )
    );
}

#[test]
fn xml_edge_cases() {
    let render = |check: UpdateCheckResponse| {
        let mut app = AppResponse::new(id("aaaa"), AppStatus::Ok);
        app.updatecheck = Some(check);
        update2::encode_xml(&Response {
            apps: vec![app],
            ..Default::default()
        })
        .unwrap()
    };
    let big = render(update(&["https://cdn.example/a.crx"], 1 << 31));
    assert!(!big.contains("size="), "{big}");

    let h: Sha256 = H1.parse().unwrap();
    let diff_only = UpdateCheckResponse::new(Outcome::Update {
        nextversion: "2.0".parse().unwrap(),
        pipelines: vec![Pipeline {
            id: "puff".into(),
            operations: vec![
                Operation::Download {
                    size: 1,
                    out: h,
                    urls: vec!["https://cdn.example/a.puff".into()],
                },
                Operation::Puff {
                    previous: h,
                    out: h,
                },
                Operation::Crx3 {
                    input: h,
                    size: None,
                    path: None,
                    arguments: None,
                },
            ],
        }],
    });
    assert!(render(diff_only).contains(r#"<updatecheck status="error-inexpressible"/>"#));

    let mut info = UpdateCheckResponse::new(Outcome::NoUpdate);
    info.info = Some("a\u{1}b\u{ffff}c\td\ne".into());
    assert!(render(info).contains("info=\"a\u{fffd}b\u{fffd}c d e\""));
}

#[test]
fn xml_parses_back_with_a_real_parser() {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let tricky = "a&b<c>d\"e'f";
    let mut check = update(&["https://cdn.example/a.crx?x=1&y=2"], 7);
    check.info = Some(tricky.into());
    check
        .attributes
        .insert(AttributeName::new("_note").unwrap(), tricky.into());
    let mut app = AppResponse::new(id("aaaa"), AppStatus::Ok);
    app.updatecheck = Some(check);
    let xml = update2::encode_xml(&Response {
        apps: vec![app],
        server: Some("<prod>".into()),
        ..Default::default()
    })
    .unwrap();

    let mut reader = Reader::from_str(&xml);
    let mut attributes = std::collections::BTreeMap::new();
    loop {
        match reader.read_event().unwrap() {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => {
                let name = e.name().as_ref().to_owned();
                for a in e.attributes() {
                    let a = a.unwrap();
                    let key = a.key.as_ref().to_owned();
                    attributes.insert(
                        format!("{name}.{key}"),
                        a.normalized_value(quick_xml::XmlVersion::Explicit1_0)
                            .unwrap()
                            .into_owned(),
                    );
                }
            }
            _ => {}
        }
    }
    assert_eq!(attributes["gupdate.server"], "<prod>");
    assert_eq!(
        attributes["updatecheck.codebase"],
        "https://cdn.example/a.crx?x=1&y=2"
    );
    assert_eq!(attributes["updatecheck.info"], tricky);
    assert_eq!(attributes["updatecheck._note"], tricky);
    assert_eq!(attributes["updatecheck.size"], "7");
}

#[test]
fn redirect_targets_the_full_package() {
    let mut app = AppResponse::new(id("aaaa"), AppStatus::Ok);
    app.updatecheck = Some(update(
        &["https://cdn.example/a.crx", "https://mirror.example/a.crx"],
        1,
    ));
    let response = Response {
        apps: vec![app],
        ..Default::default()
    };
    assert_eq!(
        update2::redirect_url(&response),
        Some("https://cdn.example/a.crx")
    );

    let mut none = AppResponse::new(id("aaaa"), AppStatus::Ok);
    none.updatecheck = Some(UpdateCheckResponse::new(Outcome::NoUpdate));
    assert_eq!(
        update2::redirect_url(&Response {
            apps: vec![none],
            ..Default::default()
        }),
        None
    );
}
