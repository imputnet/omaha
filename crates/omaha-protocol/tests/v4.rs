#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use omaha_protocol::v4::{self, RequestIds};
use omaha_protocol::*;

const H1: &str = "b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116";
const H2: &str = "1c995179f75863101c995179f75863101c995179f75863101c995179f7586310";

fn hash(h: &str) -> Sha256 {
    h.parse().unwrap()
}

fn id(s: &str) -> AppId {
    AppId::new(s).unwrap()
}

/// Shaped like Chromium's `ProtocolSerializerJSON::Serialize` output,
/// including the identifiers servers must never see.
const CHROMIUM_REQUEST: &str = r#"{"request":{
    "protocol":"4.0","ismachine":false,"dedup":"cr",
    "acceptformat":"crx3,download,puff,run,xz,zucc",
    "sessionid":"{2c7b5a6e-0000-4000-8000-000000000001}",
    "requestid":"{2c7b5a6e-0000-4000-8000-000000000002}",
    "@updater":"chrome","prodversion":"157.0.8103.38","updaterversion":"157.0.8103.38",
    "@os":"linux","arch":"x64","prodchannel":"stable",
    "hw":{"physmemory":16,"sse":true,"sse2":true,"sse3":true,"sse41":true,"sse42":true,"ssse3":true,"avx":true},
    "os":{"platform":"Linux","arch":"x86_64","version":"6.12.0"},
    "apps":[{
        "appid":"hfnkpimlhhgieaddgfemjhofmfblmnib","version":"10461","lang":"en-US",
        "installdate":6850,"iid":"{2c7b5a6e-0000-4000-8000-000000000003}",
        "cohort":"1:jcl:","cohortname":"Stable","enabled":true,
        "cached_items":[{"sha256":"b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116"}],
        "updatecheck":{},
        "ping":{"ping_freshness":"{2c7b5a6e-0000-4000-8000-000000000004}","ad":6900,"rd":6900},
        "events":[{"eventtype":3,"eventresult":1}]
    }]
}}"#;

#[test]
fn decodes_chromium_request_without_identifiers() {
    let r = v4::decode_request(CHROMIUM_REQUEST.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(r.protocol, Protocol::V4);
    assert_eq!(r.client.updater.as_deref(), Some("chrome"));
    assert_eq!(r.client.prodversion, Some("157.0.8103.38".parse().unwrap()));
    assert!(r.client.accepts("puff") && r.client.accepts("zucc") && !r.client.accepts("bsdiff"));
    assert_eq!(
        r.client.platform.as_ref().unwrap().arch.as_deref(),
        Some("x86_64")
    );
    let app = &r.apps[0];
    assert_eq!(app.appid, id("hfnkpimlhhgieaddgfemjhofmfblmnib"));
    assert_eq!(app.version, Some("10461".parse().unwrap()));
    assert_eq!(app.cohort.id.as_deref(), Some("1:jcl:"));
    assert_eq!(app.cached, [hash(H1)]);
    assert_eq!(app.updatecheck, Some(UpdateCheck::default()));
    let hw = r.client.hw.as_ref().unwrap();
    assert_eq!((hw.avx, hw.physmemory), (Some(true), Some(16)));
    assert!(!app.is_pingback());
    assert!(
        !format!("{r:?}").contains("2c7b5a6e"),
        "identifiers leaked into the model"
    );
}

fn sample_request() -> Request {
    let mut app = App::new(id("{8A69D345-D564-463C-AFF1-A69D9E530F96}"));
    app.version = Some("156.0.1.2".parse().unwrap());
    app.ap = Some("x64-stable".into());
    app.brand = Some("HLM1".into());
    app.cohort.hint = Some("157".into());
    app.enabled = Some(false);
    app.disabled_reasons = vec![1, 1024];
    app.cached = vec![hash(H1), hash(H2)];
    app.updatecheck = Some(UpdateCheck {
        updatedisabled: true,
        rollback_allowed: true,
        sameversionupdate: false,
        targetversionprefix: Some("157.".into()),
    });
    app.data = vec![
        DataRequest::Install {
            index: "verboselogging".into(),
        },
        DataRequest::Untrusted {
            text: "a=1&b=2".into(),
        },
    ];
    Request {
        protocol: Protocol::V4,
        client: Client {
            updater: Some("updater".into()),
            prodversion: Some("157.0.8103.38".parse().unwrap()),
            updaterversion: Some("1.2.3".parse().unwrap()),
            os: Some("win".into()),
            arch: Some("x64".into()),
            platform: Some(Platform {
                platform: Some("Windows".into()),
                version: Some("10.0.26100".into()),
                arch: Some("x86_64".into()),
                service_pack: Some("SP1".into()),
                device_form_factor: Some("desktop".into()),
            }),
            acceptformat: vec!["crx3".into(), "download".into(), "run".into()],
            prodchannel: Some("beta".into()),
            updaterchannel: Some("stable".into()),
            ismachine: true,
            wow64: true,
            domainjoined: Some(false),
            dlpref: Some("cacheable".into()),
            hw: Some(Hardware {
                sse: Some(true),
                sse2: Some(true),
                avx: Some(false),
                physmemory: Some(8),
                ..Hardware::default()
            }),
        },
        apps: vec![app],
    }
}

#[test]
fn requests_round_trip() {
    let request = sample_request();
    let ids = RequestIds {
        session_id: "{s}".into(),
        request_id: "{r}".into(),
    };
    let body = v4::encode_request(&request, Some(&ids)).unwrap();
    assert!(String::from_utf8_lossy(&body).contains("\"sessionid\":\"{s}\""));
    assert_eq!(
        v4::decode_request(&body, &Limits::default()).unwrap(),
        request
    );
}

fn sample_response() -> Response {
    let full = Pipeline {
        id: "full".into(),
        operations: vec![
            Operation::Download {
                size: 9092445,
                out: hash(H1),
                urls: vec![
                    "https://cdn.example/a.crx".into(),
                    "https://mirror.example/a.crx".into(),
                ],
            },
            Operation::Crx3 {
                input: hash(H1),
                size: None,
                path: None,
                arguments: None,
            },
        ],
    };
    let diff = Pipeline {
        id: "puff".into(),
        operations: vec![
            Operation::Download {
                size: 1200,
                out: hash(H2),
                urls: vec!["https://cdn.example/a.puff".into()],
            },
            Operation::Puff {
                previous: hash(H2),
                out: hash(H1),
            },
            Operation::Crx3 {
                input: hash(H1),
                size: Some(9092445),
                path: None,
                arguments: None,
            },
        ],
    };
    let installer = Pipeline {
        id: "installer".into(),
        operations: vec![
            Operation::Download {
                size: 5,
                out: hash(H2),
                urls: vec!["https://cdn.example/s.crx".into()],
            },
            Operation::Xz,
            Operation::Zucc {
                previous: hash(H1),
                out: hash(H2),
            },
            Operation::Crx3 {
                input: hash(H2),
                size: None,
                path: Some("setup.exe".into()),
                arguments: Some("--do-update".into()),
            },
            Operation::Run {
                path: "postinstall.exe".into(),
                arguments: None,
            },
        ],
    };
    let mut update = UpdateCheckResponse::new(Outcome::Update {
        nextversion: "2026.1103.1743".parse().unwrap(),
        pipelines: vec![diff, full, installer],
    });
    update
        .attributes
        .insert(AttributeName::new("_exts_block").unwrap(), "malware".into());
    let mut ok = AppResponse::new(id("ddkjiahejlhfcafbddmgiahcphecmpfh"), AppStatus::Ok);
    ok.cohort.id = Some("1:abc:".into());
    ok.data = vec![DataResponse {
        name: "install".into(),
        index: Some("verboselogging".into()),
        status: DataStatus::Ok,
        text: Some("{\"distribution\":{}}".into()),
    }];
    ok.updatecheck = Some(update);
    let mut noupdate = AppResponse::new(id("nngceckbapebfimnlniiiahkandclblb"), AppStatus::Ok);
    let mut check = UpdateCheckResponse::new(Outcome::NoUpdate);
    check.info = Some("up to date".into());
    noupdate.updatecheck = Some(check);
    let mut failed = AppResponse::new(id("eimadpbcbfnmbkopoojfekhnkhdbieeh"), AppStatus::Ok);
    failed.updatecheck = Some(UpdateCheckResponse::new(Outcome::Error(
        UpdateCheckError::OsNotSupported,
    )));
    Response {
        apps: vec![
            ok,
            noupdate,
            failed,
            AppResponse::new(
                id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                AppStatus::UnknownApplication,
            ),
        ],
        daystart: Some(DayStart {
            elapsed_days: 7251,
            elapsed_seconds: Some(43200),
        }),
        server: Some("exts.org".into()),
    }
}

#[test]
fn responses_round_trip() {
    let response = sample_response();
    let body = v4::encode_response(&response).unwrap();
    assert!(body.starts_with(v4::SAFE_JSON_PREFIX.as_bytes()));
    let decoded = v4::decode_response(&body).unwrap();
    assert!(decoded.errors.is_empty(), "{:?}", decoded.errors);
    assert_eq!(decoded.response, response);
}

/// Shaped like what clients2.google.com returned for a Chrome Web Store
/// extension on 2026-11-08.
const GOOGLE_RESPONSE: &str = r#")]}'
{"response":{"server":"prod","protocol":"4.0","daystart":{"elapsed_seconds":43200,"elapsed_days":7251},"apps":[{"appid":"ddkjiahejlhfcafbddmgiahcphecmpfh","cohort":"1::","status":"ok","cohortname":"","updatecheck":{"_esbAllowlist":"true","status":"ok","nextversion":"2026.1103.1743","pipelines":[{"pipeline_id":"direct_full","operations":[{"type":"download","size":9092445,"out":{"sha256":"b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116"},"urls":[{"url":"https://clients2.googleusercontent.com/crx/blobs/ARGaeZJQ/DDKJIAHEJLHFCAFBDDMGIAHCPHECMPFH_2026_1103_1743.crx"}]},{"type":"crx3","in":{"sha256":"b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116"}}]}]}}]}}"#;

#[test]
fn decodes_google_response() {
    let d = v4::decode_response(GOOGLE_RESPONSE.as_bytes()).unwrap();
    assert!(d.errors.is_empty(), "{:?}", d.errors);
    assert_eq!(
        d.response.daystart,
        Some(DayStart {
            elapsed_days: 7251,
            elapsed_seconds: Some(43200)
        })
    );
    let check = d.response.apps[0].updatecheck.as_ref().unwrap();
    assert_eq!(
        check.attributes[&AttributeName::new("_esbAllowlist").unwrap()],
        "true"
    );
    let Outcome::Update {
        nextversion,
        pipelines,
    } = &check.outcome
    else {
        panic!()
    };
    assert_eq!(nextversion.to_string(), "2026.1103.1743");
    let (urls, out, size) = pipelines[0].full_crx().unwrap();
    assert_eq!((out, size, urls.len()), (&hash(H1), 9092445, 1));
}

#[test]
fn sizes_like_chromium() {
    let body = |size: &str| {
        format!(
            r#")]}}'{{"response":{{"protocol":"4.0","apps":[{{"appid":"a","status":"ok","updatecheck":{{"status":"ok","nextversion":"1","pipelines":[{{"operations":[{{"type":"download","size":{size},"out":{{"sha256":"{H1}"}},"urls":[{{"url":"https://x.example/a"}}]}}]}}]}}}}]}}}}"#
        )
    };
    for (size, expected) in [
        ("1234", 1234),
        ("9007199254740991", 9007199254740991),
        ("-1234", 0),
        ("\"-a\"", 0),
        ("123467890123456789", 0),
    ] {
        let d = v4::decode_response(body(size).as_bytes()).unwrap();
        let Outcome::Update { pipelines, .. } =
            &d.response.apps[0].updatecheck.as_ref().unwrap().outcome
        else {
            panic!()
        };
        let Operation::Download { size: got, .. } = pipelines[0].operations[0] else {
            panic!()
        };
        assert_eq!(got, expected, "{size}");
    }
}

#[test]
fn rejects_bad_requests() {
    let limits = Limits::default();
    let decode = |s: &str| v4::decode_request(s.as_bytes(), &limits);
    assert_eq!(
        decode(r#"{"request":{"protocol":"3.1","apps":[]}}"#),
        Err(DecodeError::UnsupportedProtocol("3.1".into()))
    );
    assert!(matches!(decode("{"), Err(DecodeError::Syntax(_))));
    assert_eq!(
        decode(r#"{"request":{"protocol":"4.0","apps":[{"appid":"a b"}]}}"#),
        Err(DecodeError::Invalid("appid"))
    );
    assert_eq!(
        decode(r#"{"request":{"protocol":"4.0","apps":[{"appid":"a","version":"1.x"}]}}"#),
        Err(DecodeError::Invalid("version"))
    );
    assert_eq!(
        decode(
            r#"{"request":{"protocol":"4.0","apps":[{"appid":"a","cached_items":[{"sha256":"12"}]}]}}"#
        ),
        Err(DecodeError::Invalid("cached_items"))
    );

    let small = Limits {
        max_body_len: 64,
        max_apps: 2,
        max_string_len: 8,
        max_list_len: 1,
    };
    let apps = |n: usize| {
        let apps = vec![r#"{"appid":"a"}"#; n].join(",");
        format!(r#"{{"request":{{"protocol":"4.0","apps":[{apps}]}}}}"#)
    };
    assert_eq!(
        v4::decode_request(
            apps(3).as_bytes(),
            &Limits {
                max_apps: 2,
                ..Limits::default()
            }
        ),
        Err(DecodeError::TooManyApps)
    );
    assert_eq!(
        v4::decode_request(apps(30).as_bytes(), &small),
        Err(DecodeError::TooLarge)
    );
    assert_eq!(
        v4::decode_request(
            br#"{"request":{"protocol":"4.0","apps":[{"appid":"aaaaaaaaa"}]}}"#,
            &small
        ),
        Err(DecodeError::FieldTooLong("appid"))
    );
}

/// Shaped like a Chromium component updater ping-back after an update.
const CHROMIUM_PINGBACK: &str = r#"{"request":{
    "protocol":"4.0","ismachine":false,"dedup":"cr","acceptformat":"crx3,download,puff,run,xz,zucc",
    "sessionid":"{s}","requestid":"{r}","@updater":"chrome","prodversion":"157.0.8103.38",
    "@os":"linux","arch":"x64","hw":{"physmemory":"-1","sse":"1","avx":"-1"},
    "apps":[{"appid":"hfnkpimlhhgieaddgfemjhofmfblmnib","version":"10462","events":[
        {"eventtype":14,"eventresult":1,"download_time_ms":812,"downloaded":4096,"total":4096,
         "downloader":"direct","url":"https://cdn.example/crlset.crx","pipeline_id":"direct_full",
         "previousversion":"10461","nextversion":"10462"},
        {"eventtype":3,"eventresult":0,"errorcat":2,"errorcode":7,"extracode1":-3,
         "previousversion":"10461","nextversion":"10462"}
    ]}]
}}"#;

#[test]
fn decodes_and_answers_pingbacks() {
    let r = v4::decode_request(CHROMIUM_PINGBACK.as_bytes(), &Limits::default()).unwrap();
    let hw = r.client.hw.as_ref().unwrap();
    assert_eq!((hw.sse, hw.avx, hw.physmemory), (Some(true), None, None));
    let app = &r.apps[0];
    assert!(app.is_pingback());
    let download = &app.events[0];
    assert_eq!(
        (download.kind, download.result),
        (EventType::Download, EventResult::Success)
    );
    assert_eq!(download.pipeline_id.as_deref(), Some("direct_full"));
    let stats = download.download.as_ref().unwrap();
    assert_eq!(
        (stats.time_ms, stats.downloaded, stats.total),
        (Some(812), 4096, 4096)
    );
    assert_eq!(stats.downloader.as_deref(), Some("direct"));
    let update = &app.events[1];
    assert_eq!(
        (update.kind, update.result),
        (EventType::Update, EventResult::Error)
    );
    assert_eq!(
        (update.error_category, update.error_code, update.extra_code1),
        (2, 7, -3)
    );
    assert_eq!(update.previous_version, Some("10461".parse().unwrap()));
    assert!(
        !format!("{r:?}").contains("cdn.example"),
        "download URL leaked into the model"
    );

    let response = Response {
        apps: vec![AppResponse::pingback(app)],
        ..Default::default()
    };
    let body = v4::encode_response(&response).unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains(r#""events":[{"status":"ok"},{"status":"ok"}]"#)
    );
    assert_eq!(v4::decode_response(&body).unwrap().response, response);

    let pingback = Request {
        protocol: Protocol::V4,
        client: Client::default(),
        apps: vec![app.clone()],
    };
    let again = v4::decode_request(
        &v4::encode_request(&pingback, None).unwrap(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(again.apps, pingback.apps);
}

#[test]
fn refuses_invalid_responses() {
    let h = hash(H1);
    let with = |operations: Vec<Operation>| {
        let mut app = AppResponse::new(id("a"), AppStatus::Ok);
        app.updatecheck = Some(UpdateCheckResponse::new(Outcome::Update {
            nextversion: "1".parse().unwrap(),
            pipelines: vec![Pipeline {
                id: "p".into(),
                operations,
            }],
        }));
        Response {
            apps: vec![app],
            ..Default::default()
        }
    };
    let download = |size: u64, urls: &[&str]| Operation::Download {
        size,
        out: h,
        urls: urls.iter().map(|u| u.to_string()).collect(),
    };
    let crx3 = |input| Operation::Crx3 {
        input,
        size: None,
        path: None,
        arguments: None,
    };
    let err = |r: Response| v4::encode_response(&r).unwrap_err();
    let (a, p) = (|| "a".to_owned(), || "p".to_owned());
    let invalid_download = || EncodeError::InvalidDownload {
        appid: a(),
        pipeline: p(),
    };

    assert!(
        v4::encode_response(&with(vec![download(1, &["https://x.example/a"]), crx3(h)])).is_ok()
    );
    assert_eq!(
        err(with(vec![])),
        EncodeError::EmptyPipeline {
            appid: a(),
            pipeline: p()
        }
    );
    assert_eq!(
        err(with(vec![download(0, &["https://x.example/a"])])),
        invalid_download()
    );
    assert_eq!(err(with(vec![download(1, &[])])), invalid_download());
    assert_eq!(
        err(with(vec![download(1, &["ftp://x.example/a"])])),
        invalid_download()
    );
    assert_eq!(
        err(with(vec![
            download(1, &["https://x.example/a"]),
            crx3(hash(H2))
        ])),
        EncodeError::HashMismatch {
            appid: a(),
            pipeline: p()
        }
    );
    assert_eq!(
        err(with(vec![Operation::Run {
            path: String::new(),
            arguments: None
        }])),
        EncodeError::InvalidRun {
            appid: a(),
            pipeline: p()
        }
    );
    assert_eq!(
        err(with(vec![Operation::Other {
            kind: "bsdiff".into()
        }])),
        EncodeError::UnknownOperation {
            appid: a(),
            pipeline: p()
        }
    );

    let mut no_pipelines = with(vec![]);
    no_pipelines.apps[0].updatecheck = Some(UpdateCheckResponse::new(Outcome::Update {
        nextversion: "1".parse().unwrap(),
        pipelines: vec![],
    }));
    assert_eq!(err(no_pipelines), EncodeError::NoPipelines { appid: a() });

    let mut mixed = with(vec![download(1, &["https://x.example/a"]), crx3(h)]);
    mixed.apps[0].events = vec![EventStatus::Ok];
    assert_eq!(err(mixed), EncodeError::MixedPingback { appid: a() });
}

#[test]
fn accepts_protocol_4_value_forms() {
    let body = br#"{"request":{"protocol":"4.0","ismachine":-1,"wow64":"1","domainjoined":"false","apps":[
        {"appid":"a","enabled":"0","disabled":[{"reason":"1024"},{"reason":2}],
         "updatecheck":{"updatedisabled":"true","rollback_allowed":1,"sameversionupdate":false}}]}}"#;
    let r = v4::decode_request(body, &Limits::default()).unwrap();
    assert_eq!(
        (r.client.ismachine, r.client.wow64, r.client.domainjoined),
        (false, true, Some(false))
    );
    let app = &r.apps[0];
    assert_eq!(app.enabled, Some(false));
    assert_eq!(app.disabled_reasons, [1024, 2]);
    let u = app.updatecheck.as_ref().unwrap();
    assert!(u.updatedisabled && u.rollback_allowed && !u.sameversionupdate);

    let bad = br#"{"request":{"protocol":"4.0","apps":[{"appid":"a","enabled":"yes"}]}}"#;
    assert!(matches!(
        v4::decode_request(bad, &Limits::default()),
        Err(DecodeError::Syntax(_))
    ));
}

#[test]
fn refuses_ambiguous_statuses_and_huge_sizes() {
    let mut app = AppResponse::new(id("a"), AppStatus::Ok);
    app.updatecheck = Some(UpdateCheckResponse::new(Outcome::Error(
        UpdateCheckError::Other("ok".into()),
    )));
    let r = Response {
        apps: vec![app],
        ..Default::default()
    };
    assert_eq!(
        v4::encode_response(&r).unwrap_err(),
        EncodeError::InvalidStatus { appid: "a".into() }
    );

    let h = hash(H1);
    let mut app = AppResponse::new(id("a"), AppStatus::Ok);
    app.updatecheck = Some(UpdateCheckResponse::new(Outcome::Update {
        nextversion: "1".parse().unwrap(),
        pipelines: vec![Pipeline {
            id: "p".into(),
            operations: vec![
                Operation::Download {
                    size: 1 << 53,
                    out: h,
                    urls: vec!["https://x.example/a".into()],
                },
                Operation::Crx3 {
                    input: h,
                    size: None,
                    path: None,
                    arguments: None,
                },
            ],
        }],
    }));
    let r = Response {
        apps: vec![app],
        ..Default::default()
    };
    assert!(matches!(
        v4::encode_response(&r),
        Err(EncodeError::InvalidDownload { .. })
    ));
}
