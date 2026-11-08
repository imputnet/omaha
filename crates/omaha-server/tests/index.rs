//! Signing and opening indexes, and the answers an index gives to update
//! checks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use omaha_protocol::*;
use omaha_server::index::aws_lc::{EcdsaKey, EcdsaSigner};
use omaha_server::index::{
    File, Index, IndexError, OpenError, Patch, PatchFormat, Release, Signer,
};
use std::time::{Duration, UNIX_EPOCH};

const CRLSET: &str = "hfnkpimlhhgieaddgfemjhofmfblmnib";
const NOW: u64 = 1_800_000_000;
const BASES: &[&str] = &["https://a.example/", "https://b.example/x/"];

fn hash(byte: u8) -> Sha256 {
    Sha256::from_bytes([byte; 32])
}

fn file(path: &str, byte: u8) -> File {
    File {
        path: path.into(),
        sha256: hash(byte),
        size: 100 + u64::from(byte),
    }
}

fn v(s: &str) -> Version {
    s.parse().unwrap()
}

fn release(version: &str, byte: u8) -> Release {
    Release::new(v(version), file(&format!("crlset/{version}.crx3"), byte))
}

fn index(releases: Vec<Release>) -> Index {
    let mut index = Index::new(7, NOW + 86400);
    index.apps.insert(AppId::new(CRLSET).unwrap(), releases);
    index
}

fn client() -> Client {
    Client {
        os: Some("linux".into()),
        arch: Some("x64".into()),
        prodversion: Some(v("140.0.7000.1")),
        acceptformat: "crx3,download,puff,run,xz,zucc"
            .split(',')
            .map(str::to_owned)
            .collect(),
        ..Client::default()
    }
}

fn app(version: Option<&str>) -> App {
    let mut app = App::new(AppId::new(CRLSET).unwrap());
    app.version = version.map(v);
    app.updatecheck = Some(UpdateCheck::default());
    app
}

fn bases() -> Vec<String> {
    BASES.iter().map(|b| (*b).to_owned()).collect()
}

fn answer(index: &Index, client: &Client, app: &App) -> AppResponse {
    let answer = index.answer(Protocol::V4, client, app, &bases());
    let response = Response {
        apps: vec![answer.clone()],
        daystart: None,
        server: None,
    };
    v4::encode_response(&response).expect("answers are valid Omaha 4");
    answer
}

fn outcome(answer: &AppResponse) -> &Outcome {
    &answer.updatecheck.as_ref().unwrap().outcome
}

fn offered(answer: &AppResponse) -> Option<(String, Vec<String>)> {
    match outcome(answer) {
        Outcome::Update {
            nextversion,
            pipelines,
        } => Some((
            nextversion.to_string(),
            pipelines.iter().map(|p| p.id.clone()).collect(),
        )),
        _ => None,
    }
}

fn now() -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW)
}

#[test]
fn signs_and_opens() {
    let signer = EcdsaSigner::generate().unwrap();
    let key = EcdsaKey::from_spki(signer.public_key()).unwrap();
    let mut r = release("9001", 1);
    r.requires.prodversionmin = Some(v("120"));
    r.requires.os = vec!["win".into(), "linux".into()];
    r.patches.push(Patch {
        format: PatchFormat::Puff,
        from: hash(9),
        file: file("crlset/9000-9001.puff", 2),
    });
    r.attributes
        .insert(AttributeName::new("_flag").unwrap(), "1".into());
    let index = index(vec![r, release("9000", 9)]);

    let signed = index.sign(&[&signer]).unwrap();
    assert_eq!(Index::open(&signed, &[&key], now()).unwrap(), index);
}

#[test]
fn open_needs_a_trusted_fresh_signature() {
    let signer = EcdsaSigner::generate().unwrap();
    let other = EcdsaSigner::generate().unwrap();
    let key = EcdsaKey::from_spki(signer.public_key()).unwrap();
    let other_key = EcdsaKey::from_spki(other.public_key()).unwrap();
    let index = index(vec![release("1", 1)]);
    let signed = index.sign(&[&other, &signer]).unwrap();

    assert!(Index::open(&signed, &[&key], now()).is_ok());
    assert!(Index::open(&signed, &[&other_key], now()).is_ok());
    assert_eq!(
        Index::open(&index.sign(&[&other]).unwrap(), &[&key], now()),
        Err(OpenError::Untrusted)
    );
    let expired = UNIX_EPOCH + Duration::from_secs(NOW + 86400);
    assert_eq!(Index::verify(&signed, &[&key]), Ok(index.clone()));
    assert_eq!(
        Index::open(&signed, &[&key], expired),
        Err(OpenError::Expired {
            expires: NOW + 86400
        })
    );

    let mut envelope: serde_json::Value = serde_json::from_slice(&signed).unwrap();
    let mut replayed = index.clone();
    replayed.serial = 8;
    envelope["payload"] = STANDARD.encode(replayed.to_json().unwrap()).into();
    assert_eq!(
        Index::open(&serde_json::to_vec(&envelope).unwrap(), &[&key], now()),
        Err(OpenError::Untrusted)
    );

    let mut envelope: serde_json::Value = serde_json::from_slice(&signed).unwrap();
    envelope["payloadType"] = "application/json".into();
    assert!(matches!(
        Index::open(&serde_json::to_vec(&envelope).unwrap(), &[&key], now()),
        Err(OpenError::PayloadType(_))
    ));
}

fn parse(json: &str) -> Result<Index, IndexError> {
    Index::from_json(json.as_bytes())
}

#[test]
fn rejects_bad_documents() {
    let h = "11".repeat(32);
    let ok = format!(
        r#"{{"format":1,"serial":1,"expires":2,"apps":{{"{CRLSET}":[{{"version":"1","crx":{{"path":"a/b.crx3","sha256":"{h}","size":1}}}}]}}}}"#
    );
    assert!(parse(&ok).is_ok());

    assert_eq!(
        parse(&ok.replace(r#""format":1"#, r#""format":2"#)),
        Err(IndexError::UnsupportedFormat(2))
    );

    let bad = [
        ok.replace(r#""size":1"#, r#""size":1,"mirror":"x""#),
        ok.replace(
            r#""version":"1","#,
            r#""version":"1","requires":{"gpu":"x"},"#,
        ),
        ok.replace("a/b.crx3", "../b.crx3"),
        ok.replace("a/b.crx3", "/b.crx3"),
        ok.replace("a/b.crx3", "a//b.crx3"),
        ok.replace("a/b.crx3", "https://evil.example/b.crx3"),
        ok.replace("a/b.crx3", "a/b.crx3?x"),
        ok.replace(r#""size":1"#, r#""size":0"#),
        ok.replace(r#""version":"1""#, r#""version":"x""#),
        ok.replace(&h, "11"),
    ];

    for doc in bad {
        assert!(parse(&doc).is_err(), "accepted {doc}");
    }

    let mut duplicate = index(vec![release("1", 1), release("1.0", 2)]);
    assert!(duplicate.to_json().is_err());
    duplicate.apps.clear();
    assert!(duplicate.to_json().is_ok());
}

#[test]
fn offers_the_newest_release() {
    let index = index(vec![release("3", 3), release("1", 1), release("2", 2)]);
    let answer = answer(&index, &client(), &app(Some("1")));
    assert_eq!(answer.status, AppStatus::Ok);
    assert_eq!(offered(&answer), Some(("3".into(), vec!["full".into()])));

    let Outcome::Update { pipelines, .. } = outcome(&answer) else {
        panic!()
    };
    let (urls, sha256, size) = pipelines[0].full_crx().unwrap();
    assert_eq!(
        urls,
        [
            "https://a.example/crlset/3.crx3",
            "https://b.example/x/crlset/3.crx3"
        ]
    );
    assert_eq!((*sha256, size), (hash(3), 103));
}

#[test]
fn compares_with_the_installed_version() {
    let index = index(vec![release("2", 2)]);
    let client = client();
    let mut same = app(Some("2"));
    let mut newer = app(Some("3"));

    assert_eq!(
        offered(&answer(&index, &client, &app(None))).unwrap().0,
        "2"
    );
    assert_eq!(outcome(&answer(&index, &client, &same)), &Outcome::NoUpdate);
    assert_eq!(
        outcome(&answer(&index, &client, &newer)),
        &Outcome::NoUpdate
    );

    same.updatecheck.as_mut().unwrap().sameversionupdate = true;
    newer.updatecheck.as_mut().unwrap().rollback_allowed = true;
    assert_eq!(offered(&answer(&index, &client, &same)).unwrap().0, "2");
    assert_eq!(offered(&answer(&index, &client, &newer)).unwrap().0, "2");

    let mut disabled = app(Some("1"));
    disabled.updatecheck.as_mut().unwrap().updatedisabled = true;
    assert_eq!(
        outcome(&answer(&index, &client, &disabled)),
        &Outcome::NoUpdate
    );
}

#[test]
fn honours_target_version_prefix() {
    let index = index(vec![
        release("1.2.3.4", 1),
        release("1.2.34.0", 2),
        release("1.3.0.0", 3),
    ]);
    let mut pinned = app(Some("1.2.0.0"));
    pinned.updatecheck.as_mut().unwrap().targetversionprefix = Some("1.2.3".into());
    assert_eq!(
        offered(&answer(&index, &client(), &pinned)).unwrap().0,
        "1.2.3.4"
    );

    let mut downgrade = app(Some("1.3.0.0"));
    let check = downgrade.updatecheck.as_mut().unwrap();
    check.targetversionprefix = Some("1.2".into());
    assert_eq!(
        outcome(&answer(&index, &client(), &downgrade)),
        &Outcome::NoUpdate
    );

    downgrade.updatecheck.as_mut().unwrap().rollback_allowed = true;
    assert_eq!(
        offered(&answer(&index, &client(), &downgrade)).unwrap().0,
        "1.2.34.0"
    );
}

#[test]
fn applies_requirements() {
    let mut newest = release("3", 3);
    newest.requires.prodversionmin = Some(v("150"));
    let mut mac = release("2", 2);
    mac.requires.os = vec!["mac".into()];
    let index = index(vec![newest, mac, release("1", 1)]);
    assert_eq!(
        offered(&answer(&index, &client(), &app(None))).unwrap().0,
        "1"
    );

    let mut new_browser = client();
    new_browser.prodversion = Some(v("150.0.1.0"));
    assert_eq!(
        offered(&answer(&index, &new_browser, &app(None)))
            .unwrap()
            .0,
        "3"
    );

    let mut unknown = client();
    unknown.prodversion = None;
    assert_eq!(
        offered(&answer(&index, &unknown, &app(None))).unwrap().0,
        "1"
    );
}

#[test]
fn reports_unsupported_systems() {
    let mut win = release("2", 2);
    win.requires.os = vec!["win".into()];
    let mut arm = release("1", 1);
    arm.requires.arch = vec!["arm64".into()];
    let mut later = release("3", 3);
    later.requires.prodversionmin = Some(v("999"));

    assert_eq!(
        outcome(&answer(&index(vec![win.clone()]), &client(), &app(None))),
        &Outcome::Error(UpdateCheckError::OsNotSupported)
    );
    assert_eq!(
        outcome(&answer(
            &index(vec![win.clone(), arm.clone()]),
            &client(),
            &app(None)
        )),
        &Outcome::Error(UpdateCheckError::HwNotSupported)
    );
    assert_eq!(
        outcome(&answer(
            &index(vec![win, arm, later]),
            &client(),
            &app(None)
        )),
        &Outcome::NoUpdate
    );

    let mut win = release("2", 2);
    win.requires.os = vec!["win".into()];
    let mut linux = release("1", 1);
    linux.requires.os = vec!["linux".into()];
    let mut pinned = app(None);
    pinned.updatecheck.as_mut().unwrap().targetversionprefix = Some("2".into());
    assert_eq!(
        outcome(&answer(&index(vec![win, linux]), &client(), &pinned)),
        &Outcome::NoUpdate,
        "the OS is supported, just not by the pinned version"
    );
}

#[test]
fn prefers_a_patch_from_a_cached_crx() {
    let mut r = release("2", 2);
    r.patches = vec![
        Patch {
            format: PatchFormat::Zucc,
            from: hash(1),
            file: file("crlset/1-2.zucc", 5),
        },
        Patch {
            format: PatchFormat::Puff,
            from: hash(1),
            file: file("crlset/1-2.puff", 6),
        },
    ];
    let index = index(vec![r]);
    let mut cached = app(Some("1"));
    cached.cached = vec![hash(1)];

    let answer_with = |formats: &str, app: &App| {
        let mut client = client();
        client.acceptformat = formats.split(',').map(str::to_owned).collect();
        offered(&answer(&index, &client, app)).map(|(_, pipelines)| pipelines)
    };

    assert_eq!(
        answer_with("crx3,download,puff,zucc", &cached),
        Some(vec!["zucc".into(), "full".into()])
    );
    assert_eq!(
        answer_with("crx3,download,puff", &cached),
        Some(vec!["puff".into(), "full".into()])
    );
    assert_eq!(
        answer_with("crx3,download,puff,zucc", &app(Some("1"))),
        Some(vec!["full".into()])
    );

    let mut client = client();
    client.acceptformat = vec!["crx3".into(), "download".into(), "puff".into()];
    let answer = answer(&index, &client, &cached);
    let Outcome::Update { pipelines, .. } = outcome(&answer) else {
        panic!()
    };
    assert_eq!(
        pipelines[0].operations,
        vec![
            Operation::Download {
                size: 106,
                out: hash(6),
                urls: vec![
                    "https://a.example/crlset/1-2.puff".into(),
                    "https://b.example/x/crlset/1-2.puff".into()
                ],
            },
            Operation::Puff {
                previous: hash(1),
                out: hash(2),
            },
            Operation::Crx3 {
                input: hash(2),
                size: None,
                path: None,
                arguments: None,
            },
        ]
    );
}

#[test]
fn respects_acceptformat_only_in_omaha_4() {
    let index = index(vec![release("2", 2)]);
    let mut client = client();
    client.acceptformat = vec!["crx3".into(), "puff".into()];

    assert_eq!(
        outcome(&answer(&index, &client, &app(None))),
        &Outcome::Error(UpdateCheckError::Inexpressible)
    );

    let update2 = index.answer(Protocol::Update2, &client, &app(None), &bases());
    assert_eq!(offered(&update2), Some(("2".into(), vec!["full".into()])));
}

#[test]
fn passes_attributes_and_handles_odd_apps() {
    let mut r = release("2", 2);
    r.attributes
        .insert(AttributeName::new("_esbAllowlist").unwrap(), "true".into());
    let index = index(vec![r]);

    let answer = answer(&index, &client(), &app(None));
    let attributes = &answer.updatecheck.as_ref().unwrap().attributes;
    assert_eq!(
        attributes.get(&AttributeName::new("_esbAllowlist").unwrap()),
        Some(&"true".to_owned())
    );

    let mut other = app(None);
    other.appid = AppId::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    assert_eq!(
        index
            .answer(Protocol::V4, &client(), &other, &bases())
            .status,
        AppStatus::UnknownApplication
    );

    let mut no_check = app(Some("1"));
    no_check.updatecheck = None;
    assert!(
        index
            .answer(Protocol::V4, &client(), &no_check, &bases())
            .updatecheck
            .is_none()
    );
}

#[test]
fn refuses_oversized_envelopes() {
    let huge = vec![b' '; (16 << 20) + 1];
    assert!(matches!(
        Index::verify(&huge, &[]),
        Err(OpenError::Envelope(e)) if e.contains("16 MiB")
    ));
}
