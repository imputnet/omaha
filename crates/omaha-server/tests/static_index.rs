//! A [`omaha_server::StaticIndex`] serving an endpoint while its index is
//! replaced or expires.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use omaha_protocol::*;
use omaha_server::index::aws_lc::{EcdsaKey, EcdsaSigner};
use omaha_server::index::{File, Index, OpenError, Release, Signer};
use omaha_server::{Endpoint, ReplaceError, Replaced, StaticIndex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CRLSET: &str = "hfnkpimlhhgieaddgfemjhofmfblmnib";
const START: u64 = 1_800_000_000;

static NOW: AtomicU64 = AtomicU64::new(START);

fn fixed() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(START)
}

fn moving() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW.load(Ordering::SeqCst))
}

fn index(serial: u64, version: &str) -> Index {
    let mut index = Index::new(serial, START + 3600);
    let crx = File {
        path: format!("crlset/{version}.crx3"),
        sha256: Sha256::from_bytes([1; 32]),
        size: 1000,
    };
    index.apps.insert(
        AppId::new(CRLSET).unwrap(),
        vec![Release::new(version.parse().unwrap(), crx)],
    );
    index
}

struct Setup {
    signer: EcdsaSigner,
    source: StaticIndex,
    endpoint: Endpoint,
}

fn setup(clock: fn() -> SystemTime) -> Setup {
    let signer = EcdsaSigner::generate().unwrap();
    let source = StaticIndex::builder(["https://dl.example/c", "https://mirror.example/"])
        .trust(EcdsaKey::from_spki(signer.public_key()).unwrap())
        .clock(clock)
        .build();
    let endpoint = Endpoint::builder().fallback(source.clone()).build();
    Setup {
        signer,
        source,
        endpoint,
    }
}

async fn check(endpoint: &Endpoint) -> Outcome {
    let body = format!(
        r#"{{"request":{{"protocol":"4.0","acceptformat":"crx3,download","apps":[{{"appid":"{CRLSET}","version":"1","updatecheck":{{}}}}]}}}}"#
    );
    let response = endpoint
        .handle(http::Request::post("/").body(Bytes::from(body)).unwrap())
        .await;
    assert_eq!(response.status(), 200);
    let decoded = v4::decode_response(response.body()).unwrap();
    assert!(decoded.errors.is_empty(), "{:?}", decoded.errors);
    decoded.response.apps[0]
        .updatecheck
        .clone()
        .unwrap()
        .outcome
}

fn nextversion(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Update { nextversion, .. } => nextversion.to_string(),
        other => panic!("no update: {other:?}"),
    }
}

#[tokio::test]
async fn serves_the_latest_signed_index() {
    let s = setup(fixed);
    assert_eq!(
        check(&s.endpoint).await,
        Outcome::Error(UpdateCheckError::Internal)
    );

    let first = index(1, "2").sign(&[&s.signer]).unwrap();
    assert_eq!(s.source.replace(&first), Ok(Replaced::Loaded { serial: 1 }));
    assert_eq!(nextversion(&check(&s.endpoint).await), "2");
    assert_eq!(s.source.replace(&first), Ok(Replaced::Unchanged));

    let second = index(2, "3").sign(&[&s.signer]).unwrap();
    assert_eq!(
        s.source.replace(&second),
        Ok(Replaced::Loaded { serial: 2 })
    );
    assert_eq!(nextversion(&check(&s.endpoint).await), "3");

    assert_eq!(
        s.source.replace(&first),
        Err(ReplaceError::Rollback {
            loaded: 2,
            offered: 1
        })
    );
    assert_eq!(
        s.source.replace(&index(2, "4").sign(&[&s.signer]).unwrap()),
        Err(ReplaceError::Conflict { serial: 2 })
    );

    let stranger = EcdsaSigner::generate().unwrap();
    assert_eq!(
        s.source.replace(&index(3, "4").sign(&[&stranger]).unwrap()),
        Err(ReplaceError::Open(OpenError::Untrusted))
    );
    assert_eq!(nextversion(&check(&s.endpoint).await), "3");
}

#[tokio::test]
async fn keeps_serving_an_expired_index() {
    let s = setup(moving);
    let signed = index(1, "2").sign(&[&s.signer]).unwrap();
    s.source.replace(&signed).unwrap();
    assert!(!s.source.is_stale());

    NOW.store(START + 3600, Ordering::SeqCst);
    assert!(s.source.is_stale());
    assert_eq!(nextversion(&check(&s.endpoint).await), "2");

    let fresh = setup(moving);
    assert_eq!(
        fresh
            .source
            .replace(&index(1, "2").sign(&[&fresh.signer]).unwrap()),
        Err(ReplaceError::Open(OpenError::Expired {
            expires: START + 3600
        }))
    );
}

#[tokio::test]
async fn redirects_update2_installs_to_the_first_base() {
    let s = setup(fixed);
    s.source
        .replace(&index(1, "2").sign(&[&s.signer]).unwrap())
        .unwrap();
    let x =
        form_urlencoded::byte_serialize(format!("id={CRLSET}&uc").as_bytes()).collect::<String>();
    let response = s
        .endpoint
        .handle(
            http::Request::get(format!("/?response=redirect&x={x}"))
                .body(Bytes::new())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), 302);
    assert_eq!(
        response.headers()[http::header::LOCATION],
        "https://dl.example/c/crlset/2.crx3"
    );
}
