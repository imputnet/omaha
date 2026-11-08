#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use cup2::aws_lc::MlDsa44Signer;
use http_body_util::{BodyExt, Full};
use omaha_protocol::*;
use omaha_server::{BoxFuture, Endpoint, PingSink, Source};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_service::Service;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const UNKNOWN: &str = "cccccccccccccccccccccccccccccccc";
const H: &str = "b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116";

fn id(s: &str) -> AppId {
    AppId::new(s).unwrap()
}

fn update() -> UpdateCheckResponse {
    let h: Sha256 = H.parse().unwrap();
    UpdateCheckResponse::new(Outcome::Update {
        nextversion: "2.0".parse().unwrap(),
        pipelines: vec![Pipeline {
            id: "full".into(),
            operations: vec![
                Operation::Download {
                    size: 1234,
                    out: h,
                    urls: vec!["https://cdn.example/a.crx".into()],
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

/// Offers an update for app A, says "no update" for everything else, and
/// counts its calls.
#[derive(Default)]
struct Fixed {
    calls: Arc<AtomicUsize>,
}

impl Source for Fixed {
    fn check<'a>(&'a self, _: &'a Client, apps: &'a [&'a App]) -> BoxFuture<'a, Vec<AppResponse>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            apps.iter()
                .map(|app| {
                    let mut answer = AppResponse::new(app.appid.clone(), AppStatus::Ok);
                    answer.updatecheck = Some(if app.appid.as_str() == A {
                        update()
                    } else {
                        UpdateCheckResponse::new(Outcome::NoUpdate)
                    });
                    answer
                })
                .collect()
        })
    }
}

/// Returns whatever it was built with, regardless of the request.
struct Canned(Vec<AppResponse>);

impl Source for Canned {
    fn check<'a>(&'a self, _: &'a Client, _: &'a [&'a App]) -> BoxFuture<'a, Vec<AppResponse>> {
        Box::pin(async move { self.0.clone() })
    }
}

fn clock() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_167_609_600 + 7251 * 86400 + 43200)
}

fn endpoint() -> Endpoint {
    Endpoint::builder()
        .source([id(A), id(B)], Fixed::default())
        .clock(clock)
        .build()
}

async fn call(
    endpoint: &mut Endpoint,
    request: http::Request<Full<Bytes>>,
) -> http::Response<Bytes> {
    let response = endpoint.call(request).await.unwrap();
    let (parts, body) = response.into_parts();
    http::Response::from_parts(parts, body.collect().await.unwrap().to_bytes())
}

fn post(uri: &str, body: &str) -> http::Request<Full<Bytes>> {
    http::Request::post(uri)
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap()
}

fn get(uri: &str) -> http::Request<Full<Bytes>> {
    http::Request::get(uri)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn check(appids: &[&str]) -> String {
    let apps: Vec<String> = appids
        .iter()
        .map(|a| format!(r#"{{"appid":"{a}","version":"1.0","updatecheck":{{}}}}"#))
        .collect();
    format!(
        r#"{{"request":{{"protocol":"4.0","apps":[{}]}}}}"#,
        apps.join(",")
    )
}

fn decode(response: &http::Response<Bytes>) -> Response {
    assert_eq!(response.status(), 200, "{:?}", response.body());
    let d = v4::decode_response(response.body()).unwrap();
    assert!(d.errors.is_empty(), "{:?}", d.errors);
    d.response
}

#[tokio::test]
async fn answers_and_signs_update_checks() {
    let signer = MlDsa44Signer::generate(16).unwrap();
    let client = cup2::Client::new(cup2::KeyId::MlDsa44(16), signer.public_key()).unwrap();
    let mut endpoint = Endpoint::builder()
        .source([id(A), id(B)], Fixed::default())
        .cup(cup2::Server::new().with(signer))
        .server_name("test")
        .clock(clock)
        .build();

    let body = check(&[A, UNKNOWN, B]);
    let cup = client.prepare(body.as_bytes()).unwrap();
    let response = call(
        &mut endpoint,
        post(&format!("/update?{}", cup.query()), &body),
    )
    .await;
    let proof = response.headers()["x-cup-server-proof"]
        .to_str()
        .unwrap()
        .to_owned();
    client.verify(&cup, response.body(), &proof).unwrap();
    assert!(response.headers().get("etag").is_none());

    let r = decode(&response);
    assert_eq!(r.server.as_deref(), Some("test"));
    assert_eq!(
        r.daystart,
        Some(DayStart {
            elapsed_days: 7251,
            elapsed_seconds: Some(43200)
        })
    );
    let apps: Vec<_> = r
        .apps
        .iter()
        .map(|a| (a.appid.as_str(), a.status.clone()))
        .collect();
    assert_eq!(
        apps,
        [
            (A, AppStatus::Ok),
            (UNKNOWN, AppStatus::UnknownApplication),
            (B, AppStatus::Ok)
        ]
    );
    assert_eq!(r.apps[0].updatecheck, Some(update()));
    assert_eq!(
        r.apps[2].updatecheck.as_ref().unwrap().outcome,
        Outcome::NoUpdate
    );
}

#[tokio::test]
async fn cup_etag_and_unknown_keys() {
    let signer = MlDsa44Signer::generate(16).unwrap();
    let client = cup2::Client::new(cup2::KeyId::MlDsa44(16), signer.public_key()).unwrap();
    let mut endpoint = Endpoint::builder()
        .source([id(A)], Fixed::default())
        .cup(cup2::Server::new().with(signer))
        .cup_etag(true)
        .build();
    let body = check(&[A]);
    let cup = client.prepare(body.as_bytes()).unwrap();
    let response = call(&mut endpoint, post(&format!("/?{}", cup.query()), &body)).await;
    let etag = response.headers()["etag"].to_str().unwrap().to_owned();
    client.verify(&cup, response.body(), &etag).unwrap();

    let response = call(&mut endpoint, post("/?cup2key=ML-DSA-44-17:n", &body)).await;
    assert_eq!(response.status(), 400);
    let response = call(
        &mut endpoint,
        post("/?cup2key=ML-DSA-44-16:n&cup2hreq=00", &body),
    )
    .await;
    assert_eq!(response.status(), 400);

    let response = call(&mut endpoint, post("/", &body)).await;
    assert!(response.headers().get("x-cup-server-proof").is_none());
    assert_eq!(decode(&response).apps.len(), 1);
}

struct Counter(Arc<AtomicUsize>);

impl PingSink for Counter {
    fn record(&self, _: &Client, app: &App) {
        self.0.fetch_add(app.events.len(), Ordering::SeqCst);
    }
}

#[tokio::test]
async fn acknowledges_pingbacks_without_asking_sources() {
    let source = Fixed::default();
    let calls = source.calls.clone();
    let pings = Arc::new(AtomicUsize::new(0));
    let mut endpoint = Endpoint::builder()
        .source([id(A)], source)
        .pings(Counter(pings.clone()))
        .build();
    let body = format!(
        r#"{{"request":{{"protocol":"4.0","apps":[{{"appid":"{A}","version":"2.0","events":[{{"eventtype":3,"eventresult":1}},{{"eventtype":14,"eventresult":1}}]}}]}}}}"#
    );
    let r = decode(&call(&mut endpoint, post("/", &body)).await);
    assert_eq!(r.apps[0].events, [EventStatus::Ok, EventStatus::Ok]);
    assert_eq!(r.apps[0].updatecheck, None);
    assert_eq!(pings.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn serves_update2_xml_and_redirects() {
    let mut endpoint = endpoint();
    let x = |a: &str| format!("x=id%3D{a}%26v%3D1.0%26uc");
    let response = call(
        &mut endpoint,
        get(&format!(
            "/u?prodversion=157.0.8103.38&{}&{}",
            x(A),
            x(UNKNOWN)
        )),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "text/xml; charset=utf-8"
    );
    let xml = String::from_utf8(response.body().to_vec()).unwrap();
    assert!(
        xml.contains(r#"codebase="https://cdn.example/a.crx""#),
        "{xml}"
    );
    assert!(
        xml.contains(&format!(
            r#"<app appid="{UNKNOWN}" status="error-unknownApplication"/>"#
        )),
        "{xml}"
    );

    let response = call(
        &mut endpoint,
        get(&format!("/u?response=redirect&{}", x(A))),
    )
    .await;
    assert_eq!(response.status(), 302);
    assert_eq!(response.headers()["location"], "https://cdn.example/a.crx");

    let response = call(
        &mut endpoint,
        get(&format!("/u?response=redirect&{}", x(B))),
    )
    .await;
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn fits_source_answers_to_the_request() {
    let mut no_check = AppResponse::new(id(A), AppStatus::Ok);
    no_check.events = vec![EventStatus::Ok];
    let mut unasked = AppResponse::new(id(B), AppStatus::Ok);
    unasked.updatecheck = Some(UpdateCheckResponse::new(Outcome::NoUpdate));
    let mut endpoint = Endpoint::builder()
        .source([id(A), id(B)], Canned(vec![no_check, unasked]))
        .build();
    let body = format!(
        r#"{{"request":{{"protocol":"4.0","apps":[{{"appid":"{A}","updatecheck":{{}}}},{{"appid":"{B}","data":[{{"name":"install","index":"x"}}]}}]}}}}"#
    );
    let r = decode(&call(&mut endpoint, post("/", &body)).await);
    assert_eq!(
        r.apps[0].updatecheck.as_ref().unwrap().outcome,
        Outcome::Error(UpdateCheckError::Internal)
    );
    assert!(r.apps[0].events.is_empty());
    assert_eq!(r.apps[1].updatecheck, None);
}

#[tokio::test]
async fn misbehaving_sources_only_affect_their_apps() {
    let mut wrong = AppResponse::new(id(UNKNOWN), AppStatus::Ok);
    wrong.updatecheck = Some(UpdateCheckResponse::new(Outcome::NoUpdate));
    let mut endpoint = Endpoint::builder()
        .source([id(A)], Fixed::default())
        .source([id(B)], Canned(vec![wrong.clone(), wrong]))
        .build();
    let r = decode(&call(&mut endpoint, post("/", &check(&[B, A]))).await);
    assert_eq!(
        r.apps[0].updatecheck.as_ref().unwrap().outcome,
        Outcome::Error(UpdateCheckError::Internal)
    );
    assert_eq!(r.apps[1].updatecheck, Some(update()));
}

#[tokio::test]
async fn rejects_bad_requests() {
    let mut endpoint = Endpoint::builder()
        .source([id(A)], Fixed::default())
        .limits(Limits {
            max_body_len: 512,
            max_apps: 2,
            ..Limits::default()
        })
        .build();
    let status = |r: http::Response<Bytes>| r.status().as_u16();

    assert_eq!(
        status(call(&mut endpoint, post("/", &"x".repeat(513))).await),
        413
    );
    assert_eq!(status(call(&mut endpoint, post("/", "{")).await), 400);
    assert_eq!(
        status(
            call(
                &mut endpoint,
                post("/", r#"{"request":{"protocol":"3.1"}}"#)
            )
            .await
        ),
        400
    );
    assert_eq!(status(call(&mut endpoint, get("/?os=win")).await), 400);
    let mut put = post("/", "{}");
    *put.method_mut() = http::Method::PUT;
    let response = call(&mut endpoint, put).await;
    assert_eq!(
        (
            response.status().as_u16(),
            response.headers()["allow"].to_str().unwrap()
        ),
        (405, "POST, GET")
    );

    let mut many = post("/", &check(&[A]));
    many.headers_mut().insert(
        "x-goog-update-appid",
        http::HeaderValue::from_static("a,b,c"),
    );
    assert_eq!(status(call(&mut endpoint, many).await), 400);
}

#[tokio::test]
async fn sends_retry_after() {
    let mut endpoint = Endpoint::builder()
        .source([id(A)], Fixed::default())
        .retry_after(|| Some(Duration::from_secs(7 * 86400)))
        .build();
    let response = call(&mut endpoint, post("/", &check(&[A]))).await;
    assert_eq!(response.headers()["x-retry-after"], "86400");
}
