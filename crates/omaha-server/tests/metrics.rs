//! Metrics the endpoint records, and that their labels never carry what a
//! client sent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use omaha_protocol::*;
use omaha_server::{BoxFuture, Check, Endpoint, Source};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ROUTED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VOUCHED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const STRANGER: &str = "cccccccccccccccccccccccccccccccc";
const TODAY: u32 = 7251;

fn clock() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_167_609_600 + u64::from(TODAY) * 86400 + 3600)
}

/// Offers an update to the routed app, "no update" to the rest, and vouches
/// for one app's ID.
struct Store;

impl Source for Store {
    fn check<'a>(&'a self, check: Check<'a>) -> BoxFuture<'a, Vec<AppResponse>> {
        let answers = check
            .apps
            .iter()
            .map(|app| {
                let mut answer = AppResponse::new(app.appid.clone(), AppStatus::Ok);
                let outcome = if app.appid.as_str() == ROUTED {
                    let h = Sha256::from_bytes([1; 32]);
                    Outcome::Update {
                        nextversion: "2".parse().unwrap(),
                        pipelines: vec![Pipeline {
                            id: "full".into(),
                            operations: vec![
                                Operation::Download {
                                    size: 1,
                                    out: h,
                                    urls: vec!["https://dl.example/a.crx3".into()],
                                },
                                Operation::Crx3 {
                                    input: h,
                                    size: None,
                                    path: None,
                                    arguments: None,
                                },
                            ],
                        }],
                    }
                } else {
                    Outcome::NoUpdate
                };
                answer.updatecheck = Some(UpdateCheckResponse::new(outcome));
                answer
            })
            .collect();
        Box::pin(async move { answers })
    }

    fn labels_app(&self, appid: &AppId) -> bool {
        appid.as_str() == VOUCHED
    }
}

fn request() -> Bytes {
    let app = |id: &str, version: &str, ping: String| {
        format!(
            r#"{{"appid":"{id}","version":"{version}","updatecheck":{{}},"ping":{{{ping},"ping_freshness":"{{00000000-0000-4000-8000-000000000000}}"}}}}"#
        )
    };
    let pingback = format!(
        r#"{{"appid":"{STRANGER}","version":"9.8.7.6","events":[{{"eventtype":3,"eventresult":1}},{{"eventtype":14,"eventresult":0,"errorcode":5}}]}}"#
    );
    let apps = [
        app(ROUTED, "1.2.3.4", format!(r#""rd":{}"#, TODAY - 1)),
        app(
            VOUCHED,
            "5.6.7.8",
            format!(r#""rd":{TODAY},"ad":{}"#, TODAY - 3),
        ),
        app(STRANGER, "31.33.7.1", r#""r":-1,"a":2"#.into()),
        pingback,
    ];
    Bytes::from(format!(
        r#"{{"request":{{"protocol":"4.0","acceptformat":"crx3,download","apps":[{}]}}}}"#,
        apps.join(",")
    ))
}

type Counters = BTreeMap<String, u64>;

fn run(count_activity: bool) -> Counters {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let endpoint = Endpoint::builder()
        .source([AppId::new(ROUTED).unwrap()], Store)
        .fallback(Store)
        .count_activity(count_activity)
        .clock(clock)
        .build();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let request = http::Request::post("/").body(request()).unwrap();
            let response = endpoint.handle(request).await;
            assert_eq!(response.status(), 200);
            let request = http::Request::put("/").body(Bytes::new()).unwrap();
            assert_eq!(endpoint.handle(request).await.status(), 405);
        });
    });

    let mut counters = Counters::new();

    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        let key = key.key();
        let labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();

        for label in &labels {
            assert!(
                !label.contains('.') && !label.contains(STRANGER),
                "client data in a label: {label}"
            );
        }

        if let DebugValue::Counter(n) = value {
            counters.insert(format!("{}{{{}}}", key.name(), labels.join(",")), n);
        }
    }

    counters
}

#[test]
fn counts_with_bounded_labels() {
    let counters = run(true);
    let get = |name: &str| counters.get(name).copied().unwrap_or(0);

    assert_eq!(get("omaha_requests_total{protocol=v4,status=200}"), 1);
    assert_eq!(get("omaha_requests_total{protocol=other,status=405}"), 1);
    assert_eq!(
        get(&format!(
            "omaha_update_checks_total{{app={ROUTED},outcome=update}}"
        )),
        1
    );
    assert_eq!(
        get(&format!(
            "omaha_update_checks_total{{app={VOUCHED},outcome=noupdate}}"
        )),
        1
    );
    assert_eq!(
        get("omaha_update_checks_total{app=other,outcome=noupdate}"),
        1
    );
    assert_eq!(
        get(&format!(
            "omaha_updates_offered_total{{app={ROUTED},pipeline=full}}"
        )),
        1
    );
    assert_eq!(
        get("omaha_events_total{app=other,event=update,result=success}"),
        1
    );
    assert_eq!(
        get("omaha_events_total{app=other,event=download,result=error}"),
        1
    );

    assert_eq!(get(&format!("omaha_roll_calls_total{{app={ROUTED}}}")), 1);
    assert_eq!(get(&format!("omaha_roll_calls_total{{app={VOUCHED}}}")), 0);
    assert_eq!(get("omaha_roll_calls_total{app=other}"), 1);
    assert_eq!(
        get(&format!("omaha_active_reports_total{{app={ROUTED}}}")),
        0
    );
    assert_eq!(
        get(&format!("omaha_active_reports_total{{app={VOUCHED}}}")),
        1
    );
    assert_eq!(get("omaha_active_reports_total{app=other}"), 1);
}

#[test]
fn counts_activity_only_when_asked() {
    let counters = run(false);
    assert!(
        counters
            .keys()
            .all(|k| !k.starts_with("omaha_roll_calls") && !k.starts_with("omaha_active")),
        "{counters:?}"
    );
    assert!(counters.contains_key("omaha_requests_total{protocol=v4,status=200}"));
}
