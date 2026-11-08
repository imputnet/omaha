use crate::router::Router;
use crate::source::{BoxFuture, PingSink, Source};
use bytes::Bytes;
use futures_util::future::join_all;
use http::header::{CONTENT_TYPE, ETAG, LOCATION};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use omaha_protocol::update2::{self, ResponseMode};
use omaha_protocol::{
    App, AppId, AppResponse, AppStatus, DayStart, DecodeError, Limits, Outcome, Request, Response,
    UpdateCheckError, UpdateCheckResponse, v4,
};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CUP_PROOF: HeaderName = HeaderName::from_static("x-cup-server-proof");
const RETRY_AFTER: HeaderName = HeaderName::from_static("x-retry-after");
const APP_IDS: HeaderName = HeaderName::from_static("x-goog-update-appid");
const MAX_RETRY_AFTER_SECS: u64 = 86400;
const EPOCH_2007: u64 = 1_167_609_600;

/// An update server endpoint. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<Inner>,
}

type RetryAfter = dyn Fn() -> Option<Duration> + Send + Sync;

struct Inner {
    router: Router<usize>,
    sources: Vec<Box<dyn Source>>,
    cup: Option<cup2::Server>,
    cup_etag: bool,
    limits: Limits,
    server: Option<String>,
    pings: Option<Box<dyn PingSink>>,
    retry_after: Option<Box<RetryAfter>>,
    clock: fn() -> SystemTime,
}

/// Configures an [`Endpoint`].
pub struct EndpointBuilder {
    inner: Inner,
}

impl Endpoint {
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder {
            inner: Inner {
                router: Router::new(),
                sources: Vec::new(),
                cup: None,
                cup_etag: false,
                limits: Limits::default(),
                server: None,
                pings: None,
                retry_after: None,
                clock: SystemTime::now,
            },
        }
    }
}

impl EndpointBuilder {
    /// Routes `appids` to `source`. A later route for the same app ID wins.
    pub fn source(
        mut self,
        appids: impl IntoIterator<Item = AppId>,
        source: impl Source + 'static,
    ) -> Self {
        let index = self.inner.sources.len();
        self.inner.sources.push(Box::new(source));
        for appid in appids {
            self.inner.router = self.inner.router.route(appid.as_str(), index);
        }
        self
    }

    /// Signs Omaha 4 responses to requests that carry `cup2key`.
    pub fn cup(mut self, server: cup2::Server) -> Self {
        self.inner.cup = Some(server);
        self
    }

    /// Also sends the CUP proof as a weak `ETag`, which Chromium falls back
    /// to when a proxy drops `X-Cup-Server-Proof`. ML-DSA proofs are about
    /// 4.9 KB, so this doubles the header size.
    pub fn cup_etag(mut self, enabled: bool) -> Self {
        self.inner.cup_etag = enabled;
        self
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.inner.limits = limits;
        self
    }

    /// The `server` value in responses.
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.inner.server = Some(name.into());
        self
    }

    pub fn pings(mut self, sink: impl PingSink + 'static) -> Self {
        self.inner.pings = Some(Box::new(sink));
        self
    }

    /// Asked on every response; a `Some` is sent as `X-Retry-After`, which
    /// tells clients to stay away for that long (at most a day).
    pub fn retry_after(mut self, f: impl Fn() -> Option<Duration> + Send + Sync + 'static) -> Self {
        self.inner.retry_after = Some(Box::new(f));
        self
    }

    /// The clock used for `daystart`.
    pub fn clock(mut self, clock: fn() -> SystemTime) -> Self {
        self.inner.clock = clock;
        self
    }

    pub fn build(self) -> Endpoint {
        Endpoint {
            inner: Arc::new(self.inner),
        }
    }
}

fn text(status: StatusCode, message: impl Into<String>) -> http::Response<Bytes> {
    let mut response = http::Response::new(Bytes::from(message.into()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn decode_error(e: &DecodeError) -> http::Response<Bytes> {
    let status = match e {
        DecodeError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        _ => StatusCode::BAD_REQUEST,
    };
    text(status, e.to_string())
}

fn query_param(request: &http::Request<Bytes>, name: &str) -> Option<String> {
    let query = request.uri().query()?;
    form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

fn daystart(now: SystemTime) -> DayStart {
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = secs.saturating_sub(EPOCH_2007) / 86400;
    DayStart {
        elapsed_days: u32::try_from(days).unwrap_or(u32::MAX),
        elapsed_seconds: u32::try_from(secs % 86400).ok(),
    }
}

/// An answer for an app whose source failed to answer it properly.
fn internal_error(app: &App) -> AppResponse {
    let mut answer = AppResponse::new(app.appid.clone(), AppStatus::Ok);

    if app.updatecheck.is_some() {
        answer.updatecheck = Some(UpdateCheckResponse::new(Outcome::Error(
            UpdateCheckError::Internal,
        )));
    }

    answer
}

/// Makes an answer match what the app asked for: an update check result
/// exactly when it asked for one, and no ping-back acknowledgements.
fn fit(app: &App, mut answer: AppResponse) -> AppResponse {
    answer.events.clear();

    if answer.status != AppStatus::Ok {
        answer.updatecheck = None;
        return answer;
    }

    match (&app.updatecheck, &answer.updatecheck) {
        (Some(_), None) => return internal_error(app),
        (None, Some(_)) => answer.updatecheck = None,
        _ => {}
    }

    answer
}

impl Endpoint {
    /// Answers one request with a fully read body.
    pub async fn handle(&self, request: http::Request<Bytes>) -> http::Response<Bytes> {
        let mut response = match *request.method() {
            Method::POST => self.handle_v4(&request).await,
            Method::GET => self.handle_update2(&request).await,
            _ => {
                let mut r = text(StatusCode::METHOD_NOT_ALLOWED, "use POST or GET");
                r.headers_mut()
                    .insert(http::header::ALLOW, HeaderValue::from_static("POST, GET"));
                r
            }
        };

        if let Some(after) = self.inner.retry_after.as_ref().and_then(|f| f()) {
            let secs = after.as_secs().clamp(1, MAX_RETRY_AFTER_SECS);
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(secs));
        }

        response
    }

    async fn handle_v4(&self, request: &http::Request<Bytes>) -> http::Response<Bytes> {
        let inner = &self.inner;
        let advertised = request
            .headers()
            .get(APP_IDS)
            .and_then(|v| v.to_str().ok())
            .map_or(0, |ids| ids.split(',').count());

        if advertised > inner.limits.max_apps {
            return decode_error(&DecodeError::TooManyApps);
        }

        let body = request.body();
        let ticket = match (&inner.cup, query_param(request, "cup2key")) {
            (Some(server), Some(key)) => {
                let hreq = query_param(request, "cup2hreq");
                match server.ticket(&key, hreq.as_deref(), body) {
                    Ok(ticket) => Some((server, ticket)),
                    Err(e) => return text(StatusCode::BAD_REQUEST, e.to_string()),
                }
            }
            _ => None,
        };

        let decoded = match v4::decode_request(body, &inner.limits) {
            Ok(decoded) => decoded,
            Err(e) => return decode_error(&e),
        };

        let encoded = match v4::encode_response(&self.answer(&decoded).await) {
            Ok(encoded) => encoded,
            Err(e) => return text(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };

        let proof = match &ticket {
            Some((server, ticket)) => match server.sign(ticket, &encoded) {
                Ok(proof) => Some(proof),
                Err(e) => return text(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            },
            None => None,
        };

        let mut response = http::Response::new(Bytes::from(encoded));
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if let Some(proof) = proof {
            let header = |value: &str| HeaderValue::from_str(value);
            match (header(proof.as_str()), header(&proof.etag())) {
                (Ok(value), Ok(etag)) => {
                    headers.insert(CUP_PROOF, value);

                    if inner.cup_etag {
                        headers.insert(ETAG, etag);
                    }
                }
                _ => {
                    return text(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invalid CUP proof header",
                    );
                }
            }
        }

        response
    }

    async fn handle_update2(&self, request: &http::Request<Bytes>) -> http::Response<Bytes> {
        let query = request.uri().query().unwrap_or_default();
        let decoded = match update2::decode_query(query, &self.inner.limits) {
            Ok(decoded) => decoded,
            Err(e) => return decode_error(&e),
        };
        let answer = self.answer(&decoded.request).await;

        if decoded.mode == ResponseMode::Redirect {
            let Some(url) = update2::redirect_url(&answer) else {
                return text(StatusCode::NOT_FOUND, "no package");
            };

            return match HeaderValue::from_str(url) {
                Ok(location) => {
                    let mut response = http::Response::new(Bytes::new());
                    *response.status_mut() = StatusCode::FOUND;
                    response.headers_mut().insert(LOCATION, location);
                    response
                }
                Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "invalid package URL"),
            };
        }

        match update2::encode_xml(&answer) {
            Ok(xml) => {
                let mut response = http::Response::new(Bytes::from(xml));
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/xml; charset=utf-8"),
                );
                response
            }
            Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    }

    /// Answers every app of a request: ping-backs directly, the rest by
    /// asking their sources concurrently.
    pub async fn answer(&self, request: &Request) -> Response {
        let inner = &self.inner;
        let mut answers: Vec<Option<AppResponse>> = vec![None; request.apps.len()];
        let mut checks = Vec::new();

        for (i, app) in request.apps.iter().enumerate() {
            if app.is_pingback() {
                if let Some(sink) = &inner.pings {
                    sink.record(&request.client, app);
                }

                answers[i] = Some(AppResponse::pingback(app));
            } else {
                checks.push(i);
            }
        }

        let split = inner
            .router
            .split(checks.iter().map(|&i| request.apps[i].appid.as_str()));

        for &k in &split.unknown {
            let i = checks[k];
            answers[i] = Some(AppResponse::new(
                request.apps[i].appid.clone(),
                AppStatus::UnknownApplication,
            ));
        }

        let calls = split.routes.iter().filter_map(|route| {
            let source = inner.sources.get(route.source)?;
            let apps: Vec<&App> = route
                .apps
                .iter()
                .map(|&k| &request.apps[checks[k]])
                .collect();
            Some(async move {
                let results = source.check(&request.client, &apps).await;
                (route, results)
            })
        });

        for (route, results) in join_all(calls).await {
            let mut results = if results.len() == route.apps.len() {
                results
            } else {
                Vec::new()
            }
            .into_iter();

            for &k in &route.apps {
                let app = &request.apps[checks[k]];
                let answer = match results.next() {
                    Some(result) if result.appid == app.appid => fit(app, result),
                    _ => internal_error(app),
                };
                answers[checks[k]] = Some(answer);
            }
        }

        Response {
            apps: answers
                .into_iter()
                .zip(&request.apps)
                .map(|(answer, app)| answer.unwrap_or_else(|| internal_error(app)))
                .collect(),
            daystart: Some(daystart((inner.clock)())),
            server: inner.server.clone(),
        }
    }
}

impl<B> tower_service::Service<http::Request<B>> for Endpoint
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = http::Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let endpoint = self.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let limit = endpoint.inner.limits.max_body_len;
            let response = match Limited::new(body, limit).collect().await {
                Ok(collected) => {
                    let request = http::Request::from_parts(parts, collected.to_bytes());
                    endpoint.handle(request).await
                }
                Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
                    decode_error(&DecodeError::TooLarge)
                }
                Err(_) => text(StatusCode::BAD_REQUEST, "unreadable request body"),
            };
            Ok(response.map(Full::new))
        })
    }
}
