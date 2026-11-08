use http::HeaderMap;
use omaha_protocol::{App, AppId, AppResponse, Client, Protocol};
use std::future::Future;
use std::pin::Pin;

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One source's share of an update check.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Check<'a> {
    /// The wire format the request arrived in.
    pub protocol: Protocol,
    /// Request-wide details of the client, such as browser version, OS,
    /// architecture and accepted operation types.
    pub client: &'a Client,
    /// The apps routed to the source, in request order.
    pub apps: &'a [&'a App],
    /// Headers of the HTTP request, such as `User-Agent`. Empty when the
    /// request didn't come over HTTP.
    pub headers: &'a HeaderMap,
}

impl<'a> Check<'a> {
    /// Builds a check for calling a [`Source`] directly, outside an
    /// [`Endpoint`](crate::Endpoint).
    pub fn new(
        protocol: Protocol,
        client: &'a Client,
        apps: &'a [&'a App],
        headers: &'a HeaderMap,
    ) -> Self {
        Check {
            protocol,
            client,
            apps,
            headers,
        }
    }
}

/// Answers update checks for the apps routed to it.
pub trait Source: Send + Sync {
    /// Returns one answer per app, in the order of `check.apps`. An endpoint
    /// answers apps whose answer is missing or out of place with
    /// `error-internal`.
    fn check<'a>(&'a self, check: Check<'a>) -> BoxFuture<'a, Vec<AppResponse>>;

    /// Whether metrics may use `appid` as a label. Only vouch for a bounded
    /// set of apps, such as the ones this source publishes, since a label
    /// per client-sent ID would let clients grow the metrics without bound.
    /// Apps that are routed explicitly are always labelled.
    fn labels_app(&self, appid: &AppId) -> bool {
        let _ = appid;
        false
    }
}

/// Receives ping-backs, for example to count installs and failures.
pub trait PingSink: Send + Sync {
    /// Called for each ping-back app before the response is sent, so it
    /// shouldn't block. `client` holds the request-wide details.
    fn record(&self, client: &Client, app: &App);
}
