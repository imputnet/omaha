use omaha_protocol::{App, AppResponse, Client};
use std::future::Future;
use std::pin::Pin;

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Answers update checks for the apps routed to it.
pub trait Source: Send + Sync {
    /// Returns one answer per app, in the order of `apps`. An endpoint
    /// answers apps whose answer is missing or out of place with
    /// `error-internal`.
    fn check<'a>(
        &'a self,
        client: &'a Client,
        apps: &'a [&'a App],
    ) -> BoxFuture<'a, Vec<AppResponse>>;
}

/// Receives ping-backs, for example to count installs and failures.
pub trait PingSink: Send + Sync {
    fn record(&self, client: &Client, app: &App);
}
