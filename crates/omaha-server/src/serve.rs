use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use std::error::Error;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Limits for [`serve`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServeOptions {
    /// Connections served at once; more wait to be accepted. Default: 512.
    pub max_connections: usize,
    /// How long a client may take to send a request's headers. Default: 10
    /// seconds.
    pub header_timeout: Duration,
    /// How long a connection may stay open at all; `None`, the default,
    /// leaves it unlimited, as downloads of large files need.
    pub connection_timeout: Option<Duration>,
    /// How long open connections get to finish after shutdown. Default: 10
    /// seconds.
    pub drain_timeout: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        ServeOptions {
            max_connections: 512,
            header_timeout: Duration::from_secs(10),
            connection_timeout: None,
            drain_timeout: Duration::from_secs(10),
        }
    }
}

impl ServeOptions {
    /// Sets [`max_connections`](Self::max_connections).
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Sets [`header_timeout`](Self::header_timeout).
    pub fn header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;
        self
    }

    /// Sets [`connection_timeout`](Self::connection_timeout).
    pub fn connection_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Sets [`drain_timeout`](Self::drain_timeout).
    pub fn drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }
}

/// Serves HTTP/1.1 on `listener` with `service` until `shutdown` completes,
/// then stops accepting and gives open connections
/// [`drain_timeout`](ServeOptions::drain_timeout) to finish.
///
/// An [`Endpoint`](crate::Endpoint) is served through
/// `hyper_util::service::TowerToHyperService`; a handler function through
/// `hyper::service::service_fn`.
pub async fn serve<S, B>(
    listener: TcpListener,
    service: S,
    options: ServeOptions,
    shutdown: impl Future<Output = ()>,
) where
    S: hyper::service::Service<http::Request<Incoming>, Response = http::Response<B>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let slots = Arc::new(Semaphore::new(options.max_connections.max(1)));
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            permit = slots.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
            _ = &mut shutdown => break,
        };
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = &mut shutdown => break,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(e) => {
                eprintln!("accept: {e}");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let connection = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(options.header_timeout)
            .serve_connection(TokioIo::new(stream), service.clone());
        let connection = graceful.watch(connection);
        let limit = options.connection_timeout;
        tokio::spawn(async move {
            match limit {
                Some(limit) => {
                    let _ = tokio::time::timeout(limit, connection).await;
                }
                None => {
                    let _ = connection.await;
                }
            }

            drop(permit);
        });
    }

    let _ = tokio::time::timeout(options.drain_timeout, graceful.shutdown()).await;
}
