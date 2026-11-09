//! `serve` with a slow handler: connection limits and shutdown.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use omaha_server::{ServeOptions, serve};
use std::convert::Infallible;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

async fn start(
    options: ServeOptions,
) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let service = service_fn(|request: http::Request<hyper::body::Incoming>| async move {
        if request.uri().path() == "/slow" {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(b"done"))))
    });
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, service, options, async {
        let _ = stopped.await;
    }));
    (addr, stop, server)
}

async fn get(stream: &mut TcpStream, path: &str) -> String {
    let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn lets_requests_finish_after_shutdown() {
    let (addr, stop, server) = start(ServeOptions::default()).await;
    let mut stream = TcpStream::connect(&addr).await.unwrap();
    let slow = tokio::spawn(async move { get(&mut stream, "/slow").await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.send(()).unwrap();

    assert!(slow.await.unwrap().ends_with("done"));
    server.await.unwrap();
    assert!(
        TcpStream::connect(&addr).await.is_err(),
        "stopped accepting"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn waits_for_a_free_slot() {
    let (addr, _stop, _server) = start(ServeOptions::default().max_connections(1)).await;
    let mut first = TcpStream::connect(&addr).await.unwrap();
    let slow = tokio::spawn(async move { get(&mut first, "/slow").await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut second = TcpStream::connect(&addr).await.unwrap();
    let started = tokio::time::Instant::now();
    assert!(get(&mut second, "/").await.ends_with("done"));
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "served only once the first closed"
    );
    assert!(slow.await.unwrap().ends_with("done"));
}
