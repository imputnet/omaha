//! Runs a real Chromium-based browser against `omaha-server`: force-installs
//! a test extension from a feed built with `omaha-publish`, then publishes
//! a new version and checks the browser updates to it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use object_store::local::LocalFileSystem;
use omaha_publish::Store;
use omaha_publish::archive::{self, Compression};
use omaha_publish::release::{Options, Policy};
use omaha_server::index::Signer;
use omaha_server::index::aws_lc::{EcdsaKey, EcdsaSigner};
use omaha_server::{Endpoint, StaticIndex};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};

#[derive(Parser)]
struct Args {
    /// The browser binary.
    #[arg(long)]
    browser: PathBuf,
    /// The browser's managed policy directory, which must be writable,
    /// e.g. /etc/opt/chrome_for_testing/policies/managed.
    #[arg(long)]
    policy_dir: PathBuf,
    #[arg(long, value_enum, default_values_t = [Protocol::Update2, Protocol::Omaha4])]
    protocol: Vec<Protocol>,
    /// Seconds to wait for each install.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// Keep the working directory and print where it is.
    #[arg(long)]
    keep: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Protocol {
    /// An extension with its own update URL, which Chromium checks with
    /// update2 GET requests.
    Update2,
    /// An extension installed from its own update URL, whose manifest
    /// names the (overridden) Web Store update URL, so Chromium checks it
    /// with Omaha 4 through update_client. Installing it from the Web Store
    /// URL would need Google's publisher proof.
    Omaha4,
}

struct Server {
    endpoint: Endpoint,
    files: PathBuf,
    log: Mutex<Vec<String>>,
}

impl Server {
    fn record(&self, line: String) {
        println!("  server: {line}");
        self.log.lock().unwrap().push(line);
    }

    async fn handle(&self, request: http::Request<Incoming>) -> http::Response<Full<Bytes>> {
        let (parts, body) = request.into_parts();
        let body = body
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let path = parts.uri.path().to_owned();
        let query: Vec<String> = form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes())
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let mut line = format!("{} {path} {}", parts.method, query.join(" "));

        if !body.is_empty() {
            line.push(' ');
            line.push_str(&String::from_utf8_lossy(&body));
        }

        let response = if let Some(file) = path.strip_prefix("/files/") {
            self.file(file)
        } else if path == "/update2" || path.starts_with("/service/update2/") {
            let request = http::Request::from_parts(parts, body);
            self.endpoint.handle(request).await.map(Full::new)
        } else {
            status(404)
        };

        self.record(format!("{line} -> {}", response.status().as_u16()));
        response
    }

    fn file(&self, path: &str) -> http::Response<Full<Bytes>> {
        if path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        {
            return status(400);
        }

        match std::fs::read(self.files.join(path)) {
            Ok(bytes) => http::Response::builder()
                .header("content-type", "application/x-chrome-extension")
                .body(Full::new(Bytes::from(bytes)))
                .unwrap(),
            Err(_) => status(404),
        }
    }
}

fn status(code: u16) -> http::Response<Full<Bytes>> {
    http::Response::builder()
        .status(code)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn extension(key: &crx3::aws_lc::EcdsaSigner, version: &str, update_url: &str) -> Vec<u8> {
    let manifest = format!(
        r#"{{"manifest_version":3,"name":"omaha conformance","version":"{version}","update_url":"{update_url}"}}"#
    );
    let mut data = noise(200_000, 7);
    data[1000..1000 + version.len()].copy_from_slice(version.as_bytes());
    let zip = archive::archive(
        [("manifest.json", manifest.as_bytes()), ("data.bin", &data)],
        Compression::Deflated,
    )
    .unwrap();
    crx3::Builder::new().signer(key).build(&zip).unwrap()
}

struct Browser {
    child: Child,
}

impl Browser {
    fn launch(args: &Args, profile: &Path, extra: &[String], log: &Path) -> Browser {
        let log = std::fs::File::create(log).unwrap();
        let child = Command::new(&args.browser)
            .args([
                "--headless=new",
                "--no-sandbox",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-gpu",
                "--password-store=basic",
                "--enable-logging=stderr",
                "--vmodule=extension_downloader=2,extension_updater=2,update_service=2,extension_installer=2,crx_installer=2,*/update_client/*=2,*/crx_file/*=2",
            ])
            .arg(format!("--user-data-dir={}", profile.display()))
            .args(extra)
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Browser { child }
    }

    async fn stop(mut self) {
        if let Some(pid) = self.child.id() {
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status()
                .await;
        }

        if tokio::time::timeout(Duration::from_secs(30), self.child.wait())
            .await
            .is_err()
        {
            println!("  browser didn't exit after SIGTERM, killing it");
            let _ = self.child.kill().await;
        }
    }
}

async fn wait_for(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();

    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    false
}

async fn scenario(args: &Args, protocol: Protocol) -> Result<(), String> {
    println!("== {protocol:?}");
    let dir = tempfile::tempdir().unwrap();
    let feed = dir.path().join("feed");
    let profile = dir.path().join("profile");
    std::fs::create_dir_all(&feed).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());

    let index_key = EcdsaSigner::generate().unwrap();
    let trusted = EcdsaKey::from_spki(index_key.public_key()).unwrap();
    let source = StaticIndex::builder([format!("{base}/files/")])
        .trust(EcdsaKey::from_spki(index_key.public_key()).unwrap())
        .build();
    let server = Arc::new(Server {
        endpoint: Endpoint::builder()
            .fallback(source.clone())
            .server_name("omaha conformance")
            .build(),
        files: feed.clone(),
        log: Mutex::new(Vec::new()),
    });

    let accept = server.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let server = accept.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let server = server.clone();
                    async move { Ok::<_, Infallible>(server.handle(request).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let store = Store::new(
        Arc::new(LocalFileSystem::new_with_prefix(&feed).unwrap()),
        "index.json",
    )
    .unwrap();
    let install_url = format!("{base}/update2");
    let (update_url, extra) = match protocol {
        Protocol::Update2 => (install_url.clone(), vec![]),
        Protocol::Omaha4 => {
            let url = format!("{base}/service/update2/crx");
            (
                url.clone(),
                vec![format!("--apps-gallery-update-url={url}")],
            )
        }
    };
    let crx_key = crx3::aws_lc::EcdsaSigner::generate().unwrap();
    let publish = |version: &'static str| {
        let update_url = &update_url;
        let store = &store;
        let index_key = &index_key;
        let trusted = &trusted;
        let crx_key = &crx_key;
        let source = &source;
        let feed = &feed;
        async move {
            let plan = store
                .publish(
                    extension(crx_key, version, update_url),
                    Options::default(),
                    &[index_key],
                    &[trusted],
                    &[],
                    &Policy::default(),
                    SystemTime::now(),
                )
                .await
                .unwrap();
            source
                .replace(&std::fs::read(feed.join("index.json")).unwrap())
                .unwrap();
            plan
        }
    };

    let plan = publish("1.0").await;
    let id = plan.index.apps.keys().next().unwrap().to_string();
    println!("  extension {id}");

    let policy = args.policy_dir.join("omaha-conformance.json");
    std::fs::write(
        &policy,
        format!(r#"{{"ExtensionInstallForcelist":["{id};{install_url}"]}}"#),
    )
    .map_err(|e| format!("{}: {e}", policy.display()))?;

    let installed = |version: &str| profile.join(format!("Default/Extensions/{id}/{version}_0"));
    let timeout = Duration::from_secs(args.timeout);

    let browser = Browser::launch(args, &profile, &extra, &dir.path().join("browser-1.log"));
    let got_v1 = wait_for(&installed("1.0"), timeout).await;
    browser.stop().await;

    if !got_v1 {
        return finish(
            args,
            dir,
            &server,
            &policy,
            Err("the browser didn't install 1.0".into()),
        );
    }

    let plan = publish("2.0").await;

    for upload in &plan.uploads {
        println!("  published {} ({} bytes)", upload.path, upload.bytes.len());
    }

    server.record("--- restart ---".into());
    let browser = Browser::launch(args, &profile, &extra, &dir.path().join("browser-2.log"));
    let updated = wait_for(&installed("2.0"), timeout).await;
    browser.stop().await;

    let after: Vec<String> = server
        .log
        .lock()
        .unwrap()
        .iter()
        .skip_while(|l| !l.starts_with("--- restart"))
        .cloned()
        .collect();
    let checked = after.iter().any(|l| match protocol {
        Protocol::Update2 => l.starts_with("GET /update2") && l.contains("v=1.0"),
        Protocol::Omaha4 => {
            l.starts_with("POST /service/update2/json") && l.contains(r#""version":"1.0""#)
        }
    });
    let crx = format!("GET /files/{} ", plan.uploads[0].path);
    let downloaded = after
        .iter()
        .any(|l| l.starts_with(&crx) && l.ends_with("200"));

    let result = if !checked {
        Err("no update check from the installed 1.0".into())
    } else if !downloaded {
        Err("the browser didn't download 2.0".into())
    } else if !updated {
        Err("the browser didn't update to 2.0".into())
    } else {
        println!("  updated to 2.0");
        Ok(())
    };

    finish(args, dir, &server, &policy, result)
}

fn finish(
    args: &Args,
    dir: tempfile::TempDir,
    server: &Server,
    policy: &Path,
    result: Result<(), String>,
) -> Result<(), String> {
    let _ = std::fs::remove_file(policy);
    let log = server.log.lock().unwrap().join("\n");
    std::fs::write(dir.path().join("server.log"), log).unwrap();

    if result.is_err() || args.keep {
        println!("  kept {}", dir.keep().display());
    }

    result
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let mut failed = false;

    for protocol in &args.protocol {
        match scenario(&args, *protocol).await {
            Ok(()) => println!("== {protocol:?}: ok"),
            Err(e) => {
                println!("== {protocol:?}: FAILED: {e}");
                failed = true;
            }
        }
    }

    if failed {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
