//! The `omaha-server serve` binary against a feed on the local filesystem.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use omaha_protocol::*;
use omaha_server::index::aws_lc::EcdsaSigner;
use omaha_server::index::{File, Index, Release, Signer};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const APP: &str = "hfnkpimlhhgieaddgfemjhofmfblmnib";

fn pem(label: &str, der: &[u8]) -> String {
    pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, der).unwrap()
}

fn write_index(dir: &Path, key: &EcdsaSigner, serial: u64, version: &str) {
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let mut index = Index::new(serial, expires);
    let crx = File {
        path: format!("{APP}/{version}.crx3"),
        sha256: Sha256::from_bytes([7; 32]),
        size: 100,
    };
    index.apps.insert(
        AppId::new(APP).unwrap(),
        vec![Release::new(version.parse().unwrap(), crx)],
    );
    let tmp = dir.join("index.json.tmp");
    std::fs::write(&tmp, index.sign(&[key]).unwrap()).unwrap();
    std::fs::rename(tmp, dir.join("index.json")).unwrap();
}

struct Server {
    child: Child,
    addr: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(args: &[String]) -> Server {
    let mut child = Command::new(env!("CARGO_BIN_EXE_omaha-server"))
        .arg("serve")
        .args(["--listen", "127.0.0.1:0", "--reload", "1"])
        .args(args)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut lines = BufReader::new(stderr).lines();
    let addr = loop {
        let line = lines.next().expect("server exited").unwrap();

        if let Some(addr) = line.strip_prefix("listening on ") {
            break addr.to_owned();
        }
    };
    std::thread::spawn(move || lines.for_each(drop));
    Server { child, addr }
}

fn post(addr: &str, path: &str, body: &[u8]) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    (head, response[split + 4..].to_vec())
}

fn check_request() -> Vec<u8> {
    let mut app = App::new(AppId::new(APP).unwrap());
    app.version = Some("1".parse().unwrap());
    app.updatecheck = Some(UpdateCheck::default());
    let request = Request {
        protocol: Protocol::V4,
        client: Client {
            acceptformat: vec!["download".into(), "crx3".into()],
            ..Client::default()
        },
        apps: vec![app],
    };
    v4::encode_request(&request, None).unwrap()
}

fn offered(body: &[u8]) -> (String, Vec<String>) {
    let response = v4::decode_response(body).unwrap().response;

    match &response.apps[0].updatecheck.as_ref().unwrap().outcome {
        Outcome::Update {
            nextversion,
            pipelines,
        } => (
            nextversion.to_string(),
            pipelines[0].full_crx().unwrap().0.to_vec(),
        ),
        other => panic!("no update: {other:?}"),
    }
}

#[test]
fn serves_and_reloads_a_feed() {
    let dir = tempfile::tempdir().unwrap();
    let key = EcdsaSigner::generate().unwrap();
    let trust = dir.path().join("index.pub");
    std::fs::write(&trust, pem("PUBLIC KEY", key.public_key())).unwrap();
    write_index(dir.path(), &key, 1, "2");

    let server = start(&[
        format!("--index=file://{}/index.json", dir.path().display()),
        format!("--trust={}", trust.display()),
        "--base=https://dl.example/feed/".into(),
        "--base=https://mirror.example/".into(),
    ]);

    let (head, body) = post(&server.addr, "/service/update2/json", &check_request());
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (version, urls) = offered(&body);
    assert_eq!(version, "2");
    assert_eq!(
        urls,
        [
            format!("https://dl.example/feed/{APP}/2.crx3"),
            format!("https://mirror.example/{APP}/2.crx3")
        ]
    );

    write_index(dir.path(), &key, 2, "3");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);

    loop {
        let (_, body) = post(&server.addr, "/", &check_request());

        if offered(&body).0 == "3" {
            break;
        }

        assert!(std::time::Instant::now() < deadline, "index not reloaded");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn signs_with_cup_keys() {
    let dir = tempfile::tempdir().unwrap();
    let key = EcdsaSigner::generate().unwrap();
    let trust = dir.path().join("index.pub");
    std::fs::write(&trust, pem("PUBLIC KEY", key.public_key())).unwrap();
    write_index(dir.path(), &key, 1, "2");

    let cup = cup2::aws_lc::MlDsa44Signer::generate(16).unwrap();
    let cup_pem = dir.path().join("cup.pem");
    std::fs::write(&cup_pem, pem("PRIVATE KEY", &cup.to_pkcs8().unwrap())).unwrap();
    let server = start(&[
        format!("--index=file://{}/index.json", dir.path().display()),
        format!("--trust={}", trust.display()),
        "--base=https://dl.example/".into(),
        format!("--cup-key=16={}", cup_pem.display()),
    ]);

    let client = cup2::Client::new(cup2::KeyId::MlDsa44(16), cup.public_key()).unwrap();
    let body = check_request();
    let prepared = client.prepare(&body).unwrap();
    let path = format!("/service/update2/json?{}", prepared.query());
    let (head, response) = post(&server.addr, &path, &body);
    let proof = head
        .lines()
        .find_map(|l| l.strip_prefix("x-cup-server-proof: "))
        .expect("a CUP proof header");
    client.verify(&prepared, &response, proof).unwrap();
}

#[test]
fn needs_a_base_for_non_http_indexes() {
    let output = Command::new(env!("CARGO_BIN_EXE_omaha-server"))
        .args([
            "serve",
            "--index=file:///nonexistent/index.json",
            "--trust=/nonexistent.pem",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--base is required"));
}
