//! The `omaha-publish` binary's `pack`, `verify` and `id` commands.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_omaha-publish"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn packs_verifies_and_identifies() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("crx.pem");
    let der = crx3::aws_lc::RsaSigner::generate()
        .unwrap()
        .to_pkcs8()
        .unwrap();
    std::fs::write(
        &key,
        pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, &der).unwrap(),
    )
    .unwrap();
    let files = dir.path().join("files");
    std::fs::create_dir(&files).unwrap();
    std::fs::write(files.join("crl-set"), b"revocations").unwrap();
    std::fs::write(files.join("manifest.json"), br#"{"version":"1"}"#).unwrap();
    let crx = dir.path().join("out.crx3");

    let packed = stdout(&run(&[
        "pack",
        "--key",
        path(&key),
        "--stored",
        path(&files),
        path(&crx),
    ]));
    let id = packed.split_whitespace().next().unwrap();

    let ids = stdout(&run(&["id", path(&key)]));
    assert!(ids.contains(&format!("app ID: {id}")), "{ids}");
    let hash = ids
        .lines()
        .find_map(|l| l.strip_prefix("key SHA-256: "))
        .unwrap()
        .to_owned();

    let verified = stdout(&run(&[
        "verify",
        "--key-hash",
        &hash,
        "--files",
        path(&files),
        "--stored",
        path(&crx),
    ]));
    assert_eq!(verified.trim(), format!("{id} ok, archive matches"));

    let deflated = run(&["verify", "--files", path(&files), path(&crx)]);
    assert!(!deflated.status.success());

    let other = "00".repeat(32);
    assert!(
        !run(&["verify", "--key-hash", &other, path(&crx)])
            .status
            .success()
    );

    std::fs::write(files.join("crl-set"), b"changed").unwrap();
    let changed = run(&["verify", "--files", path(&files), "--stored", path(&crx)]);
    assert!(String::from_utf8_lossy(&changed.stderr).contains("archive differs"));
}
