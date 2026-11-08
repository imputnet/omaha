//! Patches made and applied with the real `puffin` and `zucchini`, taken
//! from `OMAHA_PUFFIN` and `OMAHA_ZUCCHINI`, and failures with fake tools.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crx3::aws_lc::EcdsaSigner;
use omaha_diff::{DiffError, Differ};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

fn crx(signer: &EcdsaSigner, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));

    for (name, data) in files {
        zip.start_file(*name, SimpleFileOptions::default()).unwrap();
        zip.write_all(data).unwrap();
    }

    let archive = zip.finish().unwrap().into_inner();
    crx3::Builder::new().signer(signer).build(&archive).unwrap()
}

fn tool(var: &str) -> Option<String> {
    let path = std::env::var(var).ok();

    if path.is_none() {
        eprintln!("{var} not set, skipping");
    }

    path
}

fn check(differ: &Differ) {
    let signer = EcdsaSigner::generate().unwrap();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let text: Vec<u8> = (0..200_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect();
    let mut changed = text.clone();
    changed[1000..1100].fill(7);
    let old = crx(
        &signer,
        &[("manifest.json", b"{\"version\":\"1\"}"), ("data", &text)],
    );
    let new = crx(
        &signer,
        &[
            ("manifest.json", b"{\"version\":\"2\"}"),
            ("data", &changed),
        ],
    );

    let patch = differ.diff(&old, &new).unwrap();
    assert!(
        patch.len() < new.len() / 4,
        "{} of {}",
        patch.len(),
        new.len()
    );
}

#[test]
fn puffin_patches_round_trip() {
    if let Some(path) = tool("OMAHA_PUFFIN") {
        check(&Differ::puffin(path));
    }
}

#[test]
fn zucchini_patches_round_trip() {
    if let Some(path) = tool("OMAHA_ZUCCHINI") {
        check(&Differ::zucchini(path));
    }
}

#[test]
fn reports_tool_failures() {
    let differ = Differ::puffin("false");
    assert!(matches!(
        differ.diff(b"a", b"b"),
        Err(DiffError::Failed { step: "make", .. })
    ));
}

#[cfg(unix)]
#[test]
fn rejects_patches_that_do_not_reproduce_the_target() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("puffin");
    std::fs::write(
        &tool,
        "#!/bin/sh\ncase \"$1\" in\n-puffdiff) printf p > \"$4\" ;;\n-puffpatch) printf wrong > \"$3\" ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(matches!(
        Differ::puffin(&tool).diff(b"old", b"new"),
        Err(DiffError::Mismatch)
    ));
}

#[cfg(unix)]
#[test]
fn kills_tools_that_run_too_long() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("puffin");
    std::fs::write(&tool, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

    let started = std::time::Instant::now();
    let result = Differ::puffin(&tool)
        .timeout(std::time::Duration::from_millis(200))
        .diff(b"old", b"new");
    assert!(
        matches!(result, Err(DiffError::TimedOut { step: "make" })),
        "{result:?}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
