//! Packing, planning releases and publishing to an in-memory store.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::{ObjectStoreExt, PutPayload};
use omaha_diff::Differ;
use omaha_protocol::{App, AppId, Client, Outcome, Protocol, UpdateCheck};
use omaha_publish::archive::{self, Compression, PathError};
use omaha_publish::release::{self, Candidate, Options, Policy, ReleaseError};
use omaha_publish::{Store, StoreError};
use omaha_server::index::aws_lc::{EcdsaKey, EcdsaSigner};
use omaha_server::index::{Index, Signer};
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NOW: u64 = 1_800_000_000;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW)
}

fn crx(signer: &crx3::aws_lc::EcdsaSigner, version: &str, data: &[u8]) -> Vec<u8> {
    let manifest = format!(r#"{{"name":"test","version":"{version}"}}"#);
    let zip = archive::archive(
        [("manifest.json", manifest.as_bytes()), ("data", data)],
        Compression::Stored,
    )
    .unwrap();
    crx3::Builder::new().signer(signer).build(&zip).unwrap()
}

#[test]
fn archives_are_deterministic() {
    let a = archive::archive(
        [("b/c.txt", &b"two"[..]), ("a.txt", b"one"), ("Z", b"")],
        Compression::Deflated,
    )
    .unwrap();
    let b = archive::archive(
        [("Z", &b""[..]), ("a.txt", b"one"), ("b/c.txt", b"two")],
        Compression::Deflated,
    )
    .unwrap();
    assert_eq!(a, b);

    let mut zip = zip::ZipArchive::new(Cursor::new(&a)).unwrap();
    let names: Vec<String> = zip.file_names().map(|n| n.unwrap().into_owned()).collect();
    assert_eq!(names, ["Z", "a.txt", "b/c.txt"]);

    let mut entry = zip.by_name("b/c.txt").unwrap();
    assert_eq!(entry.last_modified(), Some(zip::DateTime::default()));
    assert_eq!(entry.unix_mode(), Some(0o100644));
    let mut text = String::new();
    entry.read_to_string(&mut text).unwrap();
    assert_eq!(text, "two");

    assert!(matches!(
        archive::archive([("../x", &b""[..])], Compression::Stored),
        Err(archive::ArchiveError::Path(PathError::Unsafe(_)))
    ));
}

#[test]
fn reads_directories() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("_locales/en")).unwrap();
    std::fs::write(dir.path().join("manifest.json"), "{}").unwrap();
    std::fs::write(dir.path().join("_locales/en/messages.json"), "[]").unwrap();
    let files = archive::read_dir(dir.path()).unwrap();
    let names: Vec<_> = files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(names, ["_locales/en/messages.json", "manifest.json"]);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("link")).unwrap();
        assert!(archive::read_dir(dir.path()).is_err());
    }
}

#[test]
fn reads_candidates() {
    let signer = crx3::aws_lc::EcdsaSigner::generate().unwrap();
    let candidate = Candidate::new(crx(&signer, "1.2.3", b"x")).unwrap();
    assert_eq!(candidate.version.to_string(), "1.2.3");
    assert_eq!(
        candidate.appid.as_str(),
        crx3::verify(&candidate.crx, &crx3::Policy::default())
            .unwrap()
            .id
    );

    let zip = archive::archive([("data", &b"x"[..])], Compression::Stored).unwrap();
    let no_manifest = crx3::Builder::new().signer(&signer).build(&zip).unwrap();
    assert!(matches!(
        Candidate::new(no_manifest),
        Err(ReleaseError::Manifest(_))
    ));
    assert!(matches!(
        Candidate::new(b"not a crx".to_vec()),
        Err(ReleaseError::Crx(_))
    ));
}

/// A stand-in for puffin: a tiny patch, and "applying" it copies the
/// target the real tool would have produced.
#[cfg(unix)]
fn fake_puffin(dir: &std::path::Path) -> Differ {
    use std::os::unix::fs::PermissionsExt;

    let tool = dir.join("puffin");
    std::fs::write(
        &tool,
        "#!/bin/sh\ncase \"$1\" in\n-puffdiff) printf patch > \"$4\" ;;\n-puffpatch) /bin/cp \"${3%/*}/new.crx3\" \"$3\" ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    Differ::puffin(tool)
}

fn update_check(index: &Index, appid: &AppId, version: &str) -> Outcome {
    let mut app = App::new(appid.clone());
    app.version = Some(version.parse().unwrap());
    app.updatecheck = Some(UpdateCheck::default());
    let client = Client {
        acceptformat: vec!["download".into(), "crx3".into(), "puff".into()],
        ..Client::default()
    };
    let bases = ["https://dl.example/".to_owned()];
    index
        .answer(Protocol::V4, &client, &app, &bases)
        .updatecheck
        .unwrap()
        .outcome
}

#[cfg(unix)]
#[test]
fn plans_releases() {
    let tools = tempfile::tempdir().unwrap();
    let differs = [fake_puffin(tools.path())];
    let signer = crx3::aws_lc::EcdsaSigner::generate().unwrap();
    let policy = Policy {
        keep: 2,
        ..Policy::default()
    };
    let data = vec![42u8; 10_000];

    let first = Candidate::new(crx(&signer, "1", &data)).unwrap();
    let appid = first.appid.clone();
    let plan = release::add(
        None,
        first,
        Options::default(),
        &[],
        &differs,
        &policy,
        now(),
    )
    .unwrap();
    assert_eq!(plan.index.serial, 1);
    assert_eq!(plan.index.expires, NOW + 14 * 86400);
    assert_eq!(plan.uploads.len(), 1);
    assert!(plan.uploads[0].path.starts_with(&format!("{appid}/")));
    let v1 = plan.index;

    let second = Candidate::new(crx(&signer, "2", &data)).unwrap();
    let sources: Vec<_> = release::patch_sources(Some(&v1), &second, &policy)
        .into_iter()
        .map(|file| {
            let bytes = plan.uploads[0].bytes.clone();
            (file, bytes)
        })
        .collect();
    assert_eq!(sources.len(), 1);
    let plan2 = release::add(
        Some(&v1),
        second,
        Options::default(),
        &sources,
        &differs,
        &policy,
        now(),
    )
    .unwrap();
    assert_eq!(plan2.index.serial, 2);
    assert_eq!(plan2.uploads.len(), 2);
    let releases = &plan2.index.apps[&appid];
    assert_eq!(releases[0].version.to_string(), "2");
    assert_eq!(releases[0].patches.len(), 1);
    assert_eq!(releases[0].patches[0].from, v1.apps[&appid][0].crx.sha256);

    let Outcome::Update { pipelines, .. } = update_check(&plan2.index, &appid, "1") else {
        panic!()
    };
    assert_eq!(
        pipelines.len(),
        1,
        "no cached CRX, so only the full pipeline"
    );

    let third = Candidate::new(crx(&signer, "3", &data)).unwrap();
    let plan3 = release::add(
        Some(&plan2.index),
        third,
        Options::default(),
        &[],
        &[],
        &policy,
        now(),
    )
    .unwrap();
    let versions: Vec<_> = plan3.index.apps[&appid]
        .iter()
        .map(|r| r.version.to_string())
        .collect();
    assert_eq!(versions, ["3", "2"]);

    let again = Candidate::new(crx(&signer, "3", b"other")).unwrap();
    assert!(matches!(
        release::add(
            Some(&plan3.index),
            again,
            Options::default(),
            &[],
            &[],
            &policy,
            now()
        ),
        Err(ReleaseError::VersionExists(_))
    ));

    let wrong_source = vec![(v1.apps[&appid][0].crx.clone(), b"tampered".to_vec())];
    let fourth = Candidate::new(crx(&signer, "4", &data)).unwrap();
    assert!(matches!(
        release::add(
            Some(&plan3.index),
            fourth,
            Options::default(),
            &wrong_source,
            &differs,
            &policy,
            now()
        ),
        Err(ReleaseError::SourceMismatch(_))
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn publishes_to_a_store() {
    let tools = tempfile::tempdir().unwrap();
    let differs = [fake_puffin(tools.path())];
    let memory = Arc::new(InMemory::new());
    let store = Store::new(memory.clone(), "feed/index.json").unwrap();
    let index_key = EcdsaSigner::generate().unwrap();
    let trusted = EcdsaKey::from_spki(index_key.public_key()).unwrap();
    let crx_key = crx3::aws_lc::EcdsaSigner::generate().unwrap();
    let policy = Policy::default();
    let data = vec![7u8; 10_000];

    let plan = store
        .publish(
            crx(&crx_key, "1", &data),
            Options::default(),
            &[&index_key],
            &[&trusted],
            &differs,
            &policy,
            now(),
        )
        .await
        .unwrap();
    let appid = plan.index.apps.keys().next().unwrap().clone();
    let plan = store
        .publish(
            crx(&crx_key, "2", &data),
            Options::default(),
            &[&index_key],
            &[&trusted],
            &differs,
            &policy,
            now(),
        )
        .await
        .unwrap();
    assert_eq!(plan.index.serial, 2);

    let signed = memory
        .get(&Path::from("feed/index.json"))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let served = Index::open(&signed, &[&trusted], now()).unwrap();
    assert_eq!(served, plan.index);

    for release in &served.apps[&appid] {
        let path = Path::parse(&release.crx.path).unwrap();
        let bytes = memory.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(bytes.len() as u64, release.crx.size);

        for patch in &release.patches {
            assert!(
                memory
                    .head(&Path::parse(&patch.file.path).unwrap())
                    .await
                    .is_ok()
            );
        }
    }

    let later = now() + Duration::from_secs(30 * 86400);
    let refreshed = store
        .refresh(&[&index_key], &[&trusted], &policy, later)
        .await
        .unwrap();
    assert_eq!(refreshed.serial, 3);
    assert!(refreshed.expires > NOW + 30 * 86400);

    let stale = store.current(&[&trusted]).await.unwrap().unwrap();
    store
        .write_index(&refreshed, &[&index_key], Some(&stale))
        .await
        .unwrap();
    assert!(matches!(
        store
            .write_index(&refreshed, &[&index_key], Some(&stale))
            .await,
        Err(StoreError::Raced)
    ));

    let crx_path = Path::parse(&plan.uploads[0].path).unwrap();
    memory
        .put(&crx_path, PutPayload::from(b"replaced".to_vec()))
        .await
        .unwrap();
    assert!(matches!(
        store.upload(&plan.uploads[0]).await,
        Err(StoreError::Conflict(_))
    ));

    let stranger = EcdsaSigner::generate().unwrap();
    let stranger_key = EcdsaKey::from_spki(stranger.public_key()).unwrap();
    assert!(matches!(
        store.current(&[&stranger_key]).await,
        Err(StoreError::Index(_))
    ));
}
