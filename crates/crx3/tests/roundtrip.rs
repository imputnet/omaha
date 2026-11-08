//! CRX files built and signed with this crate's own signers, checked with
//! its verifier: IDs, appended proofs, policies and tampering.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "aws-lc")]

use crx3::aws_lc::{EcdsaSigner, RsaSigner};
use crx3::{
    Builder, Policy, Signer, VerifyError, append_proof, id_from_public_key, key_hash, verify,
};

const ARCHIVE: &[u8] = b"PK\x03\x04 not really a zip, but proofs don't care";

#[test]
fn rsa_developer_key() {
    let dev = RsaSigner::generate().unwrap();
    let crx = Builder::new().signer(&dev).build(ARCHIVE).unwrap();
    let v = verify(&crx, &Policy::default()).unwrap();
    assert_eq!(v.id, id_from_public_key(dev.public_key()));
    assert_eq!(v.public_key, dev.public_key());
    assert_eq!(v.archive_offset as usize, crx.len() - ARCHIVE.len());
    assert!(!v.diff);
}

#[test]
fn ecdsa_developer_key_and_publisher() {
    let dev = EcdsaSigner::generate().unwrap();
    let publisher = EcdsaSigner::generate().unwrap();
    let crx = Builder::new()
        .signer(&dev)
        .signer(&publisher)
        .verified_contents(b"vc")
        .build(ARCHIVE)
        .unwrap();
    let pinned = [key_hash(publisher.public_key())];
    let v = verify(&crx, &Policy::new().any_of(&pinned)).unwrap();
    assert_eq!(v.id, id_from_public_key(dev.public_key()));
    assert_eq!(v.verified_contents.as_deref(), Some(&b"vc"[..]));
}

#[test]
fn append_publisher_proof_to_developer_crx() {
    let dev = RsaSigner::generate().unwrap();
    let publisher = EcdsaSigner::generate().unwrap();
    let pinned = [key_hash(publisher.public_key())];
    let policy = Policy::new().any_of(&pinned);

    let crx = Builder::new().signer(&dev).build(ARCHIVE).unwrap();
    assert_eq!(
        verify(&crx, &policy),
        Err(VerifyError::RequiredProofMissing)
    );

    let crx = append_proof(&crx, &publisher).unwrap();
    let v = verify(&crx, &policy).unwrap();
    assert_eq!(v.id, id_from_public_key(dev.public_key()));
}

#[test]
fn required_keys_need_their_own_proofs() {
    let dev = RsaSigner::generate().unwrap();
    let extra = EcdsaSigner::generate().unwrap();
    let absent = EcdsaSigner::generate().unwrap();
    let crx = append_proof(&Builder::new().signer(&dev).build(ARCHIVE).unwrap(), &extra).unwrap();
    let have = [key_hash(extra.public_key())];
    let lack = [key_hash(absent.public_key())];
    assert!(verify(&crx, &Policy::new().required_keys(&have)).is_ok());
    assert_eq!(
        verify(&crx, &Policy::new().required_keys(&lack)),
        Err(VerifyError::RequiredProofMissing)
    );
}

#[test]
fn bad_extra_proof_fails_whole_crx() {
    let dev = RsaSigner::generate().unwrap();
    let extra = EcdsaSigner::generate().unwrap();
    let crx = Builder::new()
        .signer(&dev)
        .signer(&extra)
        .build(ARCHIVE)
        .unwrap();
    let mut bad = crx.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify(&bad, &Policy::default()),
        Err(VerifyError::SignatureVerificationFailed)
    );
}

#[test]
fn diff_crx() {
    let dev = EcdsaSigner::generate().unwrap();
    let crx = Builder::new()
        .signer(&dev)
        .diff(true)
        .build(b"patch")
        .unwrap();
    assert_eq!(&crx[..4], b"CrOD");
    assert!(verify(&crx, &Policy::default()).unwrap().diff);
}

#[test]
fn keys_round_trip_through_pkcs8() {
    let rsa = RsaSigner::generate().unwrap();
    let again = RsaSigner::from_pkcs8(&rsa.to_pkcs8().unwrap()).unwrap();
    assert_eq!(rsa.public_key(), again.public_key());
    let ec = EcdsaSigner::generate().unwrap();
    let again = EcdsaSigner::from_pkcs8(&ec.to_pkcs8().unwrap()).unwrap();
    assert_eq!(ec.public_key(), again.public_key());
}

#[test]
fn no_signer() {
    assert!(matches!(
        Builder::new().build(ARCHIVE),
        Err(crx3::BuildError::NoSigner)
    ));
}

/// Writes sample CRX files for checking against other implementations.
/// Run with CRX3_CROSSCHECK_DIR set; otherwise does nothing.
#[test]
fn write_crosscheck_samples() {
    let Ok(dir) = std::env::var("CRX3_CROSSCHECK_DIR") else {
        return;
    };
    let dev = RsaSigner::generate().unwrap();
    let publisher = EcdsaSigner::generate().unwrap();
    let rsa_only = Builder::new().signer(&dev).build(ARCHIVE).unwrap();
    let both = append_proof(&rsa_only, &publisher).unwrap();
    let ec_dev = Builder::new().signer(&publisher).build(ARCHIVE).unwrap();
    for (name, bytes) in [
        ("rsa.crx", &rsa_only),
        ("rsa_ecdsa.crx", &both),
        ("ecdsa.crx", &ec_dev),
    ] {
        std::fs::write(format!("{dir}/{name}"), bytes).unwrap();
    }
    let ids = format!(
        "{}\n{}\n",
        id_from_public_key(dev.public_key()),
        id_from_public_key(publisher.public_key())
    );
    std::fs::write(format!("{dir}/ids.txt"), ids).unwrap();
    std::fs::write(
        format!("{dir}/publisher.hash"),
        key_hash(publisher.public_key()).as_bytes(),
    )
    .unwrap();
}

struct Generated {
    len: u64,
    pos: u64,
}

impl std::io::Read for Generated {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min((self.len - self.pos) as usize);
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = ((self.pos + i as u64) % 251) as u8;
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl std::io::Seek for Generated {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.pos = match pos {
            std::io::SeekFrom::Start(p) => p,
            std::io::SeekFrom::End(d) => self.len.checked_add_signed(d).unwrap(),
            std::io::SeekFrom::Current(d) => self.pos.checked_add_signed(d).unwrap(),
        };
        Ok(self.pos)
    }
}

#[test]
fn streams_large_archives() {
    use sha2::{Digest, Sha256};
    use std::io::{Seek, SeekFrom};

    let len = 64 << 20;
    let dev = RsaSigner::generate().unwrap();
    let publisher = EcdsaSigner::generate().unwrap();
    let path = std::env::temp_dir().join(format!("crx3-stream-{}.crx", std::process::id()));
    let mut file = std::fs::File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    Builder::new()
        .signer(&dev)
        .write(Generated { len, pos: 0 }, &mut file)
        .unwrap();

    file.seek(SeekFrom::Start(0)).unwrap();
    let mut appended = Vec::new();
    crx3::append_proof_to(&mut file, &publisher, &mut appended).unwrap();

    file.seek(SeekFrom::Start(0)).unwrap();
    let v = crx3::verify_reader(&mut file, &Policy::default()).unwrap();
    assert_eq!(v.id, id_from_public_key(dev.public_key()));
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).unwrap();
    assert_eq!(v.file_sha256, <[u8; 32]>::from(hasher.finalize()));

    let pinned = [key_hash(publisher.public_key())];
    let v = crx3::verify_reader(&appended[..], &Policy::new().any_of(&pinned)).unwrap();
    assert_eq!(v.id, id_from_public_key(dev.public_key()));
    std::fs::remove_file(&path).unwrap();
}
