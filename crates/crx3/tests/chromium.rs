//! Checks against Chromium's own tests and test files
//! (components/crx_file/*_unittest.cc), read from the fetched Chromium tree.
#![cfg(feature = "aws-lc")]

use crx3::{
    Policy, VerifyError, WEBSTORE_PUBLISHER_KEY_HASH, WEBSTORE_PUBLISHER_TEST_KEY_HASH,
    id_from_public_key, key_hash, verify,
};

const DATA: &str = "components/test/data/crx_file";

fn crx(name: &str) -> Option<Vec<u8>> {
    chromium_testdata::bytes(&format!("{DATA}/{name}"))
}

struct Expected {
    ojj_id: String,
    ojj_key: Vec<u8>,
    jln_id: String,
    jln_key: Vec<u8>,
}

fn expected() -> Option<Expected> {
    let src = chromium_testdata::text("components/crx_file/crx_verifier_unittest.cc")?;
    Some(Expected {
        ojj_id: chromium_testdata::string_constant(&src, "kOjjHash"),
        ojj_key: chromium_testdata::base64(&chromium_testdata::string_constant(&src, "kOjjKey")),
        jln_id: chromium_testdata::string_constant(&src, "kJlnHash"),
        jln_key: chromium_testdata::base64(&chromium_testdata::string_constant(&src, "kJlnKey")),
    })
}

const PUBLISHER: Policy = Policy {
    required_keys: &[],
    any_of: &[WEBSTORE_PUBLISHER_KEY_HASH],
};
const PUBLISHER_OR_TEST: Policy = Policy {
    required_keys: &[],
    any_of: &[
        WEBSTORE_PUBLISHER_KEY_HASH,
        WEBSTORE_PUBLISHER_TEST_KEY_HASH,
    ],
};

#[test]
fn id_vectors() {
    let Some(src) = chromium_testdata::text("components/crx_file/id_util_unittest.cc") else {
        return;
    };
    let vectors = chromium_testdata::expect_eq_calls(&src, "GenerateId");
    assert!(vectors.len() >= 3, "found {vectors:?}");
    for (id, input) in vectors {
        assert_eq!(
            id_from_public_key(input.as_bytes()),
            id,
            "GenerateId({input:?})"
        );
    }
}

#[test]
fn valid_full_crx3() {
    let (Some(e), Some(file)) = (expected(), crx("valid_no_publisher.crx3")) else {
        return;
    };
    let v = verify(&file, &Policy::default()).unwrap();
    assert_eq!(v.id, e.ojj_id);
    assert_eq!(v.public_key, e.ojj_key);
}

#[test]
fn crx3_rejects_crx2() {
    let Some(file) = crx("valid.crx2") else {
        return;
    };
    assert_eq!(
        verify(&file, &Policy::default()),
        Err(VerifyError::HeaderInvalid)
    );
}

#[test]
fn checks_required_key_hashes() {
    let (Some(e), Some(file)) = (expected(), crx("valid_no_publisher.crx3")) else {
        return;
    };
    let good = [key_hash(&e.ojj_key)];
    assert_eq!(
        verify(
            &file,
            &Policy {
                required_keys: &good,
                any_of: &[]
            }
        )
        .unwrap()
        .id,
        e.ojj_id
    );
    assert_eq!(
        verify(
            &file,
            &Policy {
                required_keys: &[crx3::KeyHash::from_bytes([0; 32])],
                any_of: &[]
            }
        ),
        Err(VerifyError::RequiredProofMissing)
    );
}

#[test]
fn checks_pinned_key() {
    let Some(e) = expected() else { return };
    let (Some(publisher), Some(test_publisher), Some(none)) = (
        crx("valid_publisher.crx3"),
        crx("valid_test_publisher.crx3"),
        crx("valid_no_publisher.crx3"),
    ) else {
        return;
    };
    let v = verify(&publisher, &PUBLISHER).unwrap();
    assert_eq!((&v.id, &v.public_key), (&e.ojj_id, &e.ojj_key));
    assert_eq!(
        verify(&test_publisher, &PUBLISHER),
        Err(VerifyError::RequiredProofMissing)
    );
    assert_eq!(
        verify(&none, &PUBLISHER),
        Err(VerifyError::RequiredProofMissing)
    );

    assert_eq!(verify(&publisher, &PUBLISHER_OR_TEST).unwrap().id, e.ojj_id);
    let v = verify(&test_publisher, &PUBLISHER_OR_TEST).unwrap();
    assert_eq!((&v.id, &v.public_key), (&e.jln_id, &e.jln_key));
    assert_eq!(v.verified_contents, None);
    assert_eq!(
        verify(&none, &PUBLISHER_OR_TEST),
        Err(VerifyError::RequiredProofMissing)
    );
}

#[test]
fn requires_developer_key() {
    let Some(file) = crx("unsigned.crx3") else {
        return;
    };
    assert_eq!(
        verify(&file, &Policy::default()),
        Err(VerifyError::RequiredProofMissing)
    );
}

#[test]
fn rejects_eocd64_record_in_header() {
    let Some(mut file) = crx("valid_no_publisher.crx3") else {
        return;
    };
    file[12..16].copy_from_slice(b"PK\x06\x06");
    assert_eq!(
        verify(&file, &Policy::default()),
        Err(VerifyError::HeaderInvalid)
    );
}

#[test]
fn rejects_tampered_archive() {
    let Some(mut file) = crx("valid_no_publisher.crx3") else {
        return;
    };
    *file.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify(&file, &Policy::default()),
        Err(VerifyError::SignatureVerificationFailed)
    );
}
