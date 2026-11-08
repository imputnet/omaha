//! Checks against Chromium's components/client_update_protocol/cup_unittest.cc,
//! read from the fetched Chromium tree.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "aws-lc")]

use cup2::aws_lc::MlDsa44Signer;
use cup2::{Client, KeyId, Server};

const UNITTEST: &str = "components/client_update_protocol/cup_unittest.cc";

#[test]
fn request_parameters_match_chromium() {
    let Some(src) = chromium_testdata::text(UNITTEST) else {
        return;
    };
    let request = chromium_testdata::string_constant(&src, "kRequest");
    let hash_suffix = chromium_testdata::string_constant(&src, "kRequestHashWithName");
    let key_prefix = chromium_testdata::string_constant(&src, "kKeyIdWithName");

    let key = chromium_testdata::byte_array(&src, "kCupTestPrivateKeyInfo");
    let signer = MlDsa44Signer::from_pkcs8(16, &key).unwrap();
    let client = Client::new(KeyId::MlDsa44(16), signer.public_key()).unwrap();

    let first = client.prepare(request.as_bytes()).unwrap().query();
    let second = client.prepare(request.as_bytes()).unwrap().query();
    assert_ne!(first, second, "nonces must differ");
    for query in [first, second] {
        assert!(query.starts_with(&key_prefix), "{query}");
        assert!(query.ends_with(&hash_suffix), "{query}");
        let nonce = &query[key_prefix.len()..query.len() - hash_suffix.len()];
        assert_eq!(nonce.len(), 43, "32 bytes, base64url, no padding: {nonce}");
    }
}

#[test]
fn signs_with_chromium_test_key() {
    let Some(src) = chromium_testdata::text(UNITTEST) else {
        return;
    };
    let key = chromium_testdata::byte_array(&src, "kCupTestPrivateKeyInfo");
    let signer = MlDsa44Signer::from_pkcs8(16, &key).unwrap();
    let client = Client::new(KeyId::MlDsa44(16), signer.public_key()).unwrap();
    let server = Server::new().with(signer);

    let request = client.prepare(b"Request_A").unwrap();
    let ticket = server
        .ticket(request.cup2key(), None, b"Request_A")
        .unwrap();
    let proof = server.sign(&ticket, b"Response_A").unwrap();
    client
        .verify(&request, b"Response_A", proof.as_str())
        .unwrap();
    client
        .verify(&request, b"Response_A", &proof.etag())
        .unwrap();
    assert!(
        client
            .verify(&request, b"Response_B", proof.as_str())
            .is_err()
    );
}
