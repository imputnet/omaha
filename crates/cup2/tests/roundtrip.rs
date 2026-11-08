#![cfg(feature = "aws-lc")]

use cup2::aws_lc::{EcdsaSigner, MlDsa44Signer};
use cup2::{Client, Error, KeyId, Server, VerifyError};

const REQUEST: &[u8] = br#"{"request":{"protocol":"4.0"}}"#;
const RESPONSE: &[u8] = br#")]}'
{"response":{"protocol":"4.0"}}"#;

fn servers() -> (Server, Client, Client) {
    let mldsa = MlDsa44Signer::generate(16).unwrap();
    let ecdsa = EcdsaSigner::generate(8).unwrap();
    let mldsa_client = Client::new(KeyId::MlDsa44(16), mldsa.public_key()).unwrap();
    let ecdsa_client = Client::new(KeyId::Ecdsa(8), ecdsa.public_key()).unwrap();
    (
        Server::new().with(mldsa).with(ecdsa),
        mldsa_client,
        ecdsa_client,
    )
}

#[test]
fn both_schemes_round_trip() {
    let (server, mldsa, ecdsa) = servers();
    for client in [&mldsa, &ecdsa] {
        let request = client.prepare(REQUEST);
        let query = request.query();
        let (cup2key, cup2hreq) = query
            .strip_prefix("cup2key=")
            .and_then(|q| q.split_once("&cup2hreq="))
            .unwrap();
        let ticket = server.ticket(cup2key, Some(cup2hreq), REQUEST).unwrap();
        let proof = server.sign(&ticket, RESPONSE).unwrap();
        client.verify(&request, RESPONSE, proof.as_str()).unwrap();
        client.verify(&request, RESPONSE, &proof.etag()).unwrap();
    }
}

#[test]
fn rejects_tampering() {
    let (server, client, _) = servers();
    let request = client.prepare(REQUEST);
    let ticket = server.ticket(request.cup2key(), None, REQUEST).unwrap();
    let proof = server.sign(&ticket, RESPONSE).unwrap();

    assert_eq!(
        client.verify(&request, b"other", proof.as_str()),
        Err(VerifyError::BadSignature)
    );
    assert_eq!(
        client.verify(&request, b"", proof.as_str()),
        Err(VerifyError::EmptyResponse)
    );

    let other = client.prepare(REQUEST);
    assert_eq!(
        client.verify(&other, RESPONSE, proof.as_str()),
        Err(VerifyError::BadSignature)
    );

    let changed = server.ticket(request.cup2key(), None, b"changed").unwrap();
    let proof = server.sign(&changed, RESPONSE).unwrap();
    assert_eq!(
        client.verify(&request, RESPONSE, proof.as_str()),
        Err(VerifyError::RequestHashMismatch)
    );
}

#[test]
fn signature_sizes_are_checked() {
    let (server, mldsa, ecdsa) = servers();
    let request = ecdsa.prepare(REQUEST);
    let ticket = server.ticket(request.cup2key(), None, REQUEST).unwrap();
    let ecdsa_proof = server.sign(&ticket, RESPONSE).unwrap();
    let request = mldsa.prepare(REQUEST);
    let hash = ecdsa_proof.as_str().split(':').nth(1).unwrap();
    let wrong = format!("{}:{hash}", ecdsa_proof.as_str().split(':').next().unwrap());
    let _ = hash;
    assert_eq!(
        mldsa.verify(&request, RESPONSE, &wrong),
        Err(VerifyError::MalformedProof)
    );
}

#[test]
fn unknown_keys_are_refused() {
    let (server, _, _) = servers();
    assert_eq!(
        server.ticket("ML-DSA-44-17:nonce", None, REQUEST),
        Err(Error::UnknownKey(KeyId::MlDsa44(17)))
    );
    assert_eq!(
        server.ticket("9:nonce", None, REQUEST),
        Err(Error::UnknownKey(KeyId::Ecdsa(9)))
    );
}

#[test]
fn keys_round_trip_through_pkcs8() {
    let mldsa = MlDsa44Signer::generate(1).unwrap();
    let again = MlDsa44Signer::from_pkcs8(1, &mldsa.to_pkcs8().unwrap()).unwrap();
    assert_eq!(mldsa.public_key(), again.public_key());
    let ecdsa = EcdsaSigner::generate(1).unwrap();
    let again = EcdsaSigner::from_pkcs8(1, &ecdsa.to_pkcs8().unwrap()).unwrap();
    assert_eq!(ecdsa.public_key(), again.public_key());
}

/// Exchanges keys, requests and proofs with another implementation through
/// files in CUP2_CROSSCHECK_DIR. Phase 1 writes our public keys; phase 2
/// signs the other side's requests and verifies its proofs.
#[test]
fn crosscheck() {
    let Ok(dir) = std::env::var("CUP2_CROSSCHECK_DIR") else {
        return;
    };
    let read = |name: &str| std::fs::read_to_string(format!("{dir}/{name}")).unwrap();
    let write = |name: &str, data: &[u8]| std::fs::write(format!("{dir}/{name}"), data).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let unhex = |s: &str| {
        (0..s.trim().len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s.trim()[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    };

    if std::env::var("CUP2_CROSSCHECK_PHASE").as_deref() == Ok("1") {
        let mldsa = MlDsa44Signer::generate(16).unwrap();
        let ecdsa = EcdsaSigner::generate(8).unwrap();
        write("rust_mldsa.p8", hex(&mldsa.to_pkcs8().unwrap()).as_bytes());
        write("rust_ecdsa.p8", hex(&ecdsa.to_pkcs8().unwrap()).as_bytes());
        write("rust_mldsa.spki", hex(mldsa.public_key()).as_bytes());
        write("rust_ecdsa.spki", hex(ecdsa.public_key()).as_bytes());
        return;
    }

    let mldsa = MlDsa44Signer::from_pkcs8(16, &unhex(&read("rust_mldsa.p8"))).unwrap();
    let ecdsa = EcdsaSigner::from_pkcs8(8, &unhex(&read("rust_ecdsa.p8"))).unwrap();
    let server = Server::new().with(mldsa).with(ecdsa);
    for alg in ["mldsa", "ecdsa"] {
        let lines: Vec<String> = read(&format!("node_client_{alg}.txt"))
            .lines()
            .map(String::from)
            .collect();
        let (cup2key, cup2hreq, body) = (&lines[0], &lines[1], &lines[2]);
        let ticket = server
            .ticket(cup2key, Some(cup2hreq), body.as_bytes())
            .unwrap();
        let proof = server.sign(&ticket, b"Response_A").unwrap();
        write(&format!("rust_proof_{alg}.txt"), proof.as_str().as_bytes());

        let lines: Vec<String> = read(&format!("node_server_{alg}.txt"))
            .lines()
            .map(String::from)
            .collect();
        let (cup2key, body, proof, spki) = (&lines[0], &lines[1], &lines[2], &lines[3]);
        let (key_id, nonce) = cup2key.split_once(':').unwrap();
        let client = Client::new(key_id.parse().unwrap(), &unhex(spki)).unwrap();
        let request = client.prepare_with_nonce(body.as_bytes(), nonce);
        client.verify(&request, b"Response_A", proof).unwrap();
        write(&format!("rust_verified_{alg}.txt"), b"ok");
    }
}
