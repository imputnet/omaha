#![no_main]

use cup2::aws_lc::EcdsaSigner;
use cup2::{Client, KeyId};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let key = EcdsaSigner::generate(8).expect("a key");
        Client::new(KeyId::Ecdsa(8), key.public_key()).expect("a client")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = text.splitn(3, '\n');
    let (key, hreq, body) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );

    let _ = key.parse::<KeyId>();
    let _ = cup2::Ticket::new(key, Some(hreq).filter(|h| !h.is_empty()), body.as_bytes());

    let request = client().prepare_with_nonce(b"{}", "nonce");
    let _ = client().verify(&request, body.as_bytes(), key);
});
