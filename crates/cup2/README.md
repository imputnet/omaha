# cup2

Chromium's Client Update Protocol (CUP2): the server signs each update
response together with a hash of the request and a client nonce, so the
browser can tell the response is fresh, unmodified, and from the right
server.

Current Chromium only uses ML-DSA-44 keys (key IDs like `ML-DSA-44-16`);
ECDSA P-256 (key IDs like `8`) is supported for older versions.

```rust
use cup2::aws_lc::MlDsa44Signer;
use cup2::{Client, KeyId, Server};

// The server holds the private key; the browser pins its public key.
let signer = MlDsa44Signer::generate(16).expect("generate key");
let client = Client::new(KeyId::MlDsa44(16), signer.public_key()).expect("valid key");
let server = Server::new().with(signer);

// The client adds `cup2key` and `cup2hreq` to its request.
let body = br#"{"request":{"protocol":"4.0"}}"#;
let request = client.prepare(body);

// The server checks them, then signs the exact response bytes it sends,
// as the `X-Cup-Server-Proof` header.
let ticket = server.ticket(request.cup2key(), None, body).expect("known key");
let response = br#")]}'
{"response":{"protocol":"4.0"}}"#;
let proof = server.sign(&ticket, response).expect("signed");

client.verify(&request, response, proof.as_str()).expect("valid proof");
```

Signing goes through the `Signer` trait, so keys can also live in an HSM or
a remote signing service.

## Features

- `aws-lc` (default): ML-DSA-44 and ECDSA P-256 signers and the client,
  backed by [aws-lc-rs](https://crates.io/crates/aws-lc-rs).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
