# crx3

Build, sign and verify Chromium's CRX3 packages, the format of browser
extensions and components. Verification follows the same rules as
Chromium's own verifier, so a package that verifies here verifies in the
browser.

```rust,no_run
use crx3::aws_lc::{EcdsaSigner, RsaSigner};
use crx3::{key_hash, verify, Builder, Policy, Signer};

let archive = std::fs::read("extension.zip").expect("read archive");

// The first signer's key determines the extension ID. Further signers add
// proofs over the same data, such as a store's publisher key.
let developer = RsaSigner::generate().expect("generate key");
let store = EcdsaSigner::generate().expect("generate key");
let crx = Builder::new(&archive)
    .signer(&developer)
    .signer(&store)
    .build()
    .expect("build crx");

// Require a valid developer proof and a proof by the store's key.
let pinned = [key_hash(store.public_key())];
let verified = verify(&crx, &Policy { required_keys: &[], any_of: &pinned })
    .expect("valid crx");
println!("extension id: {}", verified.id);
```

`append_proof` adds a proof to a package someone else signed, without their
key. Signing goes through the `Signer` trait, so keys can also live in an
HSM or a remote signing service.

## Features

- `aws-lc` (default): RSA and ECDSA P-256 signers and verification, backed
  by [aws-lc-rs](https://crates.io/crates/aws-lc-rs).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
