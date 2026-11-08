# omaha-publish

Publish CRX feeds for Chromium's update protocol: deterministic archives,
patches from earlier releases, and a signed index that
[omaha-server](https://crates.io/crates/omaha-server) answers update checks
from.

```sh
omaha-publish keygen index.pem > index.pub.pem
omaha-publish pack --key crx.pem component/ component.crx3
omaha-publish publish --store s3://bucket/feed --key index.pem \
    --puffin out/Release/puffin component.crx3
omaha-publish refresh --store s3://bucket/feed --key index.pem
```

- `publish` uploads the CRX and patches to it from the newest earlier
  releases, then writes the next index. Files are content-addressed and
  never overwritten. The index is written last, and only if nobody else
  published in the meantime.
- `refresh` re-signs the index with a new expiry. Run it on a schedule
  shorter than `--lifetime-days`, so servers never see it expire.
- Stores are `file:///path` or, with the `s3` feature, `s3://bucket/prefix`
  configured through the usual `AWS_*` variables. Set `AWS_ENDPOINT` for
  S3-compatible stores such as R2.

The same steps are available as a library:

```rust,no_run
use omaha_publish::Store;
use omaha_publish::release::{Options, Policy};
use omaha_server::index::aws_lc::{EcdsaKey, EcdsaSigner};
use omaha_server::index::Signer;
use std::sync::Arc;
use std::time::SystemTime;

# async fn publish(key_der: &[u8], crx: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
let key = EcdsaSigner::from_pkcs8(key_der)?;
let trusted = EcdsaKey::from_spki(key.public_key())?;
let store = Store::new(Arc::new(object_store::memory::InMemory::new()), "index.json")?;

let plan = store
    .publish(crx, Options::default(), &[&key], &[&trusted], &[], &Policy::default(), SystemTime::now())
    .await?;
println!("index serial {}", plan.index.serial);
# Ok(())
# }
```

## Features

- `cli` (default): the `omaha-publish` binary.
- `s3` (default): S3-compatible object storage.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
