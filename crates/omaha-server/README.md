# omaha-server

A server for Chromium's update protocols: Omaha 4 update checks (POST) and
the legacy update2 requests of Chromium's extension downloader (GET),
answered from your own sources and signed with CUP2.

An `Endpoint` is a `tower::Service`, so it runs on hyper, axum or anything
else built on tower. It routes each app ID to the `Source` that knows it,
asks the sources concurrently, merges their answers in request order, and
makes sure each answer fits what the client asked for. Ping-backs are
acknowledged without asking a source.

```rust,no_run
use omaha_protocol::{AppId, AppResponse, AppStatus, Outcome, UpdateCheckResponse};
use omaha_server::{BoxFuture, Check, Endpoint, Source};

/// Says "no update" to every app it's asked about.
struct UpToDate;

impl Source for UpToDate {
    fn check<'a>(&'a self, check: Check<'a>) -> BoxFuture<'a, Vec<AppResponse>> {
        Box::pin(async move {
            check
                .apps
                .iter()
                .map(|app| {
                    let mut answer = AppResponse::new(app.appid.clone(), AppStatus::Ok);
                    answer.updatecheck = Some(UpdateCheckResponse::new(Outcome::NoUpdate));
                    answer
                })
                .collect()
        })
    }
}

let appid = AppId::new("ddkjiahejlhfcafbddmgiahcphecmpfh").expect("valid app ID");
let endpoint = Endpoint::builder()
    .source([appid], UpToDate)
    .server_name("example")
    .build();
```

Apps without a source of their own get `error-unknownApplication`, unless
`.fallback(source)` sends them somewhere, for example to an upstream
server. Add CUP2 signing with `.cup(cup2::Server::new().with(signer))`.

The `index` module defines a signed index of releases (JSON in a DSSE
envelope, with a serial and an expiry against replays) and answers update
checks from it: the newest release the client qualifies for, with a patch
pipeline first when the client has a CRX to patch from. `StaticIndex` serves
one as a source and swaps in newer ones while the server runs, refusing
older serials.

## Serving a feed

With the `cli` feature, `omaha-server serve` answers update checks from a
feed published with [omaha-publish](https://crates.io/crates/omaha-publish),
reloading its index every few minutes:

```sh
cargo install omaha-server --features cli
omaha-server serve --index https://dl.example/feed/index.json \
    --trust index.pub.pem --cup-key 16=cup-mldsa.pem
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
