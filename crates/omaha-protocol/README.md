# omaha-protocol

Chromium's update protocols with one typed model:

- **Omaha 4 JSON**, used by Chromium's component updater, its browser
  updater, and Chrome Web Store extension updates.
- **update2**, the GET protocol Chromium's extension downloader uses for
  extensions from any other store, answered with `gupdate` XML or, for
  installs, a redirect.

Requests carry no per-client identifiers: session and request IDs, install
IDs, install dates and ping data are never decoded. Decoders take `Limits`
and are meant for untrusted input.

```rust
use omaha_protocol::{
    v4, AppResponse, AppStatus, Limits, Operation, Outcome, Pipeline, Response,
    UpdateCheckResponse,
};

let body = br#"{"request":{"protocol":"4.0","apps":[
    {"appid":"ddkjiahejlhfcafbddmgiahcphecmpfh","version":"1.0","updatecheck":{}}
]}}"#;
let request = v4::decode_request(body, &Limits::default()).expect("valid request");

let hash = "b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116"
    .parse()
    .expect("valid hash");
let mut app = AppResponse::new(request.apps[0].appid.clone(), AppStatus::Ok);
app.updatecheck = Some(UpdateCheckResponse::new(Outcome::Update {
    nextversion: "2.0".parse().expect("valid version"),
    pipelines: vec![Pipeline {
        id: "full".into(),
        operations: vec![
            Operation::Download {
                size: 9092445,
                out: hash,
                urls: vec!["https://cdn.example/extension.crx".into()],
            },
            Operation::Crx3 { input: hash, size: None, path: None, arguments: None },
        ],
    }],
}));

let response = Response { apps: vec![app], ..Default::default() };
let json = v4::encode_response(&response).expect("valid response");
assert!(json.starts_with(b")]}'"));
```

The same `Response` renders as update2 XML with `update2::encode_xml`, or as
an install redirect with `update2::redirect_url`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
