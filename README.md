# omaha

Rust crates for Chromium's update protocol (Omaha): serve extensions,
components and browser updates from your own servers.

| Crate | Use it to |
|---|---|
| [`crx3`](crates/crx3) | build, sign and verify CRX3 packages |
| [`cup2`](crates/cup2) | sign update responses with CUP2, or verify them |
| [`omaha-protocol`](crates/omaha-protocol) | read and write Omaha 4 and update2 requests and responses |
| [`omaha-server`](crates/omaha-server) | run an update endpoint that answers from your own sources or a signed release index |
| [`omaha-diff`](crates/omaha-diff) | make patches with Chromium's puffin and zucchini |
| [`omaha-publish`](crates/omaha-publish) | publish CRXs, patches and a signed index to object storage, as a library or the `omaha-publish` CLI |
| [`omaha`](crates/omaha) | get all of them through one crate, behind features |

Early development. APIs will change.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
