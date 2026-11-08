# omaha

Rust tools for Chromium's update protocol (Omaha): CRX3 packages, CUP2
response signing, update checks and component feeds.

Early development. APIs will change.

## Testing

`cargo test --workspace` runs the unit tests, and the Chromium conformance
tests once `scripts/fetch-chromium-testdata` has fetched Chromium's own test
files.

`support/conformance` runs a real browser against `omaha-server`: it
force-installs a test extension through a managed policy, publishes a new
version with `omaha-publish`, and checks the browser updates to it, over
both update2 and Omaha 4. CI runs it with Chrome for Testing:

```sh
.github/scripts/conformance.sh
```

It needs `sudo` to write the policy, under
`/etc/opt/chrome_for_testing/policies/managed`. A stock browser can't finish
an Omaha 4 extension update, because Web Store updates need a publisher
proof that only Google can sign, so that scenario passes once the browser
has checked, downloaded and verified the update.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
