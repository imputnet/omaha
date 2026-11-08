# omaha-diff

Patches for differential updates in Chromium's update protocol, made with
Chromium's own `puffin` and `zucchini` tools.

```rust,no_run
use omaha_diff::Differ;

let old = std::fs::read("component-1.crx3").expect("read old");
let new = std::fs::read("component-2.crx3").expect("read new");

let patch = Differ::puffin("out/Release/puffin")
    .diff(&old, &new)
    .expect("make patch");
std::fs::write("1-to-2.puff", patch).expect("write patch");
```

Every patch is applied again before it is returned and must reproduce the
target exactly. The tools run as subprocesses in a temporary directory,
so build them from the same Chromium version as the browsers you serve:
`puffin` from `third_party/puffin` for CRX files, and `zucchini` from
`components/zucchini` for executables.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
