//! Access to Chromium's own test data, fetched by
//! `scripts/fetch-chromium-testdata` into `testdata/chromium/<revision>/`.
//! Without it, tests using it are skipped, unless
//! `OMAHA_REQUIRE_CHROMIUM_TESTDATA` is set.
#![allow(dead_code)]

use std::path::PathBuf;

const REVISION: &str = "7ff956173add630906515187ce16a956f0d2074e";

fn root() -> PathBuf {
    match std::env::var_os("OMAHA_CHROMIUM_TESTDATA") {
        Some(dir) => PathBuf::from(dir),
        None => [
            env!("CARGO_MANIFEST_DIR"),
            "..",
            "..",
            "testdata",
            "chromium",
            REVISION,
        ]
        .iter()
        .collect(),
    }
}

/// Reads a source file from the Chromium tree, or `None` (with a note) if
/// the test data hasn't been fetched.
pub fn text(path: &str) -> Option<String> {
    let full = root().join(path);
    match std::fs::read_to_string(&full) {
        Ok(s) => Some(s),
        Err(_) if std::env::var_os("OMAHA_REQUIRE_CHROMIUM_TESTDATA").is_none() => {
            eprintln!(
                "skipping: {} missing, run scripts/fetch-chromium-testdata",
                full.display()
            );
            None
        }
        Err(e) => panic!("{}: {e}", full.display()),
    }
}

/// The value of `NAME = "..." "...";`, adjacent string literals joined.
pub fn string_constant(src: &str, name: &str) -> String {
    let start = src
        .find(&format!("{name} ="))
        .unwrap_or_else(|| panic!("{name} not found"));
    let rest = &src[start
        ..src[start..]
            .find(';')
            .map(|e| start + e)
            .expect("end of constant")];
    rest.split('"').skip(1).step_by(2).collect()
}

/// The bytes of `NAME = std::to_array<uint8_t>({0x.., ...});`.
pub fn byte_array(src: &str, name: &str) -> Vec<u8> {
    let start = src
        .find(&format!("{name} ="))
        .unwrap_or_else(|| panic!("{name} not found"));
    let open = start + src[start..].find('{').expect("array start");
    let close = open + src[open..].find('}').expect("array end");
    src[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| u8::from_str_radix(t.trim_start_matches("0x"), 16).expect("hex byte"))
        .collect()
}
