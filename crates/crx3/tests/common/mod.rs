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

/// Reads a file from the Chromium tree, or `None` (with a note) if the test
/// data hasn't been fetched.
pub fn bytes(path: &str) -> Option<Vec<u8>> {
    let full = root().join(path);
    match std::fs::read(&full) {
        Ok(b) => Some(b),
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

pub fn text(path: &str) -> Option<String> {
    bytes(path).map(|b| String::from_utf8(b).expect("utf-8 source"))
}

/// The C++ string literals in `src`, in order, with adjacent literals
/// concatenated. Only handles what Chromium's tests use: no escapes beyond
/// `\"` and `\\`.
fn literals(src: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut chars = src.char_indices().peekable();
    let mut last_end = None;
    while let Some((i, c)) = chars.next() {
        if c == '/' && chars.peek().map(|&(_, n)| n) == Some('/') {
            for (_, n) in chars.by_ref() {
                if n == '\n' {
                    break;
                }
            }
            continue;
        }
        if c != '"' {
            if !c.is_whitespace() {
                last_end = None;
            }
            continue;
        }
        let mut lit = String::new();
        while let Some((_, n)) = chars.next() {
            match n {
                '"' => break,
                '\\' => lit.push(chars.next().expect("escape").1),
                _ => lit.push(n),
            }
        }
        match (last_end, out.last_mut()) {
            (Some(()), Some((_, prev))) => prev.push_str(&lit),
            _ => out.push((i, lit)),
        }
        last_end = Some(());
    }
    out
}

/// The value of `constexpr char NAME[] = "..." "...";`.
pub fn string_constant(src: &str, name: &str) -> String {
    let start = src
        .find(&format!("{name}[] ="))
        .unwrap_or_else(|| panic!("{name} not found"));
    literals(&src[start..])
        .into_iter()
        .next()
        .expect("literal")
        .1
}

/// Pairs `(expected, input)` from every `EXPECT_EQ("expected", call("input"))`.
pub fn expect_eq_calls(src: &str, call: &str) -> Vec<(String, String)> {
    let flat: String = src.split_whitespace().collect::<Vec<_>>().join(" ");
    let needle = format!("\", {call}(\"");
    let mut out = Vec::new();
    for (i, _) in flat.match_indices(&needle) {
        let before = &flat[..i];
        let Some(open) = before.rfind("EXPECT_EQ(") else {
            continue;
        };
        let lits = literals(&flat[open..]);
        if let [(_, expected), (_, input), ..] = lits.as_slice() {
            out.push((expected.clone(), input.clone()));
        }
    }
    out
}
