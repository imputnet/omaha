//! Chromium's own test data, fetched by `scripts/fetch-chromium-testdata`
//! into `testdata/chromium/<revision>/`. Without it, functions here return
//! `None` and print a note, unless `OMAHA_REQUIRE_CHROMIUM_TESTDATA` is set.

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

/// Reads a file from the Chromium tree.
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

/// Reads a source file from the Chromium tree.
pub fn text(path: &str) -> Option<String> {
    bytes(path).map(|b| String::from_utf8(b).expect("utf-8 source"))
}

fn find_constant(src: &str, name: &str) -> usize {
    [format!("{name}[] ="), format!("{name} =")]
        .iter()
        .find_map(|needle| src.find(needle.as_str()))
        .unwrap_or_else(|| panic!("{name} not found"))
}

/// The value of a string constant, `NAME[] = "..." "...";` or
/// `NAME = "...";`, with adjacent literals joined.
pub fn string_constant(src: &str, name: &str) -> String {
    let start = find_constant(src, name);
    literals(&src[start..])
        .into_iter()
        .next()
        .expect("literal")
        .1
}

/// The value of a raw string constant, `NAME[] = R"(...)";`.
pub fn raw_string_constant(src: &str, name: &str) -> String {
    let start = find_constant(src, name);
    let open = start + src[start..].find("R\"(").expect("raw string start") + 3;
    let close = open + src[open..].find(")\"").expect("raw string end");
    src[open..close].to_owned()
}

/// The bytes of `NAME = std::to_array<uint8_t>({0x.., ...});`.
pub fn byte_array(src: &str, name: &str) -> Vec<u8> {
    let start = find_constant(src, name);
    let open = start + src[start..].find('{').expect("array start");
    let close = open + src[open..].find('}').expect("array end");
    src[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| u8::from_str_radix(t.trim_start_matches("0x"), 16).expect("hex byte"))
        .collect()
}

/// Decodes standard base64, as Chromium's tests use for keys.
pub fn base64(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for b in s.bytes().filter(|&b| b != b'=') {
        acc = (acc << 6) | ALPHABET.iter().position(|&a| a == b).expect("base64") as u32;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
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
