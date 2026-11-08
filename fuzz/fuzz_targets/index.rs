#![no_main]

use libfuzzer_sys::fuzz_target;
use omaha_server::index::Index;
use std::time::UNIX_EPOCH;

fuzz_target!(|data: &[u8]| {
    let _ = Index::open(data, &[], UNIX_EPOCH);

    if let Ok(index) = Index::from_json(data) {
        let json = index.to_json().expect("a parsed index encodes");
        assert_eq!(Index::from_json(&json).ok(), Some(index));
    }
});
