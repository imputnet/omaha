#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(query) = std::str::from_utf8(data) {
        let _ = omaha_protocol::update2::decode_query(query, &omaha_protocol::Limits::default());
    }
});
