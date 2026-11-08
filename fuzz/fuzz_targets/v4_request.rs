#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = omaha_protocol::v4::decode_request(data, &omaha_protocol::Limits::default());
});
