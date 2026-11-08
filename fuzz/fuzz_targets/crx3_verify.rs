#![no_main]

use libfuzzer_sys::fuzz_target;

// Untrusted CRX bytes must never panic, only verify or fail.
fuzz_target!(|data: &[u8]| {
    let _ = crx3::split(data);
    let _ = crx3::verify(data, &crx3::Policy::default());
});
