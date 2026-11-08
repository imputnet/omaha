#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."

seconds=${FUZZ_SECONDS:-60}

step() {
    printf '\n==> %s\n' "$*"
}

step "installing rust nightly and cargo-fuzz"
rustup toolchain install nightly --profile minimal
cargo +nightly install --locked cargo-fuzz

for target in $(cargo +nightly fuzz list); do
    step "fuzzing $target for ${seconds}s"
    cargo +nightly fuzz run "$target" -- -max_total_time="$seconds"
done
