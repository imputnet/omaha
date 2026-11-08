#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."

toolchain=stable

step() {
    printf '\n==> %s\n' "$*"
}

step "installing rust $toolchain"
rustup toolchain install "$toolchain" \
    --profile minimal \
    --component rustfmt,clippy

step "fetching chromium test data"
./scripts/fetch-chromium-testdata
export OMAHA_REQUIRE_CHROMIUM_TESTDATA=1

step "checking formatting"
cargo "+$toolchain" fmt --all --check

step "running clippy"
cargo "+$toolchain" clippy \
    --workspace \
    --all-features \
    --all-targets \
    --locked \
    -- -D warnings

step "running tests"
cargo "+$toolchain" test \
    --workspace \
    --all-features \
    --locked
