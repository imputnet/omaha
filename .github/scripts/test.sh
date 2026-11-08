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

for crate in crx3 cup2 omaha-protocol omaha-server omaha-diff omaha-publish omaha; do
    step "running clippy on $crate without default features"
    cargo "+$toolchain" clippy \
        --package "$crate" \
        --no-default-features \
        --all-targets \
        --locked \
        -- -D warnings
done

step "running tests"
cargo "+$toolchain" test \
    --workspace \
    --all-features \
    --locked

step "running tests with default features"
cargo "+$toolchain" test \
    --workspace \
    --locked

step "building docs"
RUSTDOCFLAGS="-D warnings" cargo "+$toolchain" doc \
    --workspace \
    --all-features \
    --no-deps \
    --locked
