#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."

msrv=$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml)

step() {
    printf '\n==> %s\n' "$*"
}

step "installing rust $msrv"
rustup toolchain install "$msrv" --profile minimal

step "checking build"
cargo "+$msrv" check \
    --workspace \
    --all-features \
    --locked
