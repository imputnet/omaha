#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."

version=0.20.2
target=x86_64-unknown-linux-musl

step() {
    printf '\n==> %s\n' "$*"
}

step "installing cargo-deny $version"
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
name="cargo-deny-$version-$target"
url="https://github.com/EmbarkStudios/cargo-deny/releases/download/$version/$name.tar.gz"
curl -fsSL "$url" -o "$dir/$name.tar.gz"
expected=$(curl -fsSL "$url.sha256" | cut -d ' ' -f 1)
echo "$expected  $dir/$name.tar.gz" | sha256sum -c -
tar -xzf "$dir/$name.tar.gz" -C "$dir"

step "running cargo-deny"
"$dir/$name/cargo-deny" --locked check
