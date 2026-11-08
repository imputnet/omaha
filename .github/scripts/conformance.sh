#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."

channel=${CHROME_CHANNEL:-Stable}
dir=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/chrome-for-testing
policies=/etc/opt/chrome_for_testing/policies/managed
versions=https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json

step() {
    printf '\n==> %s\n' "$*"
}

step "installing rust stable"
rustup toolchain install stable --profile minimal

step "downloading chrome for testing ($channel)"
url=$(curl -fsSL "$versions" | jq -r --arg channel "$channel" \
    '.channels[$channel].downloads.chrome[] | select(.platform == "linux64") | .url')
rm -rf "$dir"
mkdir -p "$dir"
curl -fsSL -o "$dir/chrome.zip" "$url"
unzip -q "$dir/chrome.zip" -d "$dir"
"$dir/chrome-linux64/chrome" --version

step "allowing the test to write browser policy"
sudo mkdir -p "$policies"
sudo chown "$(id -u)" "$policies"

step "running a browser against omaha-server"
cargo +stable run --locked -p conformance -- \
    --browser "$dir/chrome-linux64/chrome" \
    --policy-dir "$policies"
