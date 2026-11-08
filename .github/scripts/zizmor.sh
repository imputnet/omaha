#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."

step() {
    printf '\n==> %s\n' "$*"
}

step "auditing workflows"
pipx run zizmor .github/workflows
