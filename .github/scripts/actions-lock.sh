#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."

step() {
    printf '\n==> %s\n' "$*"
}

step "installing gh-actions-lock"
gh extension install github/gh-actions-lock

step "checking the actions lockfile"
gh actions-lock --verify --no-interactive
