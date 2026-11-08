#!/bin/sh
set -eu

branch=$(gh api "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA/pulls" \
    --jq '[.[] | select(.merged_at != null) | .head.ref] | first // ""')

case "$branch" in
    release-plz-*) echo "release=true" >> "$GITHUB_OUTPUT" ;;
    *) echo "release=false" >> "$GITHUB_OUTPUT" ;;
esac
