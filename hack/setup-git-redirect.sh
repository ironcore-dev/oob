#!/bin/sh
set -e

if [ -f "$GITHUB_PAT_PATH" ]; then
  echo "Sourcing Github PAT from path"
  GITHUB_PAT="$(cat "$GITHUB_PAT_PATH")"
fi

if [ "$GITHUB_PAT" != "" ]; then
  echo "Rewriting to use Github PAT"
  git config --global url."https://${GITHUB_PAT}:x-oauth-basic@github.com/".insteadOf "https://github.com/"
else
  echo "No Github PAT given, rewriting to use plain ssh auth"
  git config --global url."git@github.com:".insteadOf "https://github.com"
fi
