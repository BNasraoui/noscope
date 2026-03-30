#!/bin/sh
set -eu

if [ -z "${NOSCOPE_TOKEN:-}" ]; then
  printf 'missing NOSCOPE_TOKEN\n' >&2
  exit 2
fi

if [ -z "${NOSCOPE_TOKEN_ID:-}" ]; then
  printf 'missing NOSCOPE_TOKEN_ID\n' >&2
  exit 2
fi

printf 'revoked %s\n' "$NOSCOPE_TOKEN_ID" >&2
exit 0
