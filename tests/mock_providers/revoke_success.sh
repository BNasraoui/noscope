#!/bin/sh
set -eu

# Identifier-only revoke contract (res_revoke_contract_identifier_only):
# the provider receives NOSCOPE_TOKEN_ID and never the credential value.
if [ -n "${NOSCOPE_TOKEN:-}" ]; then
  printf 'unexpected NOSCOPE_TOKEN in revoke env\n' >&2
  exit 2
fi

if [ -z "${NOSCOPE_TOKEN_ID:-}" ]; then
  printf 'missing NOSCOPE_TOKEN_ID\n' >&2
  exit 2
fi

printf 'revoked %s\n' "$NOSCOPE_TOKEN_ID" >&2
exit 0
