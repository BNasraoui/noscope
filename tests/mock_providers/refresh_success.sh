#!/bin/sh
set -eu

expires_at="2099-01-01T01:00:00Z"
printf '{"token":"refresh-%s","expires_at":"%s","token_id":"%s"}\n' "${NOSCOPE_PROVIDER:-mock}" "$expires_at" "${NOSCOPE_TOKEN_ID:-tok-mock}"
