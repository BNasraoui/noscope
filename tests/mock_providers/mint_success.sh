#!/bin/sh
set -eu

expires_at="2099-01-01T00:00:00Z"
token_id="tok-${NOSCOPE_PROVIDER:-mock}"
printf '{"token":"mint-%s-%s","expires_at":"%s","token_id":"%s"}\n' "${NOSCOPE_PROVIDER:-mock}" "${NOSCOPE_ROLE:-role}" "$expires_at" "$token_id"
