#!/usr/bin/env bash
# Test-only curl/wget shim: record actual fetches and simulate HTTP outages.
# run.sh installs it under the available client's name in a temporary PATH.
set -euo pipefail
printf '%s\n' "${!#}" >> "$CHECKCRT_TEST_FETCH_LOG"
if [[ -e "$CHECKCRT_TEST_OFFLINE" ]]; then
    echo 'Simulated CRL/AIA HTTP outage' >&2
    exit 22
fi
if [[ -n "${CHECKCRT_TEST_FETCH_DELAY:-}" ]]; then
    sleep "$CHECKCRT_TEST_FETCH_DELAY"
fi
exec "$CHECKCRT_TEST_FETCH_BIN" "$@"
