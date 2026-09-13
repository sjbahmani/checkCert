#!/usr/bin/env bash
# Test OpenSSL 3.0's CRL verification exit behavior using real crypto on any
# installed version. All other operations preserve their native exit status.
set -uo pipefail
if [[ "${1:-}" == crl && " $* " == *' -verify '* ]]; then
    output=$("$CHECKCRT_TEST_OPENSSL_BIN" "$@" 2>&1)
    result=$?
    printf '%s\n' "$output" >&2
    if grep -Fxq 'verify failure' <<< "$output"; then
        printf 'legacy CRL verification failure returned 0\n' >> "$CHECKCRT_TEST_LEGACY_LOG"
        exit 0
    fi
    exit "$result"
fi
exec "$CHECKCRT_TEST_OPENSSL_BIN" "$@"
