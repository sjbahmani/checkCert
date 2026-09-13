#!/usr/bin/env bash
# Isolate retry policy from network timing; all certificate operations stay real.
set -euo pipefail
if [[ "$1" == s_client ]]; then
    printf 'attempt\n' >> "$CHECKCRT_TEST_TLS_LOG"
    if [[ "$CHECKCRT_TEST_TLS_FAILURE" == temporary ]]; then
        echo 'connect:errno=111' >&2
    else
        echo 'SSL routines:ssl3_get_record:wrong version number' >&2
    fi
    exit 1
fi
exec "$CHECKCRT_TEST_TLS_OPENSSL" "$@"
