#!/usr/bin/env bash
# Shift only the checker's notion of "now"; signed DER remains unmodified.
set -euo pipefail
if [[ $# == 2 && $1 == -u && $2 == +%s ]]; then
    now=$("$CHECKCRT_REAL_DATE" -u +%s)
    printf '%s\n' "$((now + CHECKCRT_CLOCK_OFFSET))"
else
    exec "$CHECKCRT_REAL_DATE" "$@"
fi
