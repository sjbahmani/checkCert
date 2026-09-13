#!/usr/bin/env bash
# Record requested retry waits without delaying deterministic fixture tests.
set -euo pipefail
printf '%s\n' "$1" >> "$CHECKCRT_TEST_SLEEP_LOG"
