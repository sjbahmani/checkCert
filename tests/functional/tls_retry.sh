#!/usr/bin/env bash
# Offline integration checks for transient and permanent TLS retry failures.
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
check="$script_dir/../../checkCRT.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin"
cp "$script_dir/tls_retry_wrapper.sh" "$scratch/bin/openssl"
cp "$script_dir/retry_sleep.sh" "$scratch/bin/sleep"
chmod +x "$scratch/bin/openssl" "$scratch/bin/sleep"
export CHECKCRT_TEST_TLS_OPENSSL
CHECKCRT_TEST_TLS_OPENSSL=$(command -v openssl)
export CHECKCRT_TEST_TLS_LOG="$scratch/tls.log"
export CHECKCRT_TEST_SLEEP_LOG="$scratch/sleep.log"
for failure in temporary permanent; do
    : > "$CHECKCRT_TEST_TLS_LOG"
    : > "$CHECKCRT_TEST_SLEEP_LOG"
    if env PATH="$scratch/bin:$PATH" CHECKCRT_TEST_TLS_FAILURE="$failure" \
        "$check" --no-cache --no-caa --connect-retries 3 --retry-delay 1 \
        example.invalid > "$scratch/out" 2> "$scratch/err"; then actual=0
    else actual=$?; fi
    expected_attempts=4 expected_delays='1,1,2'
    [[ "$failure" != permanent ]] || { expected_attempts=1; expected_delays=''; }
    if [[ "$actual" != 3 || $(wc -l < "$CHECKCRT_TEST_TLS_LOG") != "$expected_attempts" \
        || $(paste -sd, "$CHECKCRT_TEST_SLEEP_LOG") != "$expected_delays" ]]; then
        echo "FAIL: TLS $failure retry count/delays/status" >&2
        cat "$scratch/err" >&2
        exit 1
    fi
    if [[ "$failure" == temporary ]]; then
        grep -q 'TLS connection failed; retry 3/3 in 2s' "$scratch/err"
    fi
    echo "PASS: TLS $failure retry count, backoff, and failure status"
done
