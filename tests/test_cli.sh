#!/usr/bin/env bash
# Lightweight offline regression tests for command-line behavior.
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
script="$project_root/checkCRT.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

expect_exit() {
    local expected=$1
    shift
    set +e
    "$@" >"$scratch/stdout" 2>"$scratch/stderr"
    local actual=$?
    set -e
    [[ $actual -eq $expected ]] || {
        echo "Expected exit $expected, got $actual: $*" >&2
        cat "$scratch/stderr" >&2
        exit 1
    }
}

expect_exit 0 "$script" --help
grep -q -- '--json' "$scratch/stdout"
expect_exit 0 "$script" --version
grep -q '^checkCRT.sh 1\.10\.1$' "$scratch/stdout"
expect_exit 1 "$script" --connect-timeout 0 example.com
grep -q 'positive number' "$scratch/stderr"
expect_exit 1 "$script" --ca-file "$scratch/missing.pem" example.com
grep -q 'CA file is not readable' "$scratch/stderr"
expect_exit 1 "$script" --expiry-warn-days -5 example.com
grep -q 'non-negative number of days' "$scratch/stderr"
expect_exit 0 "$script" --help
grep -q -- '--starttls' "$scratch/stdout"
grep -q -- '--expiry-warn-days' "$scratch/stdout"
grep -q -- '--no-caa' "$scratch/stdout"
grep -q -- '--parallel' "$scratch/stdout"
expect_exit 1 "$script" --parallel 0 example.com
grep -q 'positive integer' "$scratch/stderr"
expect_exit 1 "$script" --parallel not-a-number example.com
grep -q 'positive integer' "$scratch/stderr"

echo 'CLI regression tests passed.'
