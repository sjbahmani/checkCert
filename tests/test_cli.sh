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
grep -q -- '--summary-only' "$scratch/stdout"
grep -q -- '--connect-ip' "$scratch/stdout"
grep -q -- '--cache-dir' "$scratch/stdout"
grep -q -- '--cache-max-age' "$scratch/stdout"
grep -q -- '--cache-max-age .*default: 14400;' "$scratch/stdout"
grep -q -- '--no-cache' "$scratch/stdout"
expect_exit 0 "$script" --version
grep -q '^checkCRT.sh 1\.14\.0$' "$scratch/stdout"
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
expect_exit 1 "$script" --summary-only --connect-timeout 0 example.com
grep -q 'positive number' "$scratch/stderr"

expect_exit 1 "$script" --connect-ip
grep -q -- '--connect-ip requires a value' "$scratch/stderr"
for invalid_ip in '' backend.test https://127.0.0.1 127.0.0.1:443 127.0.0.1/24 \
    256.1.1.1 127.1 01.2.3.4 '[127.0.0.1]' ':::' '1::2::3' ':1::' '::1:' \
    '1:2:3:4:5:6:7' '1:2:3:4:5:6:7:8:9' '1:2:3:4:5:6:7:8::' \
    '12345::1' 'gggg::1' 'fe80::1%eth0' '[::1]:443' '::ffff:999.1.1.1'; do
    expect_exit 1 "$script" "--connect-ip=$invalid_ip" backend.test
    grep -q -- '--connect-ip requires an IPv4 or IPv6 address' "$scratch/stderr"
done
# A missing CA file stops before networking, after IP validation succeeds.
for valid_ip in 127.0.0.1 0.0.0.0 255.255.255.255 '::' '::1' '[::1]' \
    '2001:db8::' '2001:db8:0:1:2:3:4:5' '1:2:3:4:5:6:7::' \
    '::ffff:192.0.2.1' '0:0:0:0:0:ffff:192.0.2.1'; do
    expect_exit 1 "$script" --connect-ip "$valid_ip" --ca-file "$scratch/missing.pem" backend.test
    grep -q 'CA file is not readable' "$scratch/stderr"
done

for option in --cache-dir --cache-max-age; do
    expect_exit 1 "$script" "$option"
    grep -q -- "$option requires a value" "$scratch/stderr"
done
for invalid_age in '' 0 -1 text 1.5 9999999999; do
    expect_exit 1 "$script" "--cache-max-age=$invalid_age" example.com
    grep -q -- '--cache-max-age must be a positive integer' "$scratch/stderr"
done
expect_exit 1 "$script" --cache-dir= example.com
grep -q -- '--cache-dir requires a non-empty directory path' "$scratch/stderr"
expect_exit 1 "$script" --cache-dir "$scratch/stdout" example.com
grep -q -- '--cache-dir must be a readable/writable directory' "$scratch/stderr"
mkdir "$scratch/shared-cache"
chmod 777 "$scratch/shared-cache"
expect_exit 1 "$script" --cache-dir "$scratch/shared-cache" example.com
grep -q -- '--cache-dir must not be group- or world-writable' "$scratch/stderr"
ln -s "$scratch/shared-cache" "$scratch/link-cache"
expect_exit 1 "$script" --cache-dir "$scratch/link-cache///" example.com
grep -q -- '--cache-dir must be a readable/writable directory' "$scratch/stderr"

echo 'CLI regression tests passed.'
