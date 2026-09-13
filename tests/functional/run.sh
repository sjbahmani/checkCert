#!/usr/bin/env bash
# End-to-end regression tests for checkCRT.sh against a local, throwaway PKI
# (see setup_pki.sh). Starts a local HTTP file server (CRL/AIA fetches) and
# several openssl s_server TLS endpoints on 127.0.0.1, runs checkCRT.sh
# against each, and asserts the expected exit code / behavior. Requires
# permission to bind local TCP ports (127.0.0.1 only).
set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd "$script_dir/../.." && pwd)
check="$project_root/checkCRT.sh"

for dependency in jq busybox; do
    command -v "$dependency" >/dev/null 2>&1 || {
        echo "Error: functional tests require '$dependency'; see README.md (Development)." >&2
        exit 1
    }
done
if ! busybox httpd --help >/dev/null 2>&1; then
    echo "Error: functional tests require BusyBox with httpd (e.g. busybox-static)." >&2
    exit 1
fi

HTTPPORT=8990
GOOD_PORT=8991
REVOKED_PORT=8992
LEAF3_PORT=8993
AIA_PORT=8994
OCSP_PURPOSE_PORT=8995
SNI_PORT=8996
IPV6_PORT=8997
CROSS_PORT=8998

export HTTPPORT
PKI_DIR=$(bash "$script_dir/setup_pki.sh")
pids=()

cleanup() {
    for pid in "${pids[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
    for pid in "${pids[@]:-}"; do wait "$pid" >/dev/null 2>&1 || true; done
    rm -rf "$PKI_DIR"
}
trap cleanup EXIT

start_server() {
    local port=$1 cert=$2 chain=${3:-} bind_host=${4:-127.0.0.1}
    local key="${cert/\/certs\//\/private\/}"
    key="${key%.pem}.key"
    [[ "$bind_host" == *:* ]] && bind_host="[$bind_host]"
    local -a args=(-accept "$bind_host:$port" -cert "$cert" -key "$key" -naccept 100 -quiet)
    [[ -n "$chain" ]] && args+=(-cert_chain "$chain")
    openssl s_server "${args[@]}" >"$PKI_DIR/s_server-$port.log" 2>&1 &
    pids+=($!)
}

busybox httpd -f -p "127.0.0.1:$HTTPPORT" -h "$PKI_DIR/www" -c /dev/null >"$PKI_DIR/httpd.log" 2>&1 &
pids+=("$!")

# leaf-good served with its full chain (intermediate)
start_server "$GOOD_PORT" "$PKI_DIR/certs/leaf-good.pem" "$PKI_DIR/chain-good.pem"
start_server "$CROSS_PORT" "$PKI_DIR/certs/leaf-good.pem" "$PKI_DIR/chain-cross.pem"
# leaf-revoked served with its full chain
start_server "$REVOKED_PORT" "$PKI_DIR/certs/leaf-revoked.pem" "$PKI_DIR/chain-good.pem"
# leaf3 served with its full chain (intermediate2 + root) — intermediate2 gets revoked
start_server "$LEAF3_PORT" "$PKI_DIR/certs/leaf3.pem" "$PKI_DIR/chain3.pem"
# leaf-good served ALONE (no chain) to force AIA-based issuer recovery
start_server "$AIA_PORT" "$PKI_DIR/certs/leaf-good.pem"
# leaf-ocsp-purpose: wrong EKU (no serverAuth), exercises the -status retry
start_server "$OCSP_PURPOSE_PORT" "$PKI_DIR/certs/leaf-ocsp-purpose.pem" "$PKI_DIR/chain-good.pem"

# Only SNI=backend.test selects the good leaf; no/wrong SNI gets the revoked
# leaf. This verifies the actual ClientHello, not just command-line arguments.
openssl s_server -accept "127.0.0.1:$SNI_PORT" -quiet -naccept 20 \
    -cert "$PKI_DIR/certs/leaf-revoked.pem" -key "$PKI_DIR/private/leaf-revoked.key" \
    -cert2 "$PKI_DIR/certs/leaf-good.pem" -key2 "$PKI_DIR/private/leaf-good.key" \
    -cert_chain "$PKI_DIR/chain-good.pem" -servername backend.test >"$PKI_DIR/s_server-$SNI_PORT.log" 2>&1 &
pids+=("$!")
start_server "$IPV6_PORT" "$PKI_DIR/certs/leaf-good.pem" "$PKI_DIR/chain-good.pem" ::1

sleep 1
for p in "$HTTPPORT" "$GOOD_PORT" "$REVOKED_PORT" "$LEAF3_PORT" "$AIA_PORT" "$OCSP_PURPOSE_PORT" "$SNI_PORT" "$CROSS_PORT"; do
    timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/$p" 2>/dev/null || {
        echo "FAIL: server on port $p did not come up" >&2
        exit 1
    }
done
ipv6_available=0
if timeout 3 bash -c "echo > /dev/tcp/::1/$IPV6_PORT" 2>/dev/null; then ipv6_available=1; fi

pass=0
fail=0
check_exit() {
    local desc=$1 expected=$2
    shift 2
    local actual
    "$@" >/tmp/functest.out 2>/tmp/functest.err
    actual=$?
    if [[ "$actual" == "$expected" ]]; then
        echo "PASS: $desc (exit $actual)"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc (expected exit $expected, got $actual)"
        echo "  --- stderr tail ---"
        tail -15 /tmp/functest.err | sed 's/^/  /'
        fail=$((fail + 1))
    fi
}

check_exit "leaf-good: full chain presented -> VALID" 0 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$GOOD_PORT"
sed -n '/^FINAL STATUS$/,$p' /tmp/functest.out > "$PKI_DIR/good-final.txt"

check_exit "leaf-revoked: full chain presented -> REVOKED" 2 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$REVOKED_PORT"
sed -n '/^FINAL STATUS$/,$p' /tmp/functest.out > "$PKI_DIR/revoked-final.txt"

check_exit "leaf3: fine itself, but issuing intermediate2 is revoked -> REVOKED" 2 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$LEAF3_PORT"
if grep -q "intermediate CA .* is REVOKED" /tmp/functest.err; then
    echo "PASS: intermediate-revocation warning present"
    pass=$((pass + 1))
else
    echo "FAIL: intermediate-revocation warning missing"
    fail=$((fail + 1))
fi

check_exit "leaf-good served alone (no chain): AIA-recovered issuer -> VALID" 0 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$AIA_PORT"

# leaf-ocsp-purpose always presents the same (wrong-purpose) cert regardless
# of -status, so the retry fires, detects it's still wrong, and correctly
# falls back to reporting an untrusted/invalid-purpose result (exit 5) —
# this exercises the retry code path without requiring a server that
# actually changes certs based on OCSP-stapling requests, as msn.com's does.
check_exit "leaf-ocsp-purpose: wrong EKU triggers retry, still wrong -> exit 5" 5 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$OCSP_PURPOSE_PORT"
if grep -q "unexpected purpose" /tmp/functest.out && grep -q "still returned an unexpected certificate purpose" /tmp/functest.err; then
    echo "PASS: OCSP-stapling retry fallback triggered and handled correctly"
    pass=$((pass + 1))
else
    echo "FAIL: OCSP-stapling retry fallback did not trigger as expected"
    fail=$((fail + 1))
fi

# --hosts-file batch mode: one good, one revoked -> overall exit 1
cat > "$PKI_DIR/hosts.txt" <<EOF
127.0.0.1 $GOOD_PORT
127.0.0.1 $REVOKED_PORT
EOF
check_exit "batch mode: mixed good+revoked hosts -> exit 1" 1 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" --hosts-file "$PKI_DIR/hosts.txt"
{
    echo
    sed -n '/^BATCH SUMMARY /,$p' /tmp/functest.out
} > "$PKI_DIR/batch-summary.txt"

# --parallel N: same aggregate result whether sequential (1) or concurrent (3),
# with a repeated host list so real parallelism actually kicks in.
cat > "$PKI_DIR/hosts-repeated.txt" <<EOF
127.0.0.1 $GOOD_PORT
127.0.0.1 $REVOKED_PORT
127.0.0.1 $GOOD_PORT
127.0.0.1 $REVOKED_PORT
EOF
check_exit "--parallel 3: repeated good+revoked hosts -> exit 1" 1 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" --parallel 3 --hosts-file "$PKI_DIR/hosts-repeated.txt"
if [[ $(grep -c '^  VALID ' /tmp/functest.out) == 2 && $(grep -c '^  REVOKED ' /tmp/functest.out) == 2 ]]; then
    echo "PASS: --parallel 3 grouped summary counts are correct"
    pass=$((pass + 1))
else
    echo "FAIL: --parallel 3 grouped summary counts are wrong"
    fail=$((fail + 1))
fi

check_exit "--parallel 1 (sequential): same hosts -> exit 1" 1 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" --parallel 1 --hosts-file "$PKI_DIR/hosts-repeated.txt"
if [[ $(grep -c '^  VALID ' /tmp/functest.out) == 2 && $(grep -c '^  REVOKED ' /tmp/functest.out) == 2 ]]; then
    echo "PASS: --parallel 1 grouped summary counts are correct"
    pass=$((pass + 1))
else
    echo "FAIL: --parallel 1 grouped summary counts are wrong"
    fail=$((fail + 1))
fi

assert_output() {
    local desc=$1
    shift
    if "$@"; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc"
        fail=$((fail + 1))
    fi
}

json_matches() {
    jq -e -s "$1" "$2" >/dev/null
}

same_final_status() {
    diff -u <(sed '/^  ELAPSED:/d' "$1") <(sed '/^  ELAPSED:/d' "$2")
}

stable_batch_columns() {
    # Timing and which parallel worker wins the cache lock may vary. Strip
    # elapsed time and counters, retaining days left and all other fields.
    awk '
        /^ *[- ]+$/ { next }
        {
            sub(/[0-9]+\.[0-9]s [0-9]+\/[0-9]+/, "")
            gsub(/ +/, " ")
            print
        }
    ' "$1"
}

same_batch_status() {
    diff -u <(stable_batch_columns "$1") <(stable_batch_columns "$2")
}

# Compare the entire concise output with the corresponding portion of the
# full report, excluding timing: catch leaked progress and lost fields.
check_exit "--summary-only: good leaf keeps exit 0" 0 \
    "$check" --summary-only --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$GOOD_PORT"
assert_output "single-host summary matches the full final status apart from timing" \
    same_final_status "$PKI_DIR/good-final.txt" /tmp/functest.out
assert_output "single-host summary includes elapsed seconds" \
    grep -Eq '^  ELAPSED: [0-9]+\.[0-9]s$' /tmp/functest.out
assert_output "single-host summary counts its fresh CRL" \
    grep -qx '  CACHE: 0 hit / 1 miss' /tmp/functest.out
assert_output "single-host summary suppresses diagnostics" test ! -s /tmp/functest.err

check_exit "--summary-only: revoked leaf keeps exit 2" 2 \
    "$check" --summary-only --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$REVOKED_PORT"
assert_output "revoked summary matches the full final status apart from timing" \
    same_final_status "$PKI_DIR/revoked-final.txt" /tmp/functest.out
assert_output "revoked summary suppresses diagnostics" test ! -s /tmp/functest.err

for parallel in 1 3; do
    check_exit "--summary-only --parallel $parallel: mixed batch keeps exit 1" 1 \
        "$check" --summary-only --parallel "$parallel" --ca-file "$PKI_DIR/certs/root.pem" \
        --hosts-file "$PKI_DIR/hosts.txt"
    assert_output "batch summary ($parallel workers) preserves the other table columns" \
        same_batch_status "$PKI_DIR/batch-summary.txt" /tmp/functest.out
    assert_output "batch summary ($parallel workers) has one compact metrics column" \
        grep -q 'ISSUER  *DL TIME H/M  *REASON' /tmp/functest.out
    assert_output "batch summary ($parallel workers) has one cache miss" \
        test "$(grep -Ec '[0-9]+\.[0-9]s 0/1  ' /tmp/functest.out)" -eq 1
    assert_output "batch summary ($parallel workers) has one cache hit" \
        test "$(grep -Ec '[0-9]+\.[0-9]s 1/0  ' /tmp/functest.out)" -eq 1
    assert_output "batch summary ($parallel workers) suppresses diagnostics" test ! -s /tmp/functest.err
done

# The HTTP fixture cannot negotiate TLS, giving a deterministic early error.
check_exit "--summary-only: connection error remains visible and exits 3" 3 \
    "$check" --summary-only --connect-timeout 1 --connect-retries 0 127.0.0.1 "$HTTPPORT"
assert_output "connection error has a final status" grep -qx 'FINAL STATUS' /tmp/functest.out
assert_output "connection error is not mistaken for an invalid certificate" \
    grep -qx '  TRUST: UNKNOWN' /tmp/functest.out
assert_output "connection error overall status" grep -qx '  OVERALL: ERROR' /tmp/functest.out
assert_output "connection error includes the failure reason" \
    grep -q '^  REASON: unable to connect' /tmp/functest.out
assert_output "connection error summary suppresses diagnostics" test ! -s /tmp/functest.err
assert_output "connection error includes elapsed seconds" \
    grep -Eq '^  ELAPSED: [0-9]+\.[0-9]s$' /tmp/functest.out
assert_output "connection error has zero cache events" \
    grep -qx '  CACHE: 0 hit / 0 miss' /tmp/functest.out

# Early errors have no issuer/days fields; their metrics must survive the
# parallel result file and must not inherit a previous host's counters.
printf '127.0.0.1 %s\n127.0.0.1 %s\n127.0.0.1 65536\n' \
    "$GOOD_PORT" "$HTTPPORT" > "$PKI_DIR/hosts-metrics-errors.txt"
for parallel in 1 3; do
    check_exit "batch metrics survive early errors ($parallel workers)" 1 \
        "$check" --no-caa --summary-only --connect-retries 0 --connect-timeout 1 \
        --parallel "$parallel" --ca-file "$PKI_DIR/certs/root.pem" --hosts-file "$PKI_DIR/hosts-metrics-errors.txt"
    assert_output "error rows have zero hits/misses ($parallel workers)" \
        test "$(grep -Ec '^  ERROR .* [0-9]+\.[0-9]s 0/0  ' /tmp/functest.out)" -eq 2
    assert_output "healthy row retains its own counters ($parallel workers)" \
        grep -Eq '^  VALID .* [0-9]+\.[0-9]s 0/1  ' /tmp/functest.out
done

check_exit "JSON baseline: good leaf" 0 \
    "$check" --json --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$GOOD_PORT"
cp /tmp/functest.out "$PKI_DIR/good.json"
check_exit "--json --summary-only: good leaf" 0 \
    "$check" --json --summary-only --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$GOOD_PORT"
assert_output "summary flag preserves JSON fields apart from elapsed time" \
    diff -u <(jq -S 'del(.elapsed_seconds)' "$PKI_DIR/good.json") <(jq -S 'del(.elapsed_seconds)' /tmp/functest.out)
assert_output "JSON includes numeric elapsed seconds and host cache counts" \
    json_matches 'all(.[]; (.elapsed_seconds | type == "number" and . >= 0) and .cache_hits == 0 and .cache_misses == 1)' /tmp/functest.out
assert_output "JSON summary suppresses diagnostics" test ! -s /tmp/functest.err

check_exit "invalid port keeps a valid JSON error record" 3 \
    "$check" --json --summary-only 127.0.0.1 not-a-port
assert_output "invalid port JSON retains metrics and the rejected value" \
    json_matches 'length == 1 and (.[0] | .port == null and .error == "invalid port: not-a-port" and .cache_hits == 0 and .cache_misses == 0 and .elapsed_seconds >= 0)' /tmp/functest.out
check_exit "zero-padded port is treated as decimal" 0 \
    "$check" --no-caa --json --summary-only --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "00$GOOD_PORT"
assert_output "zero-padded port produces a canonical JSON number" \
    json_matches "length == 1 and (.[0] | .port == $GOOD_PORT and .overall == \"VALID\")" /tmp/functest.out

check_exit "--summary-only --json: parallel mixed batch keeps exit 1" 1 \
    "$check" --summary-only --json --parallel 3 --ca-file "$PKI_DIR/certs/root.pem" \
    --hosts-file "$PKI_DIR/hosts.txt"
assert_output "JSON batch contains exactly one complete record per host" \
    json_matches '
        length == 2
        and (map([.overall, .exit_code]) | sort == [["REVOKED", 2], ["VALID", 0]])
        and all(.[];
            (.warnings | type == "array" and length > 0)
            and (.reason | type == "string" and length > 0))
    ' /tmp/functest.out
assert_output "JSON batch summary suppresses diagnostics" test ! -s /tmp/functest.err

check_exit "--summary-only --json: connection error keeps its error record" 3 \
    "$check" --summary-only --json --connect-timeout 1 --connect-retries 0 127.0.0.1 "$HTTPPORT"
assert_output "JSON error record remains parseable and includes the reason" \
    json_matches '
        length == 1
        and (.[0] | .overall == "ERROR" and .exit_code == 3
            and (.error | type == "string" and length > 0))
    ' /tmp/functest.out
assert_output "JSON connection error summary suppresses diagnostics" test ! -s /tmp/functest.err

# backend.test has no public DNS record. These requests must use the override,
# while the certificate and SNI checks must still use backend.test.
check_exit "--connect-ip preserves SNI and hostname identity" 0 \
    "$check" --connect-ip 127.0.0.1 --json --summary-only --no-caa \
    --ca-file "$PKI_DIR/certs/root.pem" backend.test "$SNI_PORT"
assert_output "JSON identifies the original hostname and backend separately" \
    json_matches 'length == 1 and (.[0] | .host == "backend.test"
        and .connect_ip == "127.0.0.1" and .trust == "TRUSTED"
        and .revocation == "NOT REVOKED" and .overall == "VALID")' /tmp/functest.out

check_exit "--connect-ip does not bypass a hostname mismatch" 5 \
    "$check" --connect-ip=127.0.0.1 --json --summary-only --no-caa \
    --ca-file "$PKI_DIR/certs/root.pem" wrong-name.test "$GOOD_PORT"
assert_output "hostname mismatch refers to the requested name" \
    json_matches 'length == 1 and (.[0] | .host == "wrong-name.test"
        and .connect_ip == "127.0.0.1" and .trust == "UNTRUSTED/INVALID"
        and (.reason | contains("wrong-name.test")))' /tmp/functest.out

check_exit "--connect-ip keeps IP identity checks tied to the original IP" 5 \
    "$check" --connect-ip 127.0.0.1 --summary-only --no-caa \
    --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.2 "$GOOD_PORT"
assert_output "text summary shows the overridden address" \
    grep -qx '  CONNECT IP: 127.0.0.1' /tmp/functest.out
assert_output "text summary explains the original IP mismatch" \
    grep -q '  REASON: .*127.0.0.2' /tmp/functest.out

printf 'backend.test %s\nwrong-name.test %s\n' "$GOOD_PORT" "$GOOD_PORT" > "$PKI_DIR/hosts-backend.txt"
for parallel in 1 3; do
    check_exit "--connect-ip: batch identity is preserved ($parallel workers)" 1 \
        "$check" --connect-ip 127.0.0.1 --json --summary-only --no-caa --parallel "$parallel" \
        --ca-file "$PKI_DIR/certs/root.pem" --hosts-file "$PKI_DIR/hosts-backend.txt"
    assert_output "batch records retain each requested hostname ($parallel workers)" \
        json_matches 'length == 2 and all(.[]; .connect_ip == "127.0.0.1")
            and (map([.host, .exit_code]) | sort == [["backend.test", 0], ["wrong-name.test", 5]])' /tmp/functest.out
done

check_exit "--connect-ip: connection errors identify the backend" 3 \
    "$check" --connect-ip 127.0.0.1 --json --summary-only --no-caa \
    --connect-timeout 1 --connect-retries 0 backend.test "$HTTPPORT"
assert_output "JSON connection error retains the original hostname and override" \
    json_matches 'length == 1 and (.[0] | .host == "backend.test"
        and .connect_ip == "127.0.0.1" and .overall == "ERROR" and .exit_code == 3)' /tmp/functest.out

if (( ipv6_available == 1 )); then
    for ipv6_address in '::1' '[::1]'; do
        check_exit "--connect-ip $ipv6_address: IPv6 backend with DNS identity" 0 \
            "$check" --connect-ip "$ipv6_address" --json --summary-only --no-caa \
            --ca-file "$PKI_DIR/certs/root.pem" backend.test "$IPV6_PORT"
        assert_output "IPv6 override is reported without brackets" \
            json_matches 'length == 1 and (.[0] | .host == "backend.test"
                and .connect_ip == "::1" and .overall == "VALID")' /tmp/functest.out
    done
else
    echo 'SKIP: IPv6 backend checks (IPv6 loopback unavailable).'
fi

# Count real HTTP requests, rather than trusting cache diagnostic messages.
# The wrapper still calls the actual client against the local HTTP fixture.
if command -v curl >/dev/null 2>&1; then cache_client=curl; else cache_client=wget; fi
export CHECKCRT_TEST_FETCH_BIN
CHECKCRT_TEST_FETCH_BIN=$(command -v "$cache_client")
export CHECKCRT_TEST_FETCH_LOG="$PKI_DIR/fetch.log"
export CHECKCRT_TEST_OFFLINE="$PKI_DIR/offline"
mkdir "$PKI_DIR/fetch-bin"
cp "$script_dir/fetch_wrapper.sh" "$PKI_DIR/fetch-bin/$cache_client"
chmod +x "$PKI_DIR/fetch-bin/$cache_client"
export PATH="$PKI_DIR/fetch-bin:$PATH"
cache_args=(--no-caa --connect-retries 0 --retry-delay 0 --ca-file "$PKI_DIR/certs/root.pem")
printf '127.0.0.1 %s\n127.0.0.1 %s\n127.0.0.1 %s\n' \
    "$AIA_PORT" "$AIA_PORT" "$AIA_PORT" > "$PKI_DIR/hosts-cache.txt"

fetch_count_is() {
    local actual
    actual=$(wc -l < "$CHECKCRT_TEST_FETCH_LOG")
    if [[ "$actual" -eq "$1" ]]; then return 0; fi
    printf '  Expected %s HTTP requests, got %s:\n' "$1" "$actual"
    sed 's/^/    /' "$CHECKCRT_TEST_FETCH_LOG"
    return 1
}
seed_cache() {
    local destination=$1 source=$2 timestamp=${3:-$(date -u +%s)}
    { printf '# checkCRT-cache-v1 %s\n' "$timestamp"; cat "$source"; } > "$destination"
}

# Trust can end at the local self-signed root while the server presents a
# cross-signed copy. Its absent legacy issuer cannot verify its own CRL.
for cross_mode in cold warm disabled; do
    cross_args=(--cache-dir "$PKI_DIR/cross-cache")
    cross_fetches=1 cross_hits=0 cross_misses=1
    if [[ "$cross_mode" == warm ]]; then
        cross_fetches=0 cross_hits=1 cross_misses=0
    elif [[ "$cross_mode" == disabled ]]; then
        cross_args+=(--no-cache)
        cross_misses=0
    fi
    : > "$CHECKCRT_TEST_FETCH_LOG"
    check_exit "missing cross-signer preserves the trusted alternate path ($cross_mode)" 0 \
        "$check" "${cache_args[@]}" "${cross_args[@]}" --json 127.0.0.1 "$CROSS_PORT"
    assert_output "missing cross-signer never causes an unusable CRL download ($cross_mode)" \
        fetch_count_is "$cross_fetches"
    assert_output "cross-signed root reports its missing issuer ($cross_mode)" \
        grep -q 'issuer certificate unavailable; skipping CRL download' /tmp/functest.err
    assert_output "cross-signed root CRL does not generate a signature failure ($cross_mode)" \
        test "$(grep -c 'CRL signature could not be verified' /tmp/functest.err)" -eq 0
    assert_output "skipped cross-signed root CRL does not count as a cache event ($cross_mode)" \
        json_matches "length == 1 and (.[0] | .cache_hits == $cross_hits and .cache_misses == $cross_misses and .overall == \"VALID\")" /tmp/functest.out
done

for parallel in 1 3; do
    : > "$CHECKCRT_TEST_FETCH_LOG"
    check_exit "run cache: repeated AIA-only hosts ($parallel workers)" 0 \
        "$check" "${cache_args[@]}" --json --parallel "$parallel" --hosts-file "$PKI_DIR/hosts-cache.txt"
    assert_output "run cache downloads AIA and CRL just once ($parallel workers)" fetch_count_is 2
    assert_output "cache diagnostics do not leak into JSON ($parallel workers)" \
        json_matches 'length == 3 and all(.[]; .overall == "VALID" and .revocation == "NOT REVOKED")' /tmp/functest.out
    assert_output "cache counters belong to each host ($parallel workers)" \
        json_matches 'all(.[]; .cache_hits + .cache_misses == 2 and .elapsed_seconds >= 0) and ([.[].cache_hits] | add) == 4 and ([.[].cache_misses] | add) == 2' /tmp/functest.out
    assert_output "JSON diagnostics identify per-run cache mode ($parallel workers)" \
        grep -q '^Cache mode: PER-RUN (max age: 86400s)$' /tmp/functest.err
    assert_output "JSON diagnostics explicitly report reused evidence ($parallel workers)" \
        grep -q 'Cache HIT (CRL): USED verified cached download' /tmp/functest.err
done

: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "--no-cache bypasses reads/writes even with --cache-dir" 0 \
    "$check" "${cache_args[@]}" --no-cache --cache-dir "$PKI_DIR/unused-cache" \
    --parallel 3 --hosts-file "$PKI_DIR/hosts-cache.txt"
assert_output "uncached repeated hosts each download their own AIA and CRL" fetch_count_is 6
assert_output "--no-cache does not create a persistent directory" test ! -e "$PKI_DIR/unused-cache"
assert_output "disabled caching counts neither hits nor misses for each host" \
    test "$(grep -cx '  CACHE: 0 hit / 0 miss' /tmp/functest.out)" -eq 3
assert_output "disabled cache mode is logged" grep -q '^Cache mode: DISABLED (--no-cache)$' /tmp/functest.out
assert_output "uncached CRL download is explicitly logged" \
    grep -q 'Cache BYPASS (CRL): NOT USED; disabled by --no-cache' /tmp/functest.out
assert_output "uncached AIA download is explicitly logged" \
    grep -q 'Cache BYPASS (AIA): NOT USED; disabled by --no-cache' /tmp/functest.out
assert_output "disabled cache is not reported as a hit or miss" \
    test "$(grep -Ec 'Cache (HIT|MISS)' /tmp/functest.out)" = 0

persistent_cache="$PKI_DIR/persistent cache"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "persistent cache: populate from AIA and CRL downloads" 0 \
    "$check" "${cache_args[@]}" --cache-dir="$persistent_cache" --cache-max-age=3600 127.0.0.1 "$AIA_PORT"
assert_output "cold persistent cache downloads both objects" fetch_count_is 2
assert_output "persistent cache mode includes the chosen directory" \
    grep -Fxq "Cache mode: PERSISTENT (max age: 3600s; directory: $persistent_cache)" /tmp/functest.out
assert_output "cold CRL cache is explicitly logged as not used" \
    grep -q 'Cache MISS (CRL): NOT USED; no fresh verified entry' /tmp/functest.out
assert_output "cold AIA cache is explicitly logged as not used" \
    grep -q 'Cache MISS (AIA): NOT USED; no fresh verified entry' /tmp/functest.out
crl_entries=("$persistent_cache"/v1-crl-*.pem)
aia_entries=("$persistent_cache"/v1-aia-*.pem)
cached_crl=${crl_entries[0]}
cached_aia=${aia_entries[0]}
assert_output "persistent directory is private" test "$(stat -c %a "$persistent_cache")" = 700
assert_output "cache entries are private" test "$(stat -c %a "$cached_crl")" = 600
cp "$cached_crl" "$PKI_DIR/warm-crl.pem"

: > "$CHECKCRT_TEST_OFFLINE"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "warm persistent cache works during HTTP outage" 0 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$AIA_PORT"
assert_output "warm AIA and CRL use no HTTP requests" fetch_count_is 0
assert_output "AIA cache hit reports usage and age" \
    grep -Eq 'Cache HIT \(AIA\): USED verified cached download \(age: [0-9]+s\)' /tmp/functest.out
assert_output "CRL cache hit reports usage and age" \
    grep -Eq 'Cache HIT \(CRL\): USED verified cached download \(age: [0-9]+s\)' /tmp/functest.out

check_exit "cached CRL is checked against each leaf serial, not a cached verdict" 2 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" --json --summary-only 127.0.0.1 "$REVOKED_PORT"
assert_output "cached CRL still reports revocation in JSON" \
    json_matches 'length == 1 and (.[0] | .revocation == "REVOKED" and .exit_code == 2)' /tmp/functest.out
assert_output "summary-only suppresses cache diagnostics" test ! -s /tmp/functest.err

check_exit "cached AIA never becomes a trust anchor" 5 \
    "$check" --no-caa --connect-retries 0 --cache-dir "$persistent_cache" --json --summary-only 127.0.0.1 "$AIA_PORT"
assert_output "warm cache does not bypass trust-store verification" \
    json_matches 'length == 1 and (.[0] | .trust == "UNTRUSTED/INVALID" and .exit_code == 5)' /tmp/functest.out
assert_output "cache hits do not renew the original download timestamp" \
    cmp -s "$PKI_DIR/warm-crl.pem" "$cached_crl"

: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "--no-cache ignores an existing warm cache during HTTP outage" 3 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" --no-cache --summary-only 127.0.0.1 "$GOOD_PORT"
assert_output "--no-cache forces a real download attempt" fetch_count_is 1
assert_output "--no-cache leaves existing entries untouched" cmp -s "$PKI_DIR/warm-crl.pem" "$cached_crl"

seed_cache "$cached_crl" "$PKI_DIR/www/intermediate.crl" "$(( $(date -u +%s) - 43200 ))"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "default 24-hour TTL reuses a twelve-hour-old CRL during HTTP outage" 0 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
assert_output "twelve-hour-old CRL needs no HTTP request with the default TTL" fetch_count_is 0
assert_output "persistent cache reports the 24-hour default" \
    grep -Fxq "Cache mode: PERSISTENT (max age: 86400s; directory: $persistent_cache)" /tmp/functest.out
check_exit "explicit one-hour TTL still rejects a twelve-hour-old CRL" 3 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" --cache-max-age 3600 --summary-only 127.0.0.1 "$GOOD_PORT"
assert_output "explicit shorter TTL attempts a fresh download" fetch_count_is 1

seed_cache "$cached_crl" "$PKI_DIR/www/intermediate.crl" "$(( $(date -u +%s) - 120 ))"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "expired cache TTL plus HTTP outage stays UNKNOWN" 3 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" --cache-max-age 60 --json --summary-only 127.0.0.1 "$GOOD_PORT"
assert_output "expired TTL attempts a fresh fetch" fetch_count_is 1
assert_output "failed refresh never falls back to stale evidence" \
    json_matches 'length == 1 and (.[0] | .trust == "TRUSTED" and .revocation == "UNKNOWN" and .exit_code == 3)' /tmp/functest.out

# A signed CRL just past nextUpdate is still within the normal clock-skew
# allowance. Cache reuse must nevertheless reject it, with a recent fetch time.
openssl ca -config "$PKI_DIR/ca_intermediate.cnf" -gencrl \
    -crl_lastupdate "$(date -u -d '2 days ago' +%Y%m%d%H%M%SZ)" \
    -crl_nextupdate "$(date -u -d '1 minute ago' +%Y%m%d%H%M%SZ)" \
    -out "$PKI_DIR/stale.crl" >/dev/null 2>&1
seed_cache "$cached_crl" "$PKI_DIR/stale.crl"
check_exit "cached CRL past nextUpdate is rejected even within clock skew" 3 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" --summary-only 127.0.0.1 "$GOOD_PORT"

openssl ca -config "$PKI_DIR/ca_intermediate.cnf" -gencrl \
    -crl_lastupdate "$(date -u -d tomorrow +%Y%m%d%H%M%SZ)" \
    -crl_nextupdate "$(date -u -d '2 days' +%Y%m%d%H%M%SZ)" \
    -out "$PKI_DIR/future.crl" >/dev/null 2>&1
seed_cache "$cached_crl" "$PKI_DIR/future.crl"
check_exit "cached CRL with a future lastUpdate is rejected" 3 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" --summary-only 127.0.0.1 "$GOOD_PORT"

rm -f "$CHECKCRT_TEST_OFFLINE"
# Clock skew must not make an empty or reversed signed interval usable.
cp "$PKI_DIR/www/intermediate.crl" "$PKI_DIR/valid-period.crl"
for period in reversed empty; do
    period_now=$(date -u +%s)
    period_last=$((period_now + 240))
    period_next=$((period_now + 120))
    [[ "$period" != empty ]] || period_last=$period_next
    openssl ca -config "$PKI_DIR/ca_intermediate.cnf" -gencrl \
        -crl_lastupdate "$(date -u -d "@$period_last" +%Y%m%d%H%M%SZ)" \
        -crl_nextupdate "$(date -u -d "@$period_next" +%Y%m%d%H%M%SZ)" \
        -out "$PKI_DIR/$period.crl" >/dev/null 2>&1 || exit 1
    seed_cache "$cached_crl" "$PKI_DIR/$period.crl"
    touch "$CHECKCRT_TEST_OFFLINE"
    : > "$CHECKCRT_TEST_FETCH_LOG"
    check_exit "cached CRL with $period update period stays UNKNOWN during outage" 3 \
        "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" --json 127.0.0.1 "$GOOD_PORT"
    assert_output "$period cached period triggers a real refresh attempt" fetch_count_is 1
    assert_output "$period cached period cannot supply revocation evidence" \
        json_matches 'length == 1 and .[0].revocation == "UNKNOWN"' /tmp/functest.out
    rm -f "$CHECKCRT_TEST_OFFLINE"
    : > "$CHECKCRT_TEST_FETCH_LOG"
    check_exit "cached CRL with $period update period is refreshed" 0 \
        "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
    assert_output "$period cached period requires a new download" fetch_count_is 1

    cp "$PKI_DIR/$period.crl" "$PKI_DIR/www/intermediate.crl"
    check_exit "downloaded CRL with $period update period is rejected" 3 \
        "$check" "${cache_args[@]}" --cache-dir "$PKI_DIR/$period-cache" 127.0.0.1 "$GOOD_PORT"
    period_entries=("$PKI_DIR/$period-cache"/*.pem)
    assert_output "$period downloaded period leaves no cache entry" test ! -e "${period_entries[0]}"
    check_exit "CRL with $period update period is rejected with --no-cache" 3 \
        "$check" "${cache_args[@]}" --no-cache 127.0.0.1 "$GOOD_PORT"
    cp "$PKI_DIR/valid-period.crl" "$PKI_DIR/www/intermediate.crl"
done

openssl crl -in "$PKI_DIR/www/intermediate.crl" -badsig -out "$PKI_DIR/badsig.crl"
printf 'not a CRL\n' > "$PKI_DIR/garbage.crl"
for bad_crl in stale future badsig garbage; do
    seed_cache "$cached_crl" "$PKI_DIR/$bad_crl.crl"
    : > "$CHECKCRT_TEST_FETCH_LOG"
    check_exit "invalid cached CRL ($bad_crl) is refreshed" 0 \
        "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
    assert_output "invalid cached CRL ($bad_crl) requires one real fetch" fetch_count_is 1
done

seed_cache "$cached_crl" "$PKI_DIR/www/root.crl"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "cached CRL signed by the wrong issuer is refreshed" 0 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
assert_output "wrong-issuer CRL cannot satisfy a cache hit" fetch_count_is 1

for timestamp in "$(( $(date -u +%s) - 90000 ))" "$(( $(date -u +%s) + 7200 ))"; do
    seed_cache "$cached_crl" "$PKI_DIR/www/intermediate.crl" "$timestamp"
    : > "$CHECKCRT_TEST_FETCH_LOG"
    check_exit "out-of-range cache timestamp triggers refresh" 0 \
        "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
    assert_output "cache age is enforced independently of CRL validity" fetch_count_is 1
done

seed_cache "$cached_aia" "$PKI_DIR/certs/root.pem"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "wrong cached AIA issuer is replaced" 0 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$AIA_PORT"
assert_output "wrong AIA issuer triggers one fetch, retaining the good CRL" fetch_count_is 1

openssl req -new -x509 -key "$PKI_DIR/private/root.key" -days 30 \
    -subj '/O=checkCRT Test/CN=checkCRT Test Intermediate CA' \
    -addext 'basicConstraints=critical,CA:true' -out "$PKI_DIR/impostor.pem" >/dev/null 2>&1
seed_cache "$cached_aia" "$PKI_DIR/impostor.pem"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "same-subject cached AIA issuer with the wrong key is rejected" 0 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$AIA_PORT"
assert_output "AIA cache requires a signature check, not just a name match" fetch_count_is 1

seed_cache "$cached_aia" "$PKI_DIR/certs/intermediate.pem" "$(( $(date -u +%s) - 90000 ))"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "AIA cache has a bounded age too" 0 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$AIA_PORT"
assert_output "expired AIA cache is refreshed" fetch_count_is 1

# Publishing a refreshed entry replaces a symlink, not its target.
mv "$cached_crl" "$PKI_DIR/original-cache-entry.pem"
cp "$PKI_DIR/original-cache-entry.pem" "$PKI_DIR/cache-sentinel.pem"
ln -s "$PKI_DIR/cache-sentinel.pem" "$cached_crl"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "symlink cache entry is ignored and safely replaced" 0 \
    "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
assert_output "symlink does not supply a cache hit" fetch_count_is 1
assert_output "cache publishing does not modify the symlink target" \
    cmp -s "$PKI_DIR/original-cache-entry.pem" "$PKI_DIR/cache-sentinel.pem"
assert_output "published cache entry is a regular file" test ! -L "$cached_crl"

# Invalid freshly-downloaded data must not poison a subsequent run's cache.
cp "$PKI_DIR/www/intermediate.crl" "$PKI_DIR/original.crl"
cp "$PKI_DIR/badsig.crl" "$PKI_DIR/www/intermediate.crl"
check_exit "invalid downloaded CRL is not cached" 3 \
    "$check" "${cache_args[@]}" --cache-dir "$PKI_DIR/invalid-cache" 127.0.0.1 "$GOOD_PORT"
invalid_entries=("$PKI_DIR/invalid-cache"/*.pem)
assert_output "bad signature leaves no cache entry" test ! -e "${invalid_entries[0]}"
cp "$PKI_DIR/original.crl" "$PKI_DIR/www/intermediate.crl"

# Exercise 3.0's exit-zero signature failure even when running on OpenSSL 3.5.
# The shim changes only the exit code, never the cryptographic verification.
export CHECKCRT_TEST_OPENSSL_BIN
CHECKCRT_TEST_OPENSSL_BIN=$(command -v openssl)
export CHECKCRT_TEST_LEGACY_LOG="$PKI_DIR/legacy-crl.log"
mkdir "$PKI_DIR/legacy-bin"
cp "$script_dir/crl_verify_wrapper.sh" "$PKI_DIR/legacy-bin/openssl"
chmod +x "$PKI_DIR/legacy-bin/openssl"
legacy_path="$PKI_DIR/legacy-bin:$PATH"
seed_cache "$cached_crl" "$PKI_DIR/badsig.crl"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "legacy exit-zero bad cached signature triggers refresh" 0 \
    env PATH="$legacy_path" "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
assert_output "legacy bad cached signature needs a real download" fetch_count_is 1
cp "$PKI_DIR/badsig.crl" "$PKI_DIR/www/intermediate.crl"
check_exit "legacy exit-zero bad downloaded signature remains UNKNOWN" 3 \
    env PATH="$legacy_path" "$check" "${cache_args[@]}" --cache-dir "$PKI_DIR/legacy-cache" --json 127.0.0.1 "$GOOD_PORT"
assert_output "legacy bad signature cannot become positive JSON evidence" \
    json_matches 'length == 1 and (.[0] | .revocation == "UNKNOWN" and .exit_code == 3)' /tmp/functest.out
legacy_entries=("$PKI_DIR/legacy-cache"/*.pem)
assert_output "legacy bad signature is never cached" test ! -e "${legacy_entries[0]}"
check_exit "legacy exit-zero bad signature rejected with --no-cache" 3 \
    env PATH="$legacy_path" "$check" "${cache_args[@]}" --no-cache 127.0.0.1 "$GOOD_PORT"
assert_output "test exercised actual signature failure with exit zero" test -s "$CHECKCRT_TEST_LEGACY_LOG"
cp "$PKI_DIR/original.crl" "$PKI_DIR/www/intermediate.crl"

# Count real cryptographic checks: the caller must not repeat a successful
# fetch's CRL signature verification, and each host must still verify its own.
signature_log="$PKI_DIR/crl-signature-count.log"
for signature_mode in cold warm disabled; do
    signature_args=(--cache-dir "$PKI_DIR/signature-cache")
    signature_fetches=0
    if [[ "$signature_mode" == cold ]]; then signature_fetches=1; fi
    if [[ "$signature_mode" == disabled ]]; then
        signature_args+=(--no-cache)
        signature_fetches=1
    fi
    : > "$signature_log"
    : > "$CHECKCRT_TEST_FETCH_LOG"
    check_exit "CRL signature checked once with $signature_mode cache" 0 \
        env PATH="$legacy_path" CHECKCRT_TEST_CRL_VERIFY_LOG="$signature_log" \
        "$check" "${cache_args[@]}" "${signature_args[@]}" --json 127.0.0.1 "$GOOD_PORT"
    assert_output "$signature_mode cache performs exactly one CRL signature verification" \
        test "$(wc -l < "$signature_log")" -eq 1
    assert_output "$signature_mode cache preserves HTTP reuse behavior" fetch_count_is "$signature_fetches"
    assert_output "$signature_mode cache retains valid revocation evidence" \
        json_matches 'length == 1 and (.[0] | .overall == "VALID" and .revocation == "NOT REVOKED")' /tmp/functest.out
done
printf '127.0.0.1 %s\n127.0.0.1 %s\n127.0.0.1 %s\n' \
    "$GOOD_PORT" "$GOOD_PORT" "$GOOD_PORT" > "$PKI_DIR/hosts-signature.txt"
: > "$signature_log"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "parallel cache verifies a shared CRL separately for each host" 0 \
    env PATH="$legacy_path" CHECKCRT_TEST_CRL_VERIFY_LOG="$signature_log" \
    "$check" "${cache_args[@]}" --cache-dir "$PKI_DIR/signature-cache" \
    --parallel 3 --hosts-file "$PKI_DIR/hosts-signature.txt" --json
assert_output "three hosts perform three CRL signature verifications" \
    test "$(wc -l < "$signature_log")" -eq 3
assert_output "parallel signature verification reuses downloaded data" fetch_count_is 0
assert_output "parallel signature verification retains every host result" \
    json_matches 'length == 3 and all(.[]; .overall == "VALID")' /tmp/functest.out

# Both supported HTTP encodings must be normalized before cache publication.
openssl crl -in "$PKI_DIR/original.crl" -outform DER -out "$PKI_DIR/www/intermediate.crl"
openssl x509 -in "$PKI_DIR/certs/intermediate.pem" -outform DER -out "$PKI_DIR/www/intermediate.crt"
check_exit "DER CRL and AIA downloads are cached as PEM" 0 \
    "$check" "${cache_args[@]}" --cache-dir "$PKI_DIR/der-cache" 127.0.0.1 "$AIA_PORT"
der_crls=("$PKI_DIR/der-cache"/v1-crl-*.pem)
der_issuers=("$PKI_DIR/der-cache"/v1-aia-*.pem)
assert_output "DER CRL cache entry contains PEM" grep -q '^-----BEGIN X509 CRL-----$' "${der_crls[0]}"
assert_output "DER AIA cache entry contains PEM" grep -q '^-----BEGIN CERTIFICATE-----$' "${der_issuers[0]}"
cp "$PKI_DIR/original.crl" "$PKI_DIR/www/intermediate.crl"
cp "$PKI_DIR/certs/intermediate.pem" "$PKI_DIR/www/intermediate.crt"

# Slow shared downloads must not trigger the former five-second bypass.
printf '127.0.0.1 %s\n127.0.0.1 %s\n127.0.0.1 %s\n' \
    "$GOOD_PORT" "$GOOD_PORT" "$GOOD_PORT" > "$PKI_DIR/hosts-slow-cache.txt"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "parallel cache waits for a shared download exceeding five seconds" 0 \
    env CHECKCRT_TEST_FETCH_DELAY=7 timeout 45 "$check" "${cache_args[@]}" \
    --parallel 3 --hosts-file "$PKI_DIR/hosts-slow-cache.txt" --json
assert_output "slow shared CRL is downloaded only once" fetch_count_is 1
assert_output "slow download waiters report their wait" \
    grep -q 'Cache WAIT (CRL)' /tmp/functest.err
assert_output "slow shared download preserves all host results" \
    json_matches 'length == 3 and all(.[]; .overall == "VALID")' /tmp/functest.out
assert_output "slow shared download records two hits and only one miss" \
    json_matches 'all(.[]; .cache_hits + .cache_misses == 1) and ([.[].cache_hits] | add) == 2 and ([.[].cache_misses] | add) == 1' /tmp/functest.out
assert_output "elapsed seconds include the slow download and stay within the test timeout" \
    json_matches '([.[].elapsed_seconds] | max) >= 7 and all(.[]; .elapsed_seconds < 45)' /tmp/functest.out

# A lock file remains after its owner exits, but its kernel lock is released.
seed_cache "$cached_crl" "$PKI_DIR/stale.crl"
(
    exec 9>>"$cached_crl.lock"
    flock -x 9
)
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "lock file from an exited owner does not block a refresh" 0 \
    timeout 15 "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
assert_output "released lock permits one fresh HTTP request" fetch_count_is 1
assert_output "lock files remain available for other waiters" test -f "$cached_crl.lock"

# Refuse incompatible legacy locks without downloading around them.
seed_cache "$cached_crl" "$PKI_DIR/stale.crl"
mv "$cached_crl.lock" "$PKI_DIR/released-lock"
mkdir "$cached_crl.lock"
: > "$CHECKCRT_TEST_FETCH_LOG"
check_exit "legacy lock directory prevents an uncoordinated fetch" 3 \
    timeout 15 "$check" "${cache_args[@]}" --cache-dir "$persistent_cache" 127.0.0.1 "$GOOD_PORT"
assert_output "unavailable locking makes no HTTP requests" fetch_count_is 0
assert_output "unavailable locking is explained" \
    grep -q 'Cache ERROR (CRL): cannot open cache lock' /tmp/functest.err

echo
echo "Functional tests: $pass passed, $fail failed."
(( fail == 0 )) || exit 1
bash "$script_dir/ocsp_cache.sh"
