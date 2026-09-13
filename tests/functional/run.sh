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
    local -a args=(-accept "$bind_host:$port" -cert "$cert" -key "$key" -naccept 40 -quiet)
    [[ -n "$chain" ]] && args+=(-cert_chain "$chain")
    openssl s_server "${args[@]}" >"$PKI_DIR/s_server-$port.log" 2>&1 &
    pids+=($!)
}

busybox httpd -f -p "127.0.0.1:$HTTPPORT" -h "$PKI_DIR/www" -c /dev/null >"$PKI_DIR/httpd.log" 2>&1 &
pids+=("$!")

# leaf-good served with its full chain (intermediate)
start_server "$GOOD_PORT" "$PKI_DIR/certs/leaf-good.pem" "$PKI_DIR/chain-good.pem"
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
for p in "$HTTPPORT" "$GOOD_PORT" "$REVOKED_PORT" "$LEAF3_PORT" "$AIA_PORT" "$OCSP_PURPOSE_PORT" "$SNI_PORT"; do
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

# Compare the entire concise output with the corresponding portion of the
# full report: this catches leaked progress, tree output, and lost fields.
check_exit "--summary-only: good leaf keeps exit 0" 0 \
    "$check" --summary-only --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$GOOD_PORT"
assert_output "single-host summary exactly matches the full report's final status" \
    cmp -s "$PKI_DIR/good-final.txt" /tmp/functest.out
assert_output "single-host summary suppresses diagnostics" test ! -s /tmp/functest.err

check_exit "--summary-only: revoked leaf keeps exit 2" 2 \
    "$check" --summary-only --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$REVOKED_PORT"
assert_output "revoked summary exactly matches the full report's final status" \
    cmp -s "$PKI_DIR/revoked-final.txt" /tmp/functest.out
assert_output "revoked summary suppresses diagnostics" test ! -s /tmp/functest.err

for parallel in 1 3; do
    check_exit "--summary-only --parallel $parallel: mixed batch keeps exit 1" 1 \
        "$check" --summary-only --parallel "$parallel" --ca-file "$PKI_DIR/certs/root.pem" \
        --hosts-file "$PKI_DIR/hosts.txt"
    assert_output "batch summary ($parallel workers) contains only the unchanged table" \
        cmp -s "$PKI_DIR/batch-summary.txt" /tmp/functest.out
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

check_exit "JSON baseline: good leaf" 0 \
    "$check" --json --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$GOOD_PORT"
cp /tmp/functest.out "$PKI_DIR/good.json"
check_exit "--json --summary-only: good leaf" 0 \
    "$check" --json --summary-only --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$GOOD_PORT"
assert_output "summary flag preserves the full JSON record, including warnings" \
    cmp -s "$PKI_DIR/good.json" /tmp/functest.out
assert_output "JSON summary suppresses diagnostics" test ! -s /tmp/functest.err

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

echo
echo "Functional tests: $pass passed, $fail failed."
(( fail == 0 ))
