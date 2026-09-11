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

HTTPPORT=8990
GOOD_PORT=8991
REVOKED_PORT=8992
LEAF3_PORT=8993
AIA_PORT=8994
OCSP_PURPOSE_PORT=8995

export HTTPPORT
PKI_DIR=$(bash "$script_dir/setup_pki.sh")
pids=()

cleanup() {
    for pid in "${pids[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
    rm -rf "$PKI_DIR"
}
trap cleanup EXIT

start_server() {
    local port=$1 cert=$2 chain=${3:-}
    local key="${cert/\/certs\//\/private\/}"
    key="${key%.pem}.key"
    local -a args=(-accept "$port" -cert "$cert" -key "$key" -naccept 20 -quiet)
    [[ -n "$chain" ]] && args+=(-cert_chain "$chain")
    openssl s_server "${args[@]}" >"$PKI_DIR/s_server-$port.log" 2>&1 &
    pids+=($!)
}

(cd "$PKI_DIR/www" && python3 -m http.server "$HTTPPORT" >"$PKI_DIR/httpd.log" 2>&1 &)
httpd_pid=$(pgrep -f "http.server $HTTPPORT" | tail -1)
pids+=("$httpd_pid")

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

sleep 1
for p in "$HTTPPORT" "$GOOD_PORT" "$REVOKED_PORT" "$LEAF3_PORT" "$AIA_PORT" "$OCSP_PURPOSE_PORT"; do
    timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/$p" 2>/dev/null || {
        echo "FAIL: server on port $p did not come up" >&2
        exit 1
    }
done

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

check_exit "leaf-revoked: full chain presented -> REVOKED" 2 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" 127.0.0.1 "$REVOKED_PORT"

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
if grep -q "VALID (2)" /tmp/functest.out && grep -q "REVOKED (2)" /tmp/functest.out; then
    echo "PASS: --parallel 3 grouped summary counts are correct"
    pass=$((pass + 1))
else
    echo "FAIL: --parallel 3 grouped summary counts are wrong"
    fail=$((fail + 1))
fi

check_exit "--parallel 1 (sequential): same hosts -> exit 1" 1 \
    "$check" --ca-file "$PKI_DIR/certs/root.pem" --parallel 1 --hosts-file "$PKI_DIR/hosts-repeated.txt"
if grep -q "VALID (2)" /tmp/functest.out && grep -q "REVOKED (2)" /tmp/functest.out; then
    echo "PASS: --parallel 1 grouped summary counts are correct"
    pass=$((pass + 1))
else
    echo "FAIL: --parallel 1 grouped summary counts are wrong"
    fail=$((fail + 1))
fi

echo
echo "Functional tests: $pass passed, $fail failed."
(( fail == 0 ))
