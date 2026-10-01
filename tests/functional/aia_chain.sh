#!/usr/bin/env bash
# Recursive AIA recovery against a disposable cross-signed hierarchy.
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
check="$script_dir/../../checkCRT.sh"
fixture_dir=$(mktemp -d)
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf "$fixture_dir"
}
trap cleanup EXIT
cd "$fixture_dir"
mkdir www
http_port=19180
tls_port=19181
presented_port=19182
base="http://127.0.0.1:$http_port"
for name in root new issuer leaf wrong; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$name.key"
done
openssl req -new -x509 -key root.key -days 30 -subj '/CN=AIA Test Old Root' \
    -addext 'basicConstraints=critical,CA:true' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' -out root.pem
for name in new issuer leaf; do
    openssl req -new -key "$name.key" -subj "/CN=AIA Test $name" -out "$name.csr"
done
cat > new.ext <<EOF
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
authorityInfoAccess=caIssuers;URI:$base/root.pem
EOF
cat > issuer.ext <<EOF
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
authorityInfoAccess=caIssuers;URI:$base/new.pem
EOF
cat > leaf.ext <<EOF
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
authorityKeyIdentifier=keyid:always
authorityInfoAccess=caIssuers;URI:$base/issuer.pem
EOF
openssl req -new -x509 -key new.key -days 30 -subj '/CN=AIA Test new' \
    -addext 'basicConstraints=critical,CA:true' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' -out new-self.pem
openssl x509 -req -in new.csr -CA root.pem -CAkey root.key -set_serial 2 \
    -days 30 -extfile new.ext -out new.pem
openssl x509 -req -in issuer.csr -CA new.pem -CAkey new.key -set_serial 3 \
    -days 30 -extfile issuer.ext -out issuer.pem
openssl x509 -req -in leaf.csr -CA issuer.pem -CAkey issuer.key -set_serial 4 \
    -days 30 -extfile leaf.ext -out leaf.pem
openssl req -new -x509 -key wrong.key -days 30 -subj '/CN=AIA Test new' \
    -addext 'basicConstraints=critical,CA:true' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' -out wrong.pem
cp root.pem new.pem issuer.pem www/
busybox httpd -f -p "127.0.0.1:$http_port" -h "$fixture_dir/www" -c /dev/null > http.log 2>&1 &
http_pid=$!
pids+=("$http_pid")
openssl s_server -accept "127.0.0.1:$tls_port" -quiet -cert leaf.pem -key leaf.key > tls.log 2>&1 &
pids+=("$!")
openssl s_server -accept "127.0.0.1:$presented_port" -quiet -cert leaf.pem -key leaf.key \
    -cert_chain issuer.pem > presented.log 2>&1 &
pids+=("$!")
sleep 1
for port in "$http_port" "$tls_port" "$presented_port"; do
    timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null
done
pass=0
fail=0
args=(--no-caa --no-proxy 127.0.0.1 --connect-retries 0 --request-timeout 2 --expiry-warn-days 0)
assert() {
    local desc=$1
    shift
    if "$@"; then printf 'PASS: %s\n' "$desc"; pass=$((pass + 1))
    else printf 'FAIL: %s\n' "$desc"; fail=$((fail + 1)); fi
}
run_check() {
    local expected=$1 rc=0
    shift
    timeout 20 "$check" "${args[@]}" "$@" > out 2> err || rc=$?
    # No revocation endpoints: trusted paths are UNKNOWN (3), invalid paths 5.
    assert 'check completes with expected exit status' test "$rc" -eq "$expected"
}
run_check 3 --ca-file root.pem --cache-dir "$fixture_dir/cache" 127.0.0.1 "$tls_port"
assert 'two missing issuers lead to the trusted old root' grep -q '^  TRUST: TRUSTED$' out
assert 'cold cache fetches both missing issuers' grep -q '^  CACHE: 0 hit / 2 miss$' out
assert 'cross-signed root appears in recovered tree' grep -q 'CA: CN=AIA Test new \[FETCHED VIA AIA\]' out

run_check 3 --ca-file root.pem --cache-dir "$fixture_dir/cache" 127.0.0.1 "$presented_port"
assert 'recovery also continues above a presented immediate issuer' grep -q '^  TRUST: TRUSTED$' out
assert 'presented issuer needs only cached parent' grep -q '^  CACHE: 1 hit / 0 miss$' out

run_check 5 --cache-dir "$fixture_dir/untrusted-cache" 127.0.0.1 "$tls_port"
assert 'downloaded root is not promoted to a trust anchor' grep -q '^  TRUST: UNTRUSTED/INVALID$' out
assert 'untrusted path fetches root but still fails trust' grep -q '^  CACHE: 0 hit / 3 miss$' out
assert 'downloaded root is reported in tree' grep -q 'ROOT CA: CN=AIA Test Old Root \[FETCHED VIA AIA\]' out

cp wrong.pem www/new.pem
run_check 5 --ca-file root.pem --cache-dir "$fixture_dir/wrong-cache" 127.0.0.1 "$tls_port"
assert 'same-subject wrong-key issuer cannot complete trust' grep -q '^  TRUST: UNTRUSTED/INVALID$' out
assert 'wrong-key issuer is not accepted into tree' grep -q 'ISSUER: CN=AIA Test new \[NOT PROVIDED\]' out
assert 'invalid parent is not cached' test "$(find wrong-cache -name 'v1-aia-*.pem' | wc -l)" -eq 1

cp new-self.pem www/new.pem
run_check 5 --ca-file root.pem --no-cache 127.0.0.1 "$tls_port"
assert 'same-key self-signed new root cannot replace the cross-sign' grep -q '^  TRUST: UNTRUSTED/INVALID$' out

kill "$http_pid"
wait "$http_pid" 2>/dev/null || true
run_check 3 --ca-file root.pem --cache-dir "$fixture_dir/cache" 127.0.0.1 "$tls_port"
assert 'cached complete chain works with AIA HTTP server offline' grep -q '^  TRUST: TRUSTED$' out
assert 'both parent downloads are reused without misses' grep -q '^  CACHE: 2 hit / 0 miss$' out
printf '\nAIA chain tests: %s passed, %s failed.\n' "$pass" "$fail"
(( fail == 0 ))
