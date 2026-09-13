#!/usr/bin/env bash
# Standalone OCSP caching regressions using real signed responses over HTTP.
set -uo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
check="$script_dir/../../checkCRT.sh"
for dependency in openssl busybox jq; do
    command -v "$dependency" >/dev/null || { echo "Missing test dependency: $dependency" >&2; exit 1; }
done
fixture_dir=$(mktemp -d)
pids=()
cleanup() {
    for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]:-}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf "$fixture_dir"
}
trap cleanup EXIT
http_port=19080
good_port=19081
revoked_port=19082
other_port=19083
bash "$script_dir/setup_ocsp.sh" "$fixture_dir" "$http_port" || exit 1
mkdir -p "$fixture_dir/www/cgi-bin" "$fixture_dir/bin"
cp "$script_dir/ocsp_fixture.sh" "$fixture_dir/www/cgi-bin/ocsp"
cp "$script_dir/ocsp_clock.sh" "$fixture_dir/bin/date"
chmod +x "$fixture_dir/www/cgi-bin/ocsp" "$fixture_dir/bin/date"
export CHECKCRT_OCSP_DIR="$fixture_dir"
export CHECKCRT_REAL_DATE
CHECKCRT_REAL_DATE=$(command -v date)
export CHECKCRT_CLOCK_OFFSET=0
busybox httpd -f -p "127.0.0.1:$http_port" -h "$fixture_dir/www" -c /dev/null > "$fixture_dir/http.log" 2>&1 &
pids+=("$!")
for leaf in good revoked other; do
    port_name="${leaf}_port"
    openssl s_server -accept "127.0.0.1:${!port_name}" -quiet \
        -cert "$fixture_dir/$leaf.pem" -key "$fixture_dir/$leaf.key" \
        -cert_chain "$fixture_dir/issuer.pem" > "$fixture_dir/tls-$leaf.log" 2>&1 &
    pids+=("$!")
done
sleep 1
for port in "$http_port" "$good_port" "$revoked_port" "$other_port"; do
    timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null || {
        echo "OCSP fixture on port $port did not start" >&2; exit 1;
    }
done
out="$fixture_dir/stdout"
err="$fixture_dir/stderr"
pass=0
fail=0
args=(--no-caa --no-proxy 127.0.0.1 --connect-retries 0 --retry-delay 0 --request-timeout 3
    --ca-file "$fixture_dir/root.pem")
cache="$fixture_dir/cache"
check_exit() {
    local desc=$1 expected=$2 actual
    shift 2
    "$@" > "$out" 2> "$err"
    actual=$?
    if [[ "$actual" == "$expected" ]]; then
        printf 'PASS: %s (exit %s)\n' "$desc" "$actual"; pass=$((pass + 1))
    else
        printf 'FAIL: %s (expected %s, got %s)\n' "$desc" "$expected" "$actual"
        tail -15 "$err"
        fail=$((fail + 1))
    fi
}
assert() {
    local desc=$1
    shift
    if "$@"; then printf 'PASS: %s\n' "$desc"; pass=$((pass + 1))
    else printf 'FAIL: %s\n' "$desc"; fail=$((fail + 1)); fi
}
requests() { [[ $(wc -l < "$fixture_dir/requests.log") -eq "$1" ]]; }
json_matches() { jq -e -s "$1" "$out" >/dev/null; }
cache_path() {
    local cert=$1 issuer=$2 endpoint=$3 key cert_fp issuer_fp
    cert_fp=$(openssl x509 -in "$fixture_dir/$cert.pem" -noout -fingerprint -sha256)
    issuer_fp=$(openssl x509 -in "$fixture_dir/$issuer.pem" -noout -fingerprint -sha256)
    key=$(printf 'ocsp\n%s\n%s\n%s' "http://127.0.0.1:$http_port/cgi-bin/ocsp/$endpoint" \
        "$cert_fp" "$issuer_fp" | openssl dgst -sha256 | awk '{print $NF}')
    printf 'v1-ocsp-%s.ocsp\n' "$key"
}
good_entry=$(cache_path good issuer leaf)
revoked_entry=$(cache_path revoked issuer leaf)
issuer_entry=$(cache_path issuer root root)
set_mode() { printf '%s\n' "$1" > "$fixture_dir/mode"; : > "$fixture_dir/requests.log"; }
retime() { sed "1c# checkCRT-cache-v1 $3" "$1" > "$2"; }

check_exit 'OCSP cold cache verifies leaf and intermediate' 0 \
    "$check" "${args[@]}" --cache-dir "$cache" --json 127.0.0.1 "$good_port"
assert 'two actual HTTP requests populate the cache' requests 2
assert 'OCSP cache miss is logged outside JSON' grep -q 'Cache MISS (OCSP): NOT USED' "$err"
assert 'OCSP-only JSON result is trusted and not revoked' \
    json_matches 'length == 1 and (.[0] | .trust == "TRUSTED" and .revocation == "NOT REVOKED")'
assert 'OCSP cache files are private' test "$(stat -c %a "$cache/$good_entry")" = 600
cp "$cache/$good_entry" "$fixture_dir/good.saved"
cp "$cache/$issuer_entry" "$fixture_dir/issuer.saved"

set_mode offline
check_exit 'warm OCSP cache works during responder outage' 0 \
    "$check" "${args[@]}" --cache-dir "$cache" --json 127.0.0.1 "$good_port"
assert 'warm OCSP cache avoids all HTTP requests' requests 0
assert 'OCSP cache hits are logged' grep -q 'Cache HIT (OCSP): USED' "$err"
assert 'cache hits do not reset timestamps' cmp -s "$fixture_dir/good.saved" "$cache/$good_entry"
check_exit 'OCSP cache never makes an untrusted chain trusted' 5 \
    "$check" --no-caa --connect-retries 0 --cache-dir "$cache" --json --summary-only 127.0.0.1 "$good_port"
assert 'cached evidence does not replace the trust store' json_matches '.[0].trust == "UNTRUSTED/INVALID"'
assert 'summary-only suppresses OCSP cache diagnostics' test ! -s "$err"
check_exit '--no-cache forces OCSP queries even with warm cache' 3 \
    "$check" "${args[@]}" --no-cache --cache-dir "$cache" 127.0.0.1 "$good_port"
assert '--no-cache actually attempted both HTTP requests' requests 2
assert 'OCSP bypass is logged' grep -q 'Cache BYPASS (OCSP): NOT USED' "$out"

set_mode dynamic
check_exit 'same responder and issuer, different leaf -> REVOKED' 2 \
    "$check" "${args[@]}" --cache-dir "$cache" --json 127.0.0.1 "$revoked_port"
assert 'different leaf needs its own response, shared issuer does not' requests 1
set_mode offline
check_exit 'verified revoked response is reusable offline' 2 \
    "$check" "${args[@]}" --cache-dir "$cache" --json --summary-only 127.0.0.1 "$revoked_port"
assert 'revoked cache hit performs no HTTP requests' requests 0
assert 'cached revoked status remains REVOKED' json_matches '.[0].revocation == "REVOKED"'

set_mode dynamic
printf '127.0.0.1 %s\n127.0.0.1 %s\n127.0.0.1 %s\n' \
    "$good_port" "$other_port" "$good_port" > "$fixture_dir/hosts"
for parallel in 1 3; do
    : > "$fixture_dir/requests.log"
    check_exit "OCSP per-run batch cache ($parallel workers)" 0 \
        "$check" "${args[@]}" --parallel "$parallel" --hosts-file "$fixture_dir/hosts" --json
    assert "batch checks share two leaf responses and one issuer response ($parallel workers)" requests 3
    assert "batch OCSP cache preserves NDJSON ($parallel workers)" \
        json_matches 'length == 3 and all(.[]; .overall == "VALID")'
done

# Even a valid signed response stored under the wrong filename must be rejected.
cp "$cache/$revoked_entry" "$cache/$good_entry"
: > "$fixture_dir/requests.log"
check_exit 'cached response for the wrong CertID is refreshed' 0 \
    "$check" "${args[@]}" --cache-dir "$cache" 127.0.0.1 "$good_port"
assert 'wrong CertID cache entry requires a new HTTP query' requests 1
printf 'damaged cache\n' > "$cache/$good_entry"
: > "$fixture_dir/requests.log"
check_exit 'corrupt OCSP cache is refreshed' 0 \
    "$check" "${args[@]}" --cache-dir "$cache" 127.0.0.1 "$good_port"
assert 'corrupt cache requires a new HTTP query' requests 1

openssl ocsp -issuer "$fixture_dir/issuer.pem" -cert "$fixture_dir/good.pem" \
    -no_nonce -reqout "$fixture_dir/good.req"
openssl ocsp -index "$fixture_dir/issuer.index" -CA "$fixture_dir/issuer.pem" \
    -rsigner "$fixture_dir/issuer.pem" -rkey "$fixture_dir/issuer.key" \
    -reqin "$fixture_dir/good.req" -badsig -ndays 2 -respout "$fixture_dir/badsig.der"
{ printf '# checkCRT-cache-v1 %s\n' "$(date -u +%s)";
  openssl base64 -in "$fixture_dir/badsig.der"; } > "$cache/$good_entry"
set_mode offline
check_exit 'cached response signature is reverified before use' 3 \
    "$check" "${args[@]}" --cache-dir "$cache" --json 127.0.0.1 "$good_port"
assert 'bad cached signature forces a refresh attempt' requests 1
assert 'bad cached signature does not become positive evidence' json_matches '.[0].revocation == "UNKNOWN"'
set_mode dynamic
check_exit 'bad cached signature can be replaced with verified fresh evidence' 0 \
    "$check" "${args[@]}" --cache-dir "$cache" 127.0.0.1 "$good_port"

for mode in unknown badsig wrong-id wrong-signer; do
    set_mode "$mode"
    check_exit "OCSP $mode response does not become positive evidence" 3 \
        "$check" "${args[@]}" --cache-dir "$fixture_dir/$mode-cache" --json 127.0.0.1 "$good_port"
    assert "$mode response is not cached" test ! -e "$fixture_dir/$mode-cache/$good_entry"
    assert "$mode result remains UNKNOWN" json_matches '.[0].revocation == "UNKNOWN"'
    if [[ "$mode" == unknown ]]; then
        assert 'signed unknown status is distinguished from a query failure' \
            grep -q 'OCSP responder returned an unknown status' "$err"
    fi
done

set_mode offline
retime "$fixture_dir/good.saved" "$cache/$good_entry" "$(( $(date -u +%s) - 15000 ))"
check_exit 'expired OCSP cache TTL never falls back during outage' 3 \
    "$check" "${args[@]}" --cache-dir "$cache" 127.0.0.1 "$good_port"
assert 'expired cached response triggers a real refresh attempt' requests 1
retime "$fixture_dir/good.saved" "$cache/$good_entry" "$(( $(date -u +%s) + 3600 ))"
check_exit 'future download timestamp is not a cache hit' 3 \
    "$check" "${args[@]}" --cache-dir "$cache" 127.0.0.1 "$good_port"

# Advance only the checker's clock: signatures and CertIDs remain real, and
# the cache TTL is still live, isolating the signed response freshness limit.
for mode in dynamic no-next short-next; do
    set_mode "$mode"
    time_cache="$fixture_dir/time-$mode"
    check_exit "fresh $mode responses populate OCSP cache" 0 \
        "$check" "${args[@]}" --cache-dir "$time_cache" 127.0.0.1 "$good_port"
    set_mode offline
    check_exit "$mode responses are reusable before their time limit" 0 \
        "$check" "${args[@]}" --cache-dir "$time_cache" --summary-only 127.0.0.1 "$good_port"
    assert "warm $mode responses avoid HTTP" requests 0
    age_args=(--max-ocsp-age 60)
    [[ "$mode" != short-next ]] || age_args=(--max-ocsp-age 86400)
    check_exit "$mode response freshness is stricter than download TTL" 3 \
        env PATH="$fixture_dir/bin:$PATH" CHECKCRT_CLOCK_OFFSET=120 \
        "$check" "${args[@]}" "${age_args[@]}" --cache-dir "$time_cache" --json 127.0.0.1 "$good_port"
    assert "stale $mode responses attempt refresh, not reuse" requests 2
    assert "stale $mode response leaves revocation UNKNOWN" json_matches '.[0].revocation == "UNKNOWN"'
    set_mode "$mode"
    check_exit "freshly queried $mode response must also pass time checks" 3 \
        env PATH="$fixture_dir/bin:$PATH" CHECKCRT_CLOCK_OFFSET=120 \
        "$check" "${args[@]}" "${age_args[@]}" --cache-dir "$time_cache/fresh" --json 127.0.0.1 "$good_port"
    assert "fresh but out-of-policy $mode response is not cached" test ! -e "$time_cache/fresh/$good_entry"
done

set_mode offline
retime "$fixture_dir/good.saved" "$cache/$good_entry" "$(( $(date -u +%s) - 3600 ))"
retime "$fixture_dir/issuer.saved" "$cache/$issuer_entry" "$(( $(date -u +%s) - 3600 ))"
check_exit 'signed thisUpdate in the future is rejected despite a valid download timestamp' 3 \
    env PATH="$fixture_dir/bin:$PATH" CHECKCRT_CLOCK_OFFSET=-1800 \
    "$check" "${args[@]}" --cache-dir "$cache" 127.0.0.1 "$good_port"

set_mode root-revoked
check_exit 'OCSP detects a revoked intermediate with a good leaf' 2 \
    "$check" "${args[@]}" --cache-dir "$fixture_dir/root-revoked-cache" --json 127.0.0.1 "$good_port"
assert 'intermediate revocation is represented in JSON' json_matches '.[0].intermediate_revoked == true'
set_mode offline
check_exit 'cached intermediate revocation remains enforced offline' 2 \
    "$check" "${args[@]}" --cache-dir "$fixture_dir/root-revoked-cache" --json --summary-only 127.0.0.1 "$good_port"
assert 'cached revoked intermediate needs no HTTP requests' requests 0
assert 'cached intermediate revocation preserves JSON' json_matches '.[0].intermediate_revoked == true'

printf '\nOCSP cache tests: %s passed, %s failed.\n' "$pass" "$fail"
(( fail == 0 ))
