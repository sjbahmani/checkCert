#!/usr/bin/env bash
# Real local CRL/AIA transfers through Axel after simulated client timeouts.
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
check="$script_dir/../../checkCRT.sh"
for dependency in curl wget axel jq busybox; do
    command -v "$dependency" >/dev/null || { echo "Missing test dependency: $dependency" >&2; exit 1; }
done
fixture_dir=$(mktemp -d)
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf "$fixture_dir"
}
trap cleanup EXIT
HTTPPORT=19190 PKI_DIR="$fixture_dir" bash "$script_dir/setup_pki.sh" >/dev/null
busybox httpd -f -p 127.0.0.1:19190 -h "$fixture_dir/www" -c /dev/null > "$fixture_dir/http.log" 2>&1 &
pids+=("$!")
for port in 19191 19192; do
    chain=()
    [[ "$port" != 19191 ]] || chain=(-cert_chain "$fixture_dir/chain-good.pem")
    openssl s_server -quiet -accept "127.0.0.1:$port" -cert "$fixture_dir/certs/leaf-good.pem" \
        -key "$fixture_dir/private/leaf-good.key" "${chain[@]}" > "$fixture_dir/tls-$port.log" 2>&1 &
    pids+=("$!")
done
sleep 1
mkdir "$fixture_dir/bin"
cp "$script_dir/axel_wrapper.sh" "$fixture_dir/bin/axel"
for client in curl wget; do cp "$script_dir/fetch_wrapper.sh" "$fixture_dir/bin/$client"; done
chmod +x "$fixture_dir/bin/"*
export CHECKCRT_AXEL_BIN CHECKCRT_TEST_FETCH_BIN
CHECKCRT_AXEL_BIN=$(command -v axel)
CHECKCRT_TEST_FETCH_BIN=$(command -v curl)
export CHECKCRT_AXEL_LOG="$fixture_dir/axel.log" CHECKCRT_AXEL_ARGS="$fixture_dir/axel.args"
export CHECKCRT_TEST_FETCH_LOG="$fixture_dir/fetch.log" CHECKCRT_TEST_OFFLINE="$fixture_dir/offline"
export CHECKCRT_AXEL_INVALID="$fixture_dir/www/root.crl" CHECKCRT_AXEL_VALID="$fixture_dir/www/intermediate.crl"
export PATH="$fixture_dir/bin:$PATH"
args=(--no-caa --no-proxy '*' --ca-file "$fixture_dir/certs/root.pem" --connect-retries 2 --retry-delay 0 --request-timeout 3 --json)
out="$fixture_dir/out" err="$fixture_dir/err"
pass=0 fail=0
assert() {
    local desc=$1
    shift
    if "$@"; then printf 'PASS: %s\n' "$desc"; pass=$((pass+1))
    else printf 'FAIL: %s\n' "$desc"; fail=$((fail+1)); fi
}
run_check() {
    local desc=$1 expected=$2 rc=0
    shift 2
    : > "$CHECKCRT_AXEL_LOG"
    : > "$CHECKCRT_TEST_FETCH_LOG"
    "$@" > "$out" 2> "$err" || rc=$?
    assert "$desc (exit $rc)" test "$rc" -eq "$expected"
    if (( rc != expected )); then tail -15 "$err"; fi
}
count_is() { [[ $(wc -l < "$1") -eq "$2" ]]; }
json_matches() { jq -e -s "$1" "$out" >/dev/null; }
with_clients() (
    export CHECKCRT_AXEL_CLIENT=$1 CHECKCRT_AXEL_AVAILABLE=$2
    shift 2
    # shellcheck disable=SC2329
    command() {
        if [[ "$*" == '-v curl' && "$CHECKCRT_AXEL_CLIENT" == wget ]]; then return 1; fi
        if [[ "$*" == '-v axel' && "$CHECKCRT_AXEL_AVAILABLE" == no ]]; then return 1; fi
        builtin command "$@"
    }
    export -f command
    "$@"
)
for client in curl wget; do
    run_check "$client timeout falls back to real Axel" 0 \
        with_clients "$client" yes env CHECKCRT_TEST_FORCE_TIMEOUT=1 \
        "$check" "${args[@]}" --cache-dir "$fixture_dir/cache-$client" 127.0.0.1 19191
    assert "$client made one ordinary attempt" count_is "$CHECKCRT_TEST_FETCH_LOG" 1
    assert "$client uses one Axel attempt" count_is "$CHECKCRT_AXEL_LOG" 1
    assert "$client fallback verifies and counts one miss" json_matches '.[0].overall == "VALID" and .[0].cache_misses == 1'
    assert 'Axel requests ten connections' grep -Fxq '10' "$CHECKCRT_AXEL_ARGS"
    run_check "$client warm cache avoids all downloads" 0 \
        with_clients "$client" yes env CHECKCRT_TEST_FORCE_TIMEOUT=1 \
        "$check" "${args[@]}" --cache-dir "$fixture_dir/cache-$client" 127.0.0.1 19191
    assert 'warm cache is a verified hit' json_matches '.[0].cache_hits == 1 and .[0].cache_misses == 0'
    assert 'warm cache avoids Axel' count_is "$CHECKCRT_AXEL_LOG" 0
    assert 'warm cache avoids original client' count_is "$CHECKCRT_TEST_FETCH_LOG" 0
done
run_check 'AIA and CRL both use verified Axel downloads' 0 env CHECKCRT_TEST_FORCE_TIMEOUT=1 \
    "$check" "${args[@]}" 127.0.0.1 19192
assert 'one Axel attempt for each missing object' count_is "$CHECKCRT_AXEL_LOG" 2
assert 'AIA/CRL JSON stays valid' json_matches '.[0].overall == "VALID" and .[0].cache_misses == 2'

for mode in unavailable zero-retries permanent-http proxy; do
    extra=() available=yes forced_timeout=1 status=
    case "$mode" in
        unavailable) available=no ;;
        zero-retries) extra=(--connect-retries 0) ;;
        permanent-http) forced_timeout=0; status=404 ;;
        proxy) extra=(--proxy http://127.0.0.1:9 --no-proxy localhost) ;;
    esac
    run_check "Axel is not used for $mode" 3 with_clients curl "$available" \
        env CHECKCRT_TEST_FORCE_TIMEOUT="$forced_timeout" CHECKCRT_TEST_HTTP_STATUS="$status" \
        "$check" "${args[@]}" "${extra[@]}" 127.0.0.1 19191
    assert "$mode never calls Axel" count_is "$CHECKCRT_AXEL_LOG" 0
done
run_check 'invalid Axel CRL signature is rejected' 3 env CHECKCRT_TEST_FORCE_TIMEOUT=1 CHECKCRT_AXEL_MODE=invalid \
    "$check" "${args[@]}" --cache-dir "$fixture_dir/invalid-cache" 127.0.0.1 19191
assert 'unverified download is not cached' test "$(find "$fixture_dir/invalid-cache" -name 'v1-crl-*.pem' | wc -l)" -eq 0
run_check 'Axel permanent failure stops retries' 3 env CHECKCRT_TEST_FORCE_TIMEOUT=1 CHECKCRT_AXEL_MODE=failure \
    "$check" "${args[@]}" 127.0.0.1 19191
assert 'permanent failure makes only one Axel attempt' count_is "$CHECKCRT_AXEL_LOG" 1
run_check 'Axel deadline keeps original retry budget' 3 env CHECKCRT_TEST_FORCE_TIMEOUT=1 CHECKCRT_AXEL_MODE=timeout \
    "$check" "${args[@]}" --request-timeout 1 127.0.0.1 19191
assert 'two remaining retries use Axel' count_is "$CHECKCRT_AXEL_LOG" 2
assert 'Axel timeout stays bounded' json_matches '.[0].elapsed_seconds >= 2 and .[0].elapsed_seconds < 10'
run_check 'Axel partial data/state survives between retries' 0 env CHECKCRT_TEST_FORCE_TIMEOUT=1 CHECKCRT_AXEL_MODE=resume \
    "$check" "${args[@]}" --request-timeout 1 127.0.0.1 19191
assert 'resumed attempt produces verified evidence' json_matches '.[0].overall == "VALID"'
assert 'resume uses exactly two Axel attempts' count_is "$CHECKCRT_AXEL_LOG" 2

printf '127.0.0.1 19191\n127.0.0.1 19191\n127.0.0.1 19191\n' > "$fixture_dir/hosts"
run_check 'parallel workers share Axel download' 0 env CHECKCRT_TEST_FORCE_TIMEOUT=1 \
    "$check" "${args[@]}" --parallel 3 --hosts-file "$fixture_dir/hosts" --cache-dir "$fixture_dir/parallel-cache"
assert 'parallel workers use one ordinary attempt' count_is "$CHECKCRT_TEST_FETCH_LOG" 1
assert 'parallel workers use one Axel attempt' count_is "$CHECKCRT_AXEL_LOG" 1
assert 'parallel results contain one miss and two hits' \
    json_matches 'length == 3 and all(.[]; .overall == "VALID") and ([.[].cache_misses] | add) == 1 and ([.[].cache_hits] | add) == 2'

run_check 'parallel Axel timeouts share one failure cooldown' 1 env CHECKCRT_TEST_FORCE_TIMEOUT=1 CHECKCRT_AXEL_MODE=timeout \
    "$check" "${args[@]}" --connect-retries 1 --request-timeout 1 --parallel 3 \
    --hosts-file "$fixture_dir/hosts" --cache-dir "$fixture_dir/failed-cache"
assert 'failed parallel fetch has one ordinary attempt' count_is "$CHECKCRT_TEST_FETCH_LOG" 1
assert 'failed parallel fetch has one Axel attempt' count_is "$CHECKCRT_AXEL_LOG" 1
assert 'shared failure supplies no positive evidence or hits' \
    json_matches 'length == 3 and all(.[]; .overall == "UNKNOWN" and .cache_hits == 0) and ([.[].cache_misses] | add) == 1'
run_check 'another invocation respects Axel failure cooldown' 3 env CHECKCRT_TEST_FORCE_TIMEOUT=1 \
    "$check" "${args[@]}" --cache-dir "$fixture_dir/failed-cache" 127.0.0.1 19191
assert 'cooldown avoids ordinary client request' count_is "$CHECKCRT_TEST_FETCH_LOG" 0
assert 'cooldown avoids Axel request' count_is "$CHECKCRT_AXEL_LOG" 0
assert 'cooldown does not count as a hit or miss' json_matches '.[0].cache_hits == 0 and .[0].cache_misses == 0'

run_check 'cache bypass still allows verified Axel download' 0 env CHECKCRT_TEST_FORCE_TIMEOUT=1 \
    "$check" "${args[@]}" --no-cache --cache-dir "$fixture_dir/bypassed-cache" 127.0.0.1 19191
assert 'cache bypass never creates persistent directory' test ! -e "$fixture_dir/bypassed-cache"
assert 'cache bypass records no hits or misses' json_matches '.[0].cache_hits == 0 and .[0].cache_misses == 0'
run_check 'cache bypass ignores an already warm cache' 0 env CHECKCRT_TEST_FORCE_TIMEOUT=1 \
    "$check" "${args[@]}" --no-cache --cache-dir "$fixture_dir/cache-curl" 127.0.0.1 19191
assert 'bypass performs fresh Axel download despite warm cache' count_is "$CHECKCRT_AXEL_LOG" 1
assert 'bypass verifies data without cache metrics' json_matches '.[0].overall == "VALID" and .[0].cache_hits == 0 and .[0].cache_misses == 0'
printf '\nAxel fallback tests: %s passed, %s failed.\n' "$pass" "$fail"
(( fail == 0 ))
