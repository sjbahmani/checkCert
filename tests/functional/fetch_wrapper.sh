#!/usr/bin/env bash
# Test-only curl/wget shim: record actual fetches and simulate HTTP outages.
# run.sh installs it under the available client's name in a temporary PATH.
set -euo pipefail
printf '%s\n' "${!#}" >> "$CHECKCRT_TEST_FETCH_LOG"
network_rc=7 http_rc=22
[[ ${0##*/} != wget ]] || { network_rc=4; http_rc=8; }
if [[ ${0##*/} == wget && -n ${CHECKCRT_TEST_WGET_ARGS:-} ]]; then
    printf '%s\n' "$@" > "$CHECKCRT_TEST_WGET_ARGS"
fi
if [[ ${CHECKCRT_TEST_FORCE_TIMEOUT:-0} == 1 ]]; then
    # Include partial bytes to prove they cannot be accepted as Axel output.
    output=
    args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
        case "${args[$i]}" in
            --output) output=${args[$((i+1))]} ;;
            --output-document=*) output=${args[$i]#*=} ;;
        esac
    done
    [[ -z "$output" ]] || printf 'partial ordinary-client download\n' > "$output"
    echo 'Operation timed out (fixture)' >&2
    [[ ${0##*/} != wget ]] || exit 4
    exit 28
fi
if [[ -n "${CHECKCRT_TEST_HTTP_STATUS:-}" ]]; then
    if [[ ${0##*/} == wget ]]; then
        printf '  HTTP/1.1 %s Fixture response\n' "$CHECKCRT_TEST_HTTP_STATUS" >&2
    else
        printf '%s' "$CHECKCRT_TEST_HTTP_STATUS"
    fi
    exit "$http_rc"
fi
if (( $(wc -l < "$CHECKCRT_TEST_FETCH_LOG") <= ${CHECKCRT_TEST_FETCH_FAILURES:-0} )); then
    echo 'Simulated temporary download failure' >&2
    exit "$network_rc"
fi
if [[ -e "$CHECKCRT_TEST_OFFLINE" ]]; then
    echo 'Simulated CRL/AIA HTTP outage' >&2
    exit "$network_rc"
fi
if [[ -n "${CHECKCRT_TEST_FETCH_DELAY:-}" ]]; then
    sleep "$CHECKCRT_TEST_FETCH_DELAY"
fi
exec "$CHECKCRT_TEST_FETCH_BIN" "$@"
