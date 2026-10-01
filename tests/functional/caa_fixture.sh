#!/usr/bin/env bash
# Deterministic resolver replies; never sends DNS requests.
set -euo pipefail
resolver=${0##*/}
case "$CHECKCRT_CAA_MODE" in
    timeout) exec sleep 20 ;;
    failure) echo 'connection refused' >&2; exit 1 ;;
    empty) exit 0 ;;
esac
case "$resolver" in
    dig)
        status=NOERROR
        case "$CHECKCRT_CAA_MODE" in
            servfail) status=SERVFAIL ;;
            nxdomain) status=NXDOMAIN ;;
        esac
        printf ';; ->>HEADER<<- opcode: QUERY, status: %s, id: 1\n' "$status"
        if [[ "$CHECKCRT_CAA_MODE" == records ]]; then
            printf 'backend.test.\t60\tIN\tCAA\t0 issue "ca.example"\n'
        fi
        ;;
    host)
        case "$CHECKCRT_CAA_MODE" in
            records) echo 'backend.test has CAA record 0 issue "ca.example"' ;;
            nodata) echo 'backend.test has no CAA record' ;;
            servfail) echo 'Host backend.test not found: 2(SERVFAIL)'; exit 1 ;;
            nxdomain) echo 'Host backend.test not found: 3(NXDOMAIN)'; exit 1 ;;
        esac
        ;;
    nslookup)
        case "$CHECKCRT_CAA_MODE" in
            records) printf 'backend.test\tcaa = 0 issue "ca.example"\n' ;;
            nodata) echo "*** Can't find backend.test: No answer" ;;
            servfail) echo '** server cannot find backend.test: SERVFAIL' ;;
            nxdomain) echo '** server cannot find backend.test: NXDOMAIN'; exit 1 ;;
        esac
        ;;
esac
