#!/usr/bin/env bash
# BusyBox CGI OCSP responder. Signs real requests using a disposable PKI.
set -euo pipefail
fixture_dir=${CHECKCRT_OCSP_DIR:?}
request_dir=$(mktemp -d "$fixture_dir/request.XXXXXX")
trap 'rm -rf "$request_dir"' EXIT
[[ ${CONTENT_LENGTH:-} =~ ^[0-9]{1,5}$ ]] || exit 1
dd bs=1 count="$CONTENT_LENGTH" of="$request_dir/request.der" 2>/dev/null
printf '%s\n' "${PATH_INFO:-}" >> "$fixture_dir/requests.log"
mode=$(< "$fixture_dir/mode")
if [[ "$mode" == offline ]]; then
    printf 'Status: 503 Service Unavailable\r\nContent-Type: text/plain\r\n\r\noffline\n'
    exit 0
fi
ca=issuer
[[ ${PATH_INFO:-} == /root ]] && ca=root
args=(-index "$fixture_dir/$ca.index" -CA "$fixture_dir/$ca.pem"
    -rsigner "$fixture_dir/$ca.pem" -rkey "$fixture_dir/$ca.key"
    -reqin "$request_dir/request.der" -respout "$request_dir/response.der")
if [[ "$ca" == issuer ]]; then
    case "$mode" in
        unknown) args+=(-index "$fixture_dir/empty.index") ;;
        badsig) args+=(-badsig) ;;
        wrong-id) args+=(-reqin "$fixture_dir/revoked.req") ;;
        wrong-signer) args+=(-rsigner "$fixture_dir/root.pem" -rkey "$fixture_dir/root.key") ;;
    esac
elif [[ "$mode" == root-revoked ]]; then
    args+=(-index "$fixture_dir/root-revoked.index")
fi
case "$mode" in
    no-next) ;;
    short-next) args+=(-nmin 1) ;;
    *) args+=(-ndays 2) ;;
esac
if ! openssl ocsp "${args[@]}" >/dev/null 2>"$request_dir/errors"; then
    cat "$request_dir/errors" >&2
    printf 'Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n'
    cat "$request_dir/errors"
    exit 0
fi
printf 'Content-Type: application/ocsp-response\r\n\r\n'
cat "$request_dir/response.der"
