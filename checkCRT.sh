#!/usr/bin/env bash
# Check the certificate presented by a TLS service against its CRL(s).
# Exit codes: 0 = valid, not expired, and not revoked; 2 = revoked;
#             3 = unknown/error; 4 = expired; 5 = untrusted/invalid identity.

set -u -o pipefail

VERSION=1.2.0
verify_peer=1
peer_valid=0
ca_file=
ca_path=
output_format=text
connect_timeout=20
request_timeout=45
max_ocsp_age=86400
clock_skew=300
proxy=
no_proxy=
positionals=()

usage() {
    cat <<EOF
Usage: ${0##*/} [options] <domain-or-IP> [port]

Options:
  --verify-peer       Verify the certificate chain and hostname/IP (default;
                      retained for compatibility).
  --ca-file FILE      Additional PEM trust bundle for chain verification.
  --ca-path DIR       Directory of hashed CA certificates for verification.
  --json              Write the final status as JSON to standard output.
  --connect-timeout N TLS connection timeout in seconds (default: 20).
  --request-timeout N CRL/OCSP request timeout in seconds (default: 45).
  --max-ocsp-age N    Maximum OCSP response age in seconds (default: 86400).
  --clock-skew N      Allowed clock skew for OCSP in seconds (default: 300).
  --proxy URL         HTTP(S) proxy for CRL/OCSP HTTP requests.
  --no-proxy HOSTS    Comma-separated hosts that bypass the proxy.
  -h, --help          Show this help.
  --version           Show the version.
EOF
}

while (( $# > 0 )); do
    case $1 in
        -h|--help) usage; exit 0 ;;
        --version) printf '%s %s\n' "${0##*/}" "$VERSION"; exit 0 ;;
        --verify-peer) verify_peer=1 ;;
        --json) output_format=json ;;
        --connect-timeout|--request-timeout|--max-ocsp-age|--clock-skew|--proxy|--no-proxy|--ca-path)
            option_name=$1
            shift
            [[ $# -gt 0 ]] || { echo "Error: $option_name requires a value." >&2; exit 1; }
            case $option_name in
                --connect-timeout) connect_timeout=$1 ;;
                --request-timeout) request_timeout=$1 ;;
                --max-ocsp-age) max_ocsp_age=$1 ;;
                --clock-skew) clock_skew=$1 ;;
                --proxy) proxy=$1 ;;
                --no-proxy) no_proxy=$1 ;;
                --ca-path) ca_path=$1 ;;
            esac
            ;;
        --ca-file)
            shift
            [[ $# -gt 0 ]] || { echo "Error: --ca-file requires a file path." >&2; exit 1; }
            ca_file=$1
            ;;
        --ca-file=*) ca_file=${1#--ca-file=} ;;
        --ca-path=*) ca_path=${1#--ca-path=} ;;
        --connect-timeout=*) connect_timeout=${1#--connect-timeout=} ;;
        --request-timeout=*) request_timeout=${1#--request-timeout=} ;;
        --max-ocsp-age=*) max_ocsp_age=${1#--max-ocsp-age=} ;;
        --clock-skew=*) clock_skew=${1#--clock-skew=} ;;
        --proxy=*) proxy=${1#--proxy=} ;;
        --no-proxy=*) no_proxy=${1#--no-proxy=} ;;
        --) shift; positionals+=("$@"); break ;;
        -*) echo "Error: unknown option: $1" >&2; usage; exit 1 ;;
        *) positionals+=("$1") ;;
    esac
    shift
done

if (( ${#positionals[@]} < 1 || ${#positionals[@]} > 2 )); then usage >&2; exit 1; fi
domain=${positionals[0]}
port=${positionals[1]:-443}
if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "Error: port must be between 1 and 65535." >&2
    exit 1
fi
if [[ -n "$ca_file" && ! -r "$ca_file" ]]; then
    echo "Error: CA file is not readable: $ca_file" >&2
    exit 1
fi
if [[ -n "$ca_path" && ! -d "$ca_path" ]]; then
    echo "Error: CA path is not a directory: $ca_path" >&2
    exit 1
fi
for setting in connect_timeout request_timeout max_ocsp_age clock_skew; do
    value=${!setting}
    if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value < 1 )); then
        echo "Error: $setting must be a positive number of seconds." >&2
        exit 1
    fi
done
for command in openssl awk sed grep mktemp timeout tr sort date; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "Error: '$command' is required." >&2; exit 3;
    }
done

# JSON is intentionally the only standard-output payload in this mode; all
# progress and diagnostic output continues on standard error.
if [[ "$output_format" == json ]]; then
    exec 3>&1
    exec 1>&2
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/checkcrl.XXXXXX")
trap 'rm -rf "$workdir"' EXIT

fetch() {
    local url=$1 destination=$2
    if command -v curl >/dev/null 2>&1; then
        curl_args=(--fail --location --silent --show-error --connect-timeout "$connect_timeout" --max-time "$request_timeout")
        [[ -n "$proxy" ]] && curl_args+=(--proxy "$proxy")
        [[ -n "$no_proxy" ]] && curl_args+=(--noproxy "$no_proxy")
        curl "${curl_args[@]}" --output "$destination" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget_args=(--quiet --timeout="$connect_timeout" --tries=2 --output-document="$destination")
        [[ -n "$proxy" ]] && wget_args+=(-e use_proxy=yes -e "http_proxy=$proxy" -e "https_proxy=$proxy")
        [[ -n "$no_proxy" ]] && wget_args+=(-e "no_proxy=$no_proxy")
        wget "${wget_args[@]}" "$url"
    else
        echo "Error: curl or wget is required to download CRLs." >&2; return 1
    fi
}

connection_host=$domain
if [[ "$connection_host" =~ ^\[(.*)\]$ ]]; then connection_host=${BASH_REMATCH[1]}; fi
is_ip=0
if [[ "$connection_host" == *:* || "$connection_host" =~ ^[0-9.]+$ ]]; then is_ip=1; fi
if (( is_ip == 1 )); then
    sni_args=()
else
    sni_args=(-servername "$connection_host")
fi
if [[ "$connection_host" == *:* ]]; then
    connect_target="[$connection_host]:$port"
else
    connect_target="$connection_host:$port"
fi

echo "Fetching TLS certificate from ${domain}:${port} ..."
if ! timeout "$connect_timeout" openssl s_client -connect "$connect_target" "${sni_args[@]}" \
    -showcerts -status </dev/null >"$workdir/s_client.txt" 2>/dev/null; then
    echo "Error: unable to connect or retrieve the certificate chain." >&2; exit 3
fi
if ! awk -v output_dir="$workdir" '
        /-----BEGIN CERTIFICATE-----/ { number++; file=output_dir "/cert-" number ".pem"; writing=1 }
        writing { print > file }
        /-----END CERTIFICATE-----/ { close(file); writing=0 }
    ' "$workdir/s_client.txt"; then
    echo "Error: unable to connect or retrieve the certificate chain." >&2; exit 3
fi

stapled_ocsp='NOT STAPLED'
if grep -q 'OCSP response: no response sent' "$workdir/s_client.txt"; then
    :
elif grep -qi 'Cert Status: *good' "$workdir/s_client.txt"; then
    stapled_ocsp='PRESENT/GOOD (UNVERIFIED)'
elif grep -qi 'Cert Status: *revoked' "$workdir/s_client.txt"; then
    stapled_ocsp='PRESENT/REVOKED (UNVERIFIED)'
elif grep -q 'OCSP response:' "$workdir/s_client.txt"; then
    stapled_ocsp='PRESENT/UNKNOWN (UNVERIFIED)'
fi

leaf="$workdir/cert-1.pem"
[[ -s "$leaf" ]] || { echo "Error: the server did not present a certificate." >&2; exit 3; }
if ! openssl x509 -in "$leaf" -noout >/dev/null 2>&1; then
    echo "Error: the server returned an unreadable certificate." >&2
    exit 3
fi

echo
echo "Certificate information"
openssl x509 -in "$leaf" -noout -subject -issuer -serial -dates -fingerprint -sha256
openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null || true

certificate_expired=0
if openssl x509 -in "$leaf" -noout -checkend 0 >/dev/null 2>&1; then
    echo "Certificate expiry: not expired"
else
    certificate_expired=1
    echo "Certificate validity: EXPIRED (or expires at the current time)" >&2
fi

serial=$(openssl x509 -in "$leaf" -noout -serial | sed 's/^serial=//' | tr -d ':' | tr '[:lower:]' '[:upper:]')
leaf_issuer=$(openssl x509 -in "$leaf" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
issuer_cert=
is_issuer_of_leaf() {
    local candidate=$1 candidate_subject
    candidate_subject=$(openssl x509 -in "$candidate" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')
    [[ "$candidate_subject" == "$leaf_issuer" ]] || return 1
    # A matching distinguished name alone is not enough: prove this key signed
    # the leaf before using it to verify CRL or OCSP data.
    openssl verify -partial_chain -CAfile "$candidate" "$leaf" >/dev/null 2>&1
}

for certificate in "$workdir"/cert-*.pem; do
    [[ "$certificate" == "$leaf" ]] && continue
    if is_issuer_of_leaf "$certificate"; then issuer_cert=$certificate; break; fi
done

# Some servers omit intermediates.  Retrieve the issuing CA certificate from
# the Authority Information Access extension when it is available.
if [[ -z "$issuer_cert" ]]; then
    mapfile -t issuer_urls < <(
        openssl x509 -in "$leaf" -noout -ext authorityInfoAccess 2>/dev/null \
            | grep -oE 'CA Issuers - URI:[^,[:space:]]+' | sed 's/^CA Issuers - URI://' | sort -u
    )
    for index in "${!issuer_urls[@]}"; do
        issuer_download="$workdir/issuer-${index}.bin"
        issuer_candidate="$workdir/issuer-${index}.pem"
        if ! fetch "${issuer_urls[$index]}" "$issuer_download"; then continue; fi
        if openssl x509 -inform DER -in "$issuer_download" -out "$issuer_candidate" >/dev/null 2>&1; then :
        elif openssl x509 -inform PEM -in "$issuer_download" -out "$issuer_candidate" >/dev/null 2>&1; then :
        else continue; fi
        if is_issuer_of_leaf "$issuer_candidate"; then issuer_cert=$issuer_candidate; break; fi
    done
fi
[[ -n "$issuer_cert" ]] || echo "Warning: issuer certificate unavailable; CRL signatures cannot be verified." >&2

# s_client does not validate the server certificate by default. A CRL signed by
# an untrusted CA is not enough, so always validate the chain and identity.
if (( verify_peer == 1 )); then
    chain_bundle="$workdir/intermediates.pem"
    : > "$chain_bundle"
    for certificate in "$workdir"/cert-*.pem; do
        [[ "$certificate" == "$leaf" ]] && continue
        awk '{ print }' "$certificate" >> "$chain_bundle"
    done
    verify_args=(-purpose sslserver)
    if (( is_ip == 1 )); then
        verify_args+=(-verify_ip "$connection_host")
    else
        verify_args+=(-verify_hostname "$connection_host")
    fi
    [[ -s "$chain_bundle" ]] && verify_args+=(-untrusted "$chain_bundle")
    [[ -n "$ca_file" ]] && verify_args+=(-CAfile "$ca_file")
    [[ -n "$ca_path" ]] && verify_args+=(-CApath "$ca_path")
    echo
    echo "Verifying certificate chain and identity ..."
    if ! openssl verify "${verify_args[@]}" "$leaf"; then
        peer_valid=0
        echo "Certificate trust: INVALID (chain or hostname/IP verification failed)." >&2
    else
        peer_valid=1
        echo "Certificate trust: valid"
    fi
fi

mapfile -t crl_urls < <(
    openssl x509 -in "$leaf" -noout -ext crlDistributionPoints 2>/dev/null \
        | grep -oE 'URI:[^,[:space:]]+' | sed 's/^URI://' | sort -u
)

echo
if (( ${#crl_urls[@]} == 0 )); then
    echo "CRL status: no CRL distribution point in this certificate."
else
    echo "CRL distribution point(s):"
    printf '  %s\n' "${crl_urls[@]}"
fi

checked=0
revoked=0
crl_is_current() {
    local crl=$1 last_update next_update last_epoch next_epoch now
    last_update=$(openssl crl -in "$crl" -noout -lastupdate | sed 's/^lastUpdate=//')
    next_update=$(openssl crl -in "$crl" -noout -nextupdate | sed 's/^nextUpdate=//')
    [[ -n "$last_update" && -n "$next_update" ]] || return 1
    last_epoch=$(date -u -d "$last_update" +%s 2>/dev/null) || return 1
    next_epoch=$(date -u -d "$next_update" +%s 2>/dev/null) || return 1
    now=$(date -u +%s)
    (( last_epoch <= now + clock_skew && next_epoch > now - clock_skew ))
}

crl_has_serial() {
    # Comparing the extracted value avoids prefix matches (e.g. AB vs ABC).
    openssl crl -in "$1" -noout -text | awk -v target="$serial" '
        BEGIN { target = toupper(target); found = 0 }
        /^[[:space:]]*Serial Number:/ {
            value = $0
            sub(/^[[:space:]]*Serial Number:[[:space:]]*/, "", value)
            gsub(/[^[:xdigit:]]/, "", value)
            if (toupper(value) == target) found = 1
        }
        END { exit !found }
    '
}

for index in "${!crl_urls[@]}"; do
    url=${crl_urls[$index]}; downloaded="$workdir/crl-${index}.bin"; crl_pem="$workdir/crl-${index}.pem"
    echo; echo "Checking CRL: $url"
    if ! fetch "$url" "$downloaded"; then echo "  Result: unable to download CRL" >&2; continue; fi
    if openssl crl -inform DER -in "$downloaded" -out "$crl_pem" >/dev/null 2>&1; then :
    elif openssl crl -inform PEM -in "$downloaded" -out "$crl_pem" >/dev/null 2>&1; then :
    else echo "  Result: downloaded file is not a readable CRL" >&2; continue; fi
    openssl crl -in "$crl_pem" -noout -issuer -lastupdate -nextupdate
    if [[ -z "$issuer_cert" ]] || ! openssl crl -in "$crl_pem" -noout -verify -CAfile "$issuer_cert" >/dev/null 2>&1; then
        echo "  Result: CRL signature could not be verified" >&2; continue
    fi
    if ! crl_is_current "$crl_pem"; then
        echo "  Result: CRL is stale, not yet valid, or has no usable update period" >&2; continue
    fi
    checked=$((checked + 1))
    if crl_has_serial "$crl_pem"; then
        echo "  Result: REVOKED"
        revoked=1
        break
    fi
    echo "  Result: not listed as revoked"
done

echo
echo "STAPLED OCSP: $stapled_ocsp"
ocsp_good=0
ocsp_url=$(openssl x509 -in "$leaf" -noout -ocsp_uri 2>/dev/null || true)
if (( revoked == 1 )); then
    echo "OCSP status: skipped because a verified CRL lists the certificate as REVOKED."
elif [[ -n "$ocsp_url" ]]; then
    echo "Checking OCSP: $ocsp_url"
    if [[ -z "$issuer_cert" ]]; then
        echo "  Result: issuer certificate unavailable; OCSP response cannot be verified" >&2
    else
        ocsp_proxy_args=()
        [[ -n "$proxy" ]] && ocsp_proxy_args+=(-proxy "$proxy")
        [[ -n "$no_proxy" ]] && ocsp_proxy_args+=(-no_proxy "$no_proxy")
        ocsp_output=$(timeout "$request_timeout" openssl ocsp -issuer "$issuer_cert" -cert "$leaf" -url "$ocsp_url" \
            -no_nonce -CAfile "$issuer_cert" -partial_chain -validity_period "$clock_skew" \
            -status_age "$max_ocsp_age" "${ocsp_proxy_args[@]}" 2>&1)
        ocsp_status=$?
        if (( ocsp_status != 0 )); then
            echo "  Result: OCSP query or response verification failed" >&2
            printf '%s\n' "$ocsp_output" | sed 's/^/    /' >&2
        elif printf '%s\n' "$ocsp_output" | grep -qi ': revoked'; then
            printf '%s\n' "$ocsp_output" | grep -Ei ': revoked|This Update|Next Update|Revocation Time' | sed 's/^/  /'
            echo "  Result: REVOKED"
            revoked=1
        elif printf '%s\n' "$ocsp_output" | grep -qi ': good'; then
            printf '%s\n' "$ocsp_output" | grep -Ei ': good|This Update|Next Update' | sed 's/^/  /'
            echo "  Result: good (verified OCSP response)"
            ocsp_good=1
        else
            echo "  Result: OCSP responder returned an unknown status" >&2
        fi
    fi
else
    echo "OCSP status: no OCSP responder URL in this certificate."
fi

echo
if (( peer_valid == 1 )); then trust_status=TRUSTED; else trust_status=UNTRUSTED/INVALID; fi
if (( certificate_expired == 1 )); then expiry_status=EXPIRED; else expiry_status='NOT EXPIRED'; fi
if (( revoked == 1 )); then
    revocation_status=REVOKED
elif (( checked > 0 || ocsp_good > 0 )); then
    revocation_status='NOT REVOKED'
else
    revocation_status=UNKNOWN
fi

if (( revoked == 1 )); then
    overall_status=REVOKED
    exit_code=2
elif (( certificate_expired == 1 )); then
    overall_status=EXPIRED
    exit_code=4
elif (( peer_valid != 1 )); then
    overall_status=UNTRUSTED/INVALID
    exit_code=5
elif [[ "$revocation_status" == 'NOT REVOKED' ]]; then
    overall_status=VALID
    exit_code=0
else
    overall_status=UNKNOWN
    exit_code=3
fi

certificate_subject() {
    openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//'
}

certificate_issuer() {
    openssl x509 -in "$1" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//'
}

find_presented_issuer() {
    local child=$1 expected_issuer=$2 candidate candidate_subject
    local -a candidates=("$workdir"/cert-*.pem)
    [[ -n "$issuer_cert" ]] && candidates+=("$issuer_cert")
    for candidate in "${candidates[@]}"; do
        [[ "$candidate" == "$child" ]] && continue
        candidate_subject=$(certificate_subject "$candidate")
        [[ "$candidate_subject" == "$expected_issuer" ]] || continue
        if openssl verify -partial_chain -CAfile "$candidate" "$child" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

certificate_trust() {
    local certificate=$1
    local -a ca_verify_args=(-purpose any)
    [[ -s "$chain_bundle" ]] && ca_verify_args+=(-untrusted "$chain_bundle")
    [[ -n "$ca_file" ]] && ca_verify_args+=(-CAfile "$ca_file")
    [[ -n "$ca_path" ]] && ca_verify_args+=(-CApath "$ca_path")
    if openssl verify "${ca_verify_args[@]}" "$certificate" >/dev/null 2>&1; then
        printf 'TRUSTED'
    else
        printf 'UNTRUSTED/INVALID'
    fi
}

print_ca_tree() {
    local current=$leaf parent subject issuer label root_suffix signature_status trust_result indent='' child_indent depth=0
    echo "CA TREE"
    while :; do
        subject=$(certificate_subject "$current")
        issuer=$(certificate_issuer "$current")
        parent=
        if [[ "$subject" == "$issuer" ]]; then
            label='ROOT CA'
            root_suffix=' [PRESENTED]'
            signature_status='SELF-SIGNED'
        elif (( depth == 0 )); then
            label=CERTIFICATE
            root_suffix=
            if parent=$(find_presented_issuer "$current" "$issuer"); then signature_status=VALID; else signature_status=UNKNOWN; fi
        else
            label=CA
            root_suffix=
            if parent=$(find_presented_issuer "$current" "$issuer"); then signature_status=VALID; else signature_status=UNKNOWN; fi
        fi
        if (( depth == 0 )); then trust_result=$trust_status; else trust_result=$(certificate_trust "$current"); fi
        printf '%s└── %s: %s%s [TRUST: %s] [SIGNATURE: %s]\n' \
            "$indent" "$label" "$subject" "$root_suffix" "$trust_result" "$signature_status"
        child_indent="${indent}    "
        if [[ "$subject" == "$issuer" ]]; then
            return
        fi
        if [[ -z "$parent" ]]; then
            printf '%s└── ISSUER: %s [NOT PROVIDED]\n' "$child_indent" "$issuer"
            return
        fi
        indent=$child_indent
        current=$parent
        depth=$((depth + 1))
        if (( depth == 10 )); then
            printf '%sISSUER CHAIN DEPTH LIMIT REACHED\n' "$indent"
            return
        fi
    done
}

print_ca_tree
echo
if [[ "$output_format" == json ]]; then
    json_escape() {
        printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
    }
    printf '{"host":"%s","port":%s,"trust":"%s","revocation":"%s","expiry":"%s","stapled_ocsp":"%s","overall":"%s","exit_code":%s}\n' \
        "$(json_escape "$domain")" "$port" "$(json_escape "$trust_status")" \
        "$(json_escape "$revocation_status")" "$(json_escape "$expiry_status")" \
        "$(json_escape "$stapled_ocsp")" "$(json_escape "$overall_status")" "$exit_code" >&3
else
    echo "FINAL STATUS"
    printf '  TRUST: %s\n' "$trust_status"
    printf '  REVOCATION: %s\n' "$revocation_status"
    printf '  EXPIRY: %s\n' "$expiry_status"
    printf '  OVERALL: %s\n' "$overall_status"
fi
exit "$exit_code"
