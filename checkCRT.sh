#!/usr/bin/env bash
# Check the certificate presented by a TLS service against its CRL(s).
# Exit codes: 0 = valid, not expired, and not revoked; 2 = revoked (the leaf
#             or an intermediate CA in its chain); 3 = unknown/error;
#             4 = expired; 5 = untrusted/invalid identity; 6 = valid but
#             expiring soon (only with --fail-on-expiry-warning).
# In --hosts-file (batch) mode the process exit code is 0 if every host
# exited 0, otherwise 1; inspect each host's own result for detail.

set -u -o pipefail

VERSION=1.4.0
verify_peer=1
ca_file=
ca_path=
output_format=text
connect_timeout=20
request_timeout=45
max_ocsp_age=86400
clock_skew=300
proxy=
no_proxy=
starttls_proto=
expiry_warn_days=30
check_caa=1
fail_on_expiry_warning=0
hosts_file=
positionals=()

usage() {
    cat <<EOF
Usage: ${0##*/} [options] <domain-or-IP> [port]
       ${0##*/} [options] --hosts-file FILE

Options:
  --verify-peer       Verify the certificate chain and hostname/IP (default;
                      retained for compatibility).
  --ca-file FILE      Additional PEM trust bundle for chain verification.
  --ca-path DIR       Directory of hashed CA certificates for verification.
  --json              Write the final status as JSON to standard output
                      (one object per host, newline-delimited in batch mode).
  --connect-timeout N TLS connection timeout in seconds (default: 20).
  --request-timeout N CRL/OCSP request timeout in seconds (default: 45).
  --max-ocsp-age N    Maximum OCSP response age in seconds (default: 86400).
  --clock-skew N      Allowed clock skew for OCSP in seconds (default: 300).
  --proxy URL         HTTP(S) proxy for CRL/OCSP HTTP requests.
  --no-proxy HOSTS    Comma-separated hosts that bypass the proxy.
  --starttls PROTO    Negotiate STARTTLS before the TLS handshake (e.g. smtp,
                      imap, pop3, ftp, nntp, ldap, xmpp, postgres, mysql).
                      Applies to every host checked.
  --expiry-warn-days N Warn when the certificate expires within N days
                      (default: 30; 0 disables the warning).
  --fail-on-expiry-warning
                      Exit 6 instead of 0 when only the expiry warning
                      applies (chain trusted, not revoked, not expired).
  --no-caa            Skip the DNS CAA record lookup.
  --hosts-file FILE   Check every "host [port]" line in FILE instead of a
                      single positional host/port. Blank lines and lines
                      starting with # are ignored. Other options (CA trust,
                      STARTTLS, timeouts, ...) apply to every host checked.
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
        --no-caa) check_caa=0 ;;
        --fail-on-expiry-warning) fail_on_expiry_warning=1 ;;
        --connect-timeout|--request-timeout|--max-ocsp-age|--clock-skew|--proxy|--no-proxy|--ca-path|--starttls|--expiry-warn-days|--hosts-file)
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
                --starttls) starttls_proto=$1 ;;
                --expiry-warn-days) expiry_warn_days=$1 ;;
                --hosts-file) hosts_file=$1 ;;
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
        --starttls=*) starttls_proto=${1#--starttls=} ;;
        --expiry-warn-days=*) expiry_warn_days=${1#--expiry-warn-days=} ;;
        --hosts-file=*) hosts_file=${1#--hosts-file=} ;;
        --) shift; positionals+=("$@"); break ;;
        -*) echo "Error: unknown option: $1" >&2; usage; exit 1 ;;
        *) positionals+=("$1") ;;
    esac
    shift
done

domain=
port=443
if [[ -n "$hosts_file" ]]; then
    if (( ${#positionals[@]} != 0 )); then usage >&2; exit 1; fi
    if [[ ! -r "$hosts_file" ]]; then
        echo "Error: hosts file is not readable: $hosts_file" >&2
        exit 1
    fi
else
    if (( ${#positionals[@]} < 1 || ${#positionals[@]} > 2 )); then usage >&2; exit 1; fi
    domain=${positionals[0]}
    port=${positionals[1]:-443}
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
if ! [[ "$expiry_warn_days" =~ ^[0-9]+$ ]]; then
    echo "Error: expiry_warn_days must be a non-negative number of days." >&2
    exit 1
fi
for command in openssl awk sed grep mktemp timeout tr sort date; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "Error: '$command' is required." >&2; exit 3;
    }
done
caa_tool=
if (( check_caa == 1 )); then
    for command in dig host nslookup; do
        if command -v "$command" >/dev/null 2>&1; then caa_tool=$command; break; fi
    done
fi

# JSON is intentionally the only standard-output payload in this mode; all
# progress and diagnostic output continues on standard error. In --hosts-file
# mode each host writes one JSON object, so stdout becomes newline-delimited
# JSON (NDJSON) rather than a single JSON array.
if [[ "$output_format" == json ]]; then
    exec 3>&1
    exec 1>&2
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/checkcrl.XXXXXX")
trap 'rm -rf "$workdir"' EXIT

add_warning() {
    warnings+=("$1")
    echo "Warning: $1" >&2
}

is_ldap_url() {
    [[ "$1" =~ ^[Ll][Dd][Aa][Pp][Ss]?: ]]
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

# Emits a JSON record for a host that failed before a full check could be
# completed (e.g. connection failure), so --json/--hosts-file consumers see
# one line per host attempted instead of that host silently disappearing.
emit_error_json() {
    local err_domain=$1 err_port=$2 message=$3
    batch_overall=ERROR
    batch_reason=$message
    [[ "$output_format" == json ]] || return 0
    printf '{"host":"%s","port":%s,"trust":null,"revocation":null,"expiry":null,"expiry_days_left":null,"intermediate_revoked":null,"stapled_ocsp":null,"overall":"ERROR","exit_code":3,"warnings":[],"error":"%s"}\n' \
        "$(json_escape "$err_domain")" "$err_port" "$(json_escape "$message")" >&3
}

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

crl_has_serial_for() {
    # Comparing the extracted value avoids prefix matches (e.g. AB vs ABC).
    local crl=$1 target=$2
    openssl crl -in "$crl" -noout -text | awk -v target="$target" '
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

certificate_subject() {
    openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//'
}

certificate_issuer() {
    openssl x509 -in "$1" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//'
}

# Checks a single certificate's own CRL/OCSP revocation status. Used both for
# the leaf (label "LEAF") and for each intermediate CA found in the chain, so
# a revoked intermediate is caught even when the leaf itself is fine.
check_certificate_revocation() {
    local cert=$1 label=$2 verifier=$3
    local cert_serial local_crl_urls idx url downloaded crl_pem
    local checked_local=0 revoked_local=0 ocsp_good_local=0
    local ocsp_url_local ocsp_output ocsp_rc ocsp_proxy_args

    cert_serial=$(openssl x509 -in "$cert" -noout -serial | sed 's/^serial=//' | tr -d ':' | tr '[:lower:]' '[:upper:]')
    mapfile -t local_crl_urls < <(
        openssl x509 -in "$cert" -noout -ext crlDistributionPoints 2>/dev/null \
            | grep -oE 'URI:[^,[:space:]]+' | sed 's/^URI://' | sort -u
    )

    echo
    if (( ${#local_crl_urls[@]} == 0 )); then
        echo "CRL status ($label): no CRL distribution point in this certificate."
    else
        echo "CRL distribution point(s) ($label):"
        printf '  %s\n' "${local_crl_urls[@]}"
    fi

    for idx in "${!local_crl_urls[@]}"; do
        url=${local_crl_urls[$idx]}
        downloaded="$host_workdir/crl-$$-$RANDOM-${idx}.bin"
        crl_pem="$host_workdir/crl-$$-$RANDOM-${idx}.pem"
        echo; echo "Checking CRL ($label): $url"
        if is_ldap_url "$url"; then echo "  Result: LDAP CRL retrieval is not supported by this script" >&2; continue; fi
        if ! fetch "$url" "$downloaded"; then echo "  Result: unable to download CRL" >&2; continue; fi
        if openssl crl -inform DER -in "$downloaded" -out "$crl_pem" >/dev/null 2>&1; then :
        elif openssl crl -inform PEM -in "$downloaded" -out "$crl_pem" >/dev/null 2>&1; then :
        else echo "  Result: downloaded file is not a readable CRL" >&2; continue; fi
        openssl crl -in "$crl_pem" -noout -issuer -lastupdate -nextupdate
        if [[ -z "$verifier" ]] || ! openssl crl -in "$crl_pem" -noout -verify -CAfile "$verifier" >/dev/null 2>&1; then
            echo "  Result: CRL signature could not be verified" >&2; continue
        fi
        if ! crl_is_current "$crl_pem"; then
            echo "  Result: CRL is stale, not yet valid, or has no usable update period" >&2; continue
        fi
        checked_local=$((checked_local + 1))
        if crl_has_serial_for "$crl_pem" "$cert_serial"; then
            echo "  Result: REVOKED"
            revoked_local=1
            break
        fi
        echo "  Result: not listed as revoked"
    done

    ocsp_url_local=$(openssl x509 -in "$cert" -noout -ocsp_uri 2>/dev/null || true)
    if (( revoked_local == 1 )); then
        echo "OCSP status ($label): skipped because a verified CRL lists the certificate as REVOKED."
    elif [[ -n "$ocsp_url_local" ]]; then
        echo "Checking OCSP ($label): $ocsp_url_local"
        if [[ -z "$verifier" ]]; then
            echo "  Result: issuer certificate unavailable; OCSP response cannot be verified" >&2
        else
            ocsp_proxy_args=()
            [[ -n "$proxy" ]] && ocsp_proxy_args+=(-proxy "$proxy")
            [[ -n "$no_proxy" ]] && ocsp_proxy_args+=(-no_proxy "$no_proxy")
            ocsp_output=$(timeout "$request_timeout" openssl ocsp -issuer "$verifier" -cert "$cert" -url "$ocsp_url_local" \
                -no_nonce -CAfile "$verifier" -partial_chain -validity_period "$clock_skew" \
                -status_age "$max_ocsp_age" "${ocsp_proxy_args[@]}" 2>&1)
            ocsp_rc=$?
            if (( ocsp_rc != 0 )); then
                echo "  Result: OCSP query or response verification failed" >&2
                printf '%s\n' "$ocsp_output" | sed 's/^/    /' >&2
            elif printf '%s\n' "$ocsp_output" | grep -qi ': revoked'; then
                printf '%s\n' "$ocsp_output" | grep -Ei ': revoked|This Update|Next Update|Revocation Time' | sed 's/^/  /'
                echo "  Result: REVOKED"
                revoked_local=1
            elif printf '%s\n' "$ocsp_output" | grep -qi ': good'; then
                printf '%s\n' "$ocsp_output" | grep -Ei ': good|This Update|Next Update' | sed 's/^/  /'
                echo "  Result: good (verified OCSP response)"
                ocsp_good_local=1
            else
                echo "  Result: OCSP responder returned an unknown status" >&2
            fi
        fi
    else
        echo "OCSP status ($label): no OCSP responder URL in this certificate."
    fi

    rc_checked=$checked_local
    rc_revoked=$revoked_local
    rc_ocsp_good=$ocsp_good_local
}

# Runs the full check for one host:port and returns the exit code (does not
# call exit itself, so --hosts-file can check many hosts in one process).
check_host() {
    local domain=$1 port=$2
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        echo "Error: port must be between 1 and 65535 (got '$port' for host '$domain')." >&2
        emit_error_json "$domain" "$port" "invalid port"
        return 3
    fi

    local host_workdir connection_host is_ip sni_args connect_target starttls_args
    local -a warnings=()
    local leaf stapled_ocsp
    local negotiated_protocol negotiated_cipher
    local leaf_text sig_alg pubkey_algo pubkey_bits key_usage_text
    local certificate_expired expiry_warning expiry_days_left end_date end_epoch
    local leaf_issuer issuer_cert
    local -a issuer_urls=()
    local index issuer_download issuer_candidate
    local chain_bundle
    local -a verify_args=()
    local peer_valid=0
    local -a chain_list=()
    local -A revocation_flag=()
    local intermediate_revoked=0
    local ci cert subj iss verifier
    local checked=0 revoked=0 ocsp_good=0
    local rc_checked rc_revoked rc_ocsp_good
    local trust_status expiry_status revocation_status overall_status exit_code reason
    local caa_records

    host_workdir=$(mktemp -d "$workdir/host.XXXXXX")

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

    starttls_args=()
    [[ -n "$starttls_proto" ]] && starttls_args=(-starttls "$starttls_proto")

    echo "Fetching TLS certificate from ${domain}:${port} ...${starttls_proto:+ (STARTTLS: $starttls_proto)}"
    if ! timeout "$connect_timeout" openssl s_client -connect "$connect_target" "${sni_args[@]}" \
        "${starttls_args[@]}" -showcerts -status </dev/null >"$host_workdir/s_client.txt" 2>/dev/null; then
        echo "Error: unable to connect, negotiate STARTTLS, or retrieve the certificate chain." >&2
        emit_error_json "$domain" "$port" "unable to connect, negotiate STARTTLS, or retrieve the certificate chain"
        return 3
    fi
    if ! awk -v output_dir="$host_workdir" '
            /-----BEGIN CERTIFICATE-----/ { number++; file=output_dir "/cert-" number ".pem"; writing=1 }
            writing { print > file }
            /-----END CERTIFICATE-----/ { close(file); writing=0 }
        ' "$host_workdir/s_client.txt"; then
        echo "Error: unable to connect or retrieve the certificate chain." >&2
        emit_error_json "$domain" "$port" "unable to connect or retrieve the certificate chain"
        return 3
    fi

    stapled_ocsp='NOT STAPLED'
    if grep -q 'OCSP response: no response sent' "$host_workdir/s_client.txt"; then
        :
    elif grep -qi 'Cert Status: *good' "$host_workdir/s_client.txt"; then
        stapled_ocsp='PRESENT/GOOD (UNVERIFIED)'
    elif grep -qi 'Cert Status: *revoked' "$host_workdir/s_client.txt"; then
        stapled_ocsp='PRESENT/REVOKED (UNVERIFIED)'
    elif grep -q 'OCSP response:' "$host_workdir/s_client.txt"; then
        stapled_ocsp='PRESENT/UNKNOWN (UNVERIFIED)'
    fi

    leaf="$host_workdir/cert-1.pem"
    if [[ ! -s "$leaf" ]]; then
        echo "Error: the server did not present a certificate." >&2
        emit_error_json "$domain" "$port" "the server did not present a certificate"
        return 3
    fi
    if ! openssl x509 -in "$leaf" -noout >/dev/null 2>&1; then
        echo "Error: the server returned an unreadable certificate." >&2
        emit_error_json "$domain" "$port" "the server returned an unreadable certificate"
        return 3
    fi

    echo
    echo "Certificate information"
    openssl x509 -in "$leaf" -noout -subject -issuer -serial -dates -fingerprint -sha256
    openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null || true

    echo
    echo "Connection security"
    negotiated_protocol=$(awk -F': ' '/^ *Protocol *:/{print $2; exit}' "$host_workdir/s_client.txt" | tr -d '\r ')
    negotiated_cipher=$(awk -F': ' '/^ *Cipher *:/{print $2; exit}' "$host_workdir/s_client.txt" | tr -d '\r ')
    [[ -n "$negotiated_protocol" ]] && echo "Negotiated protocol: $negotiated_protocol"
    [[ -n "$negotiated_cipher" ]] && echo "Negotiated cipher: $negotiated_cipher"
    case "$negotiated_protocol" in
        SSLv2|SSLv3|TLSv1|TLSv1.1) add_warning "negotiated protocol $negotiated_protocol is deprecated/weak." ;;
    esac
    if [[ "$negotiated_cipher" =~ (^|_)(NULL|EXPORT|RC4|RC2|DES|MD5|anon)(_|$) ]]; then
        add_warning "negotiated cipher $negotiated_cipher is weak."
    fi

    leaf_text=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null)
    sig_alg=$(awk '/Signature Algorithm/{print $NF; exit}' <<<"$leaf_text")
    echo "Signature algorithm: $sig_alg"
    if [[ "$sig_alg" =~ [Mm][Dd]5 || "$sig_alg" =~ [Ss][Hh][Aa]1[^0-9] || "$sig_alg" =~ [Ss][Hh][Aa]1$ ]]; then
        add_warning "certificate signature algorithm $sig_alg is weak (MD5/SHA-1)."
    fi

    pubkey_algo=$(awk '/Public Key Algorithm/{print $NF; exit}' <<<"$leaf_text")
    pubkey_bits=$(awk -F'[()]' '/Public-Key:/{print $2; exit}' <<<"$leaf_text" | awk '{print $1}')
    echo "Public key: ${pubkey_algo:-unknown} ${pubkey_bits:-?} bit"
    if [[ "$pubkey_algo" == *rsaEncryption* || "$pubkey_algo" == *dsaEncryption* ]] && [[ "$pubkey_bits" =~ ^[0-9]+$ ]] && (( pubkey_bits < 2048 )); then
        add_warning "public key is only $pubkey_bits bits for $pubkey_algo (< 2048 is weak)."
    elif [[ "$pubkey_algo" == *ecPublicKey* || "$pubkey_algo" == *id-ecPublicKey* ]] && [[ "$pubkey_bits" =~ ^[0-9]+$ ]] && (( pubkey_bits < 224 )); then
        add_warning "elliptic-curve public key is only $pubkey_bits bits (< 224 is weak)."
    fi

    echo
    echo "Key usage"
    key_usage_text=$(openssl x509 -in "$leaf" -noout -ext keyUsage,extendedKeyUsage 2>/dev/null)
    if [[ -n "$key_usage_text" ]]; then
        printf '%s\n' "$key_usage_text"
    else
        echo "  (no keyUsage/extendedKeyUsage extensions present)"
    fi
    if grep -qi 'Extended Key Usage' <<<"$key_usage_text" && ! grep -qi 'TLS Web Server Authentication' <<<"$key_usage_text"; then
        add_warning "extendedKeyUsage is present but does not include TLS Web Server Authentication."
    fi

    echo
    echo "Certificate Transparency"
    if grep -qi 'CT Precertificate SCTs\|1\.3\.6\.1\.4\.1\.11129\.2\.4\.2' <<<"$leaf_text"; then
        echo "SCT: embedded in certificate"
    elif grep -qi 'signed certificate timestamp' "$host_workdir/s_client.txt"; then
        echo "SCT: present via TLS extension (unverified)"
    else
        echo "SCT: none found"
        add_warning "no Certificate Transparency SCT found (embedded or via TLS extension)."
    fi

    certificate_expired=0
    expiry_warning=0
    expiry_days_left=
    if openssl x509 -in "$leaf" -noout -checkend 0 >/dev/null 2>&1; then
        end_date=$(openssl x509 -in "$leaf" -noout -enddate | sed 's/^notAfter=//')
        end_epoch=$(date -u -d "$end_date" +%s 2>/dev/null || true)
        if [[ -n "$end_epoch" ]]; then
            expiry_days_left=$(( (end_epoch - $(date -u +%s)) / 86400 ))
            if (( expiry_warn_days > 0 && expiry_days_left <= expiry_warn_days )); then
                expiry_warning=1
                add_warning "certificate expires in $expiry_days_left day(s) (within --expiry-warn-days $expiry_warn_days)."
            fi
        fi
        echo "Certificate expiry: not expired${expiry_days_left:+ ($expiry_days_left day(s) remaining)}"
    else
        certificate_expired=1
        echo "Certificate validity: EXPIRED (or expires at the current time)" >&2
    fi

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

    for cert in "$host_workdir"/cert-*.pem; do
        [[ "$cert" == "$leaf" ]] && continue
        if is_issuer_of_leaf "$cert"; then issuer_cert=$cert; break; fi
    done

    # Some servers omit intermediates.  Retrieve the issuing CA certificate from
    # the Authority Information Access extension when it is available.
    if [[ -z "$issuer_cert" ]]; then
        mapfile -t issuer_urls < <(
            openssl x509 -in "$leaf" -noout -ext authorityInfoAccess 2>/dev/null \
                | grep -oE 'CA Issuers - URI:[^,[:space:]]+' | sed 's/^CA Issuers - URI://' | sort -u
        )
        for index in "${!issuer_urls[@]}"; do
            issuer_download="$host_workdir/issuer-${index}.bin"
            issuer_candidate="$host_workdir/issuer-${index}.pem"
            if is_ldap_url "${issuer_urls[$index]}"; then continue; fi
            if ! fetch "${issuer_urls[$index]}" "$issuer_download"; then continue; fi
            if openssl x509 -inform DER -in "$issuer_download" -out "$issuer_candidate" >/dev/null 2>&1; then :
            elif openssl x509 -inform PEM -in "$issuer_download" -out "$issuer_candidate" >/dev/null 2>&1; then :
            else continue; fi
            if is_issuer_of_leaf "$issuer_candidate"; then issuer_cert=$issuer_candidate; break; fi
        done
    fi
    [[ -n "$issuer_cert" ]] || echo "Warning: issuer certificate unavailable; CRL signatures cannot be verified." >&2

    find_presented_issuer() {
        local child=$1 expected_issuer=$2 candidate candidate_subject
        local -a candidates=("$host_workdir"/cert-*.pem)
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

    # s_client does not validate the server certificate by default. A CRL signed by
    # an untrusted CA is not enough, so always validate the chain and identity.
    if (( verify_peer == 1 )); then
        chain_bundle="$host_workdir/intermediates.pem"
        : > "$chain_bundle"
        for cert in "$host_workdir"/cert-*.pem; do
            [[ "$cert" == "$leaf" ]] && continue
            awk '{ print }' "$cert" >> "$chain_bundle"
        done
        # The server may omit intermediates; if one was recovered via AIA above,
        # include it too so chain verification is not penalized for that omission.
        [[ -n "$issuer_cert" ]] && awk '{ print }' "$issuer_cert" >> "$chain_bundle"
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

    echo
    echo "CAA records"
    if (( is_ip == 1 )); then
        echo "CAA status: skipped (connection target is an IP address, not a domain name)."
    elif (( check_caa == 0 )); then
        echo "CAA status: skipped (--no-caa)."
    elif [[ -z "$caa_tool" ]]; then
        echo "CAA status: skipped (no dig, host, or nslookup available)."
    else
        caa_records=
        case "$caa_tool" in
            dig) caa_records=$(dig +short CAA "$connection_host" 2>/dev/null) ;;
            host) caa_records=$(host -t CAA "$connection_host" 2>/dev/null | grep -i 'CAA' || true) ;;
            nslookup) caa_records=$(nslookup -type=CAA "$connection_host" 2>/dev/null | grep -i 'CAA' || true) ;;
        esac
        if [[ -n "$caa_records" ]]; then
            echo "CAA record(s) at $connection_host:"
            printf '  %s\n' "$caa_records"
        else
            echo "CAA status: no CAA record found at $connection_host (parent domains not walked; any CA may issue)."
        fi
    fi

    check_certificate_revocation "$leaf" "LEAF" "$issuer_cert"
    checked=$rc_checked
    revoked=$rc_revoked
    ocsp_good=$rc_ocsp_good
    (( revoked == 1 )) && revocation_flag[$leaf]=1

    echo
    echo "STAPLED OCSP: $stapled_ocsp"

    # Build the resolvable issuer chain (leaf -> ... -> root, if reached) and
    # check each intermediate CA's own revocation status too: a revoked
    # intermediate invalidates everything it issued, even if the leaf's own
    # CRL/OCSP looks fine.
    build_chain() {
        chain_list=("$leaf")
        local current=$leaf s i p
        while :; do
            s=$(certificate_subject "$current")
            i=$(certificate_issuer "$current")
            [[ "$s" == "$i" ]] && return
            p=$(find_presented_issuer "$current" "$i") || return
            chain_list+=("$p")
            current=$p
            (( ${#chain_list[@]} >= 10 )) && return
        done
    }
    build_chain
    if (( ${#chain_list[@]} > 1 )); then
        for (( ci = 1; ci < ${#chain_list[@]}; ci++ )); do
            cert=${chain_list[$ci]}
            subj=$(certificate_subject "$cert")
            iss=$(certificate_issuer "$cert")
            [[ "$subj" == "$iss" ]] && break
            verifier=${chain_list[$((ci + 1))]:-}
            check_certificate_revocation "$cert" "CA: $subj" "$verifier"
            if (( rc_revoked == 1 )); then
                intermediate_revoked=1
                revocation_flag[$cert]=1
                add_warning "intermediate CA '$subj' is REVOKED per its own CRL/OCSP."
            fi
        done
    fi

    echo
    if (( peer_valid == 1 )); then trust_status=TRUSTED; else trust_status=UNTRUSTED/INVALID; fi
    if (( certificate_expired == 1 )); then
        expiry_status=EXPIRED
    elif (( expiry_warning == 1 )); then
        expiry_status='EXPIRING SOON'
    else
        expiry_status='NOT EXPIRED'
    fi
    if (( revoked == 1 || intermediate_revoked == 1 )); then
        revocation_status=REVOKED
    elif (( checked > 0 || ocsp_good > 0 )); then
        revocation_status='NOT REVOKED'
    else
        revocation_status=UNKNOWN
    fi

    if (( revoked == 1 || intermediate_revoked == 1 )); then
        overall_status=REVOKED
        exit_code=2
        if (( revoked == 1 && intermediate_revoked == 1 )); then
            reason="leaf certificate and an intermediate CA are both revoked"
        elif (( revoked == 1 )); then
            reason="leaf certificate is revoked"
        else
            reason="an intermediate CA in the chain is revoked"
        fi
    elif (( certificate_expired == 1 )); then
        overall_status=EXPIRED
        exit_code=4
        reason="certificate has expired"
    elif (( peer_valid != 1 )); then
        overall_status=UNTRUSTED/INVALID
        exit_code=5
        reason="certificate chain or hostname/IP verification failed"
    elif [[ "$revocation_status" == 'NOT REVOKED' ]]; then
        if (( fail_on_expiry_warning == 1 && expiry_warning == 1 )); then
            overall_status='VALID (EXPIRING SOON)'
            exit_code=6
            reason="trusted and not revoked, but expires in $expiry_days_left day(s)"
        else
            overall_status=VALID
            exit_code=0
            if (( expiry_warning == 1 )); then
                reason="trusted and not revoked, but expires in $expiry_days_left day(s)"
            else
                reason="trusted, not revoked, not expiring soon"
            fi
        fi
    else
        overall_status=UNKNOWN
        exit_code=3
        reason="no verifiable CRL/OCSP revocation data available"
    fi
    batch_overall=$overall_status
    batch_reason=$reason

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
        local current=$leaf parent subject issuer label root_suffix revocation_suffix
        local signature_status trust_result indent='' child_indent depth=0
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
            revocation_suffix=
            [[ -n "${revocation_flag[$current]:-}" ]] && revocation_suffix=' [REVOKED]'
            printf '%s└── %s: %s%s%s [TRUST: %s] [SIGNATURE: %s]\n' \
                "$indent" "$label" "$subject" "$root_suffix" "$revocation_suffix" "$trust_result" "$signature_status"
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
    echo "ADVISORY WARNINGS"
    if (( ${#warnings[@]} == 0 )); then
        echo "  none"
    else
        printf '  - %s\n' "${warnings[@]}"
    fi
    echo
    if [[ "$output_format" == json ]]; then
        local warnings_json='['
        for index in "${!warnings[@]}"; do
            (( index > 0 )) && warnings_json+=','
            warnings_json+="\"$(json_escape "${warnings[$index]}")\""
        done
        warnings_json+=']'
        printf '{"host":"%s","port":%s,"trust":"%s","revocation":"%s","expiry":"%s","expiry_days_left":%s,"intermediate_revoked":%s,"stapled_ocsp":"%s","overall":"%s","exit_code":%s,"warnings":%s}\n' \
            "$(json_escape "$domain")" "$port" "$(json_escape "$trust_status")" \
            "$(json_escape "$revocation_status")" "$(json_escape "$expiry_status")" \
            "${expiry_days_left:-null}" \
            "$(if (( intermediate_revoked == 1 )); then echo true; else echo false; fi)" \
            "$(json_escape "$stapled_ocsp")" "$(json_escape "$overall_status")" "$exit_code" "$warnings_json" >&3
    else
        echo "FINAL STATUS"
        printf '  TRUST: %s\n' "$trust_status"
        printf '  REVOCATION: %s\n' "$revocation_status"
        printf '  EXPIRY: %s\n' "$expiry_status"
        printf '  OVERALL: %s\n' "$overall_status"
    fi
    return "$exit_code"
}

if [[ -n "$hosts_file" ]]; then
    batch_worst=0
    batch_total=0
    declare -A batch_group_lines=()
    declare -a batch_group_order=()
    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        read -r batch_host batch_port _ <<<"$raw_line"
        [[ -z "$batch_host" || "$batch_host" == \#* ]] && continue
        batch_port=${batch_port:-443}
        echo
        echo "############################################################"
        echo "### ${batch_host}:${batch_port}"
        echo "############################################################"
        batch_overall=
        batch_reason=
        check_host "$batch_host" "$batch_port"
        batch_rc=$?
        batch_total=$((batch_total + 1))
        batch_overall=${batch_overall:-UNKNOWN}
        batch_reason=${batch_reason:-"no reason recorded"}
        [[ -n "${batch_group_lines[$batch_overall]+x}" ]] || batch_group_order+=("$batch_overall")
        batch_group_lines["$batch_overall"]+="  ${batch_host}:${batch_port}: ${batch_reason}"$'\n'
        (( batch_rc != 0 )) && batch_worst=1
    done < "$hosts_file"
    if [[ "$output_format" != json ]]; then
        # Problems first, then healthy results; anything unforeseen falls
        # back to the order categories were first seen.
        batch_priority=(REVOKED EXPIRED "UNTRUSTED/INVALID" ERROR UNKNOWN "VALID (EXPIRING SOON)" VALID)
        batch_display_order=()
        for batch_cat in "${batch_priority[@]}"; do
            [[ -n "${batch_group_lines[$batch_cat]+x}" ]] && batch_display_order+=("$batch_cat")
        done
        for batch_cat in "${batch_group_order[@]}"; do
            batch_seen=0
            for batch_done in "${batch_display_order[@]}"; do
                [[ "$batch_done" == "$batch_cat" ]] && { batch_seen=1; break; }
            done
            (( batch_seen == 0 )) && batch_display_order+=("$batch_cat")
        done
        echo
        echo "BATCH SUMMARY (${batch_total} host(s) checked)"
        for batch_cat in "${batch_display_order[@]}"; do
            batch_count=$(grep -c '.' <<<"${batch_group_lines[$batch_cat]}")
            echo
            echo "${batch_cat} (${batch_count})"
            printf '%s' "${batch_group_lines[$batch_cat]}"
        done
    fi
    exit "$batch_worst"
else
    check_host "$domain" "$port"
    exit $?
fi
