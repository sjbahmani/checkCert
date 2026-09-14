#!/usr/bin/env bash
# Check the certificate presented by a TLS service against its CRL(s).
# Exit codes: 0 = valid, not expired, and not revoked; 2 = revoked (the leaf
#             or an intermediate CA in its chain); 3 = unknown/error;
#             4 = expired; 5 = untrusted/invalid identity; 6 = valid but
#             expiring soon (only with --fail-on-expiry-warning).
# In --hosts-file (batch) mode the process exit code is 0 if every host
# exited 0, otherwise 1; inspect each host's own result for detail.

set -u -o pipefail

VERSION=1.16.0
verify_peer=1
ca_file=
ca_path=
output_format=text
summary_only=0
connect_ip=
connect_ip_set=0
connect_ip_json=null
cache_enabled=1
cache_dir=
cache_dir_set=0
cache_max_age=86400
connect_timeout=2
request_timeout=60
connect_retries=6
retry_delay=1
max_ocsp_age=86400
max_ocsp_age_set=0
clock_skew=300
proxy=
no_proxy=
starttls_proto=
expiry_warn_days=14
check_caa=1
fail_on_expiry_warning=0
hosts_file=
batch_parallel=6
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
  --summary-only      Show only FINAL STATUS (single host) or BATCH SUMMARY
                      (hosts file). With --json, suppress diagnostics.
  --connect-ip IP     Connect to this IPv4/IPv6 address, keeping the original
                      hostname for SNI and identity checks. Applies to all hosts.
  --cache-dir DIR     Keep verified CRL/AIA/OCSP data between runs in a private
                      directory. By default, the cache lasts only this run.
                      Shared downloads wait for a per-object lock (uses flock).
                      Failed shared requests have a 10-second cooldown.
  --cache-max-age N   Maximum cached download age in seconds (default: 86400;
                      24 hours).
                      CRL/OCSP entries are never reused past nextUpdate.
  --no-cache          Disable cache reads and writes, including --cache-dir.
  --connect-timeout N TLS connection timeout in seconds (default: 2).
  --request-timeout N CRL/OCSP request timeout in seconds (default: 60).
  --connect-retries N Retry a failed network operation (initial TLS
                      connection, CRL download, or OCSP query) up to N
                      extra times (default: 6; 0 disables retrying).
                      Only temporary transport/HTTP failures are retried.
  --retry-delay N     Initial retry delay in seconds (default: 1; 0 disables
                      waiting). Doubles each retry, capped at 6 seconds.
  --max-ocsp-age N    Maximum OCSP response age in seconds (default: 86400
                      for leaf/no-nextUpdate responses). CA responses with
                      nextUpdate use its signed deadline unless N is set.
  --clock-skew N      Allowed clock skew for OCSP in seconds (default: 300).
  --proxy URL         HTTP(S) proxy for CRL/OCSP HTTP requests.
  --no-proxy HOSTS    Comma-separated hosts that bypass the proxy.
  --starttls PROTO    Negotiate STARTTLS before the TLS handshake (e.g. smtp,
                      imap, pop3, ftp, nntp, ldap, xmpp, postgres, mysql).
                      Applies to every host checked.
  --expiry-warn-days N Warn when the certificate expires within N days
                      (default: 14; 0 disables the warning).
  --fail-on-expiry-warning
                      Exit 6 instead of 0 when only the expiry warning
                      applies (chain trusted, not revoked, not expired).
  --no-caa            Skip the DNS CAA record lookup.
  --hosts-file FILE   Check every "host [port]" line in FILE instead of a
                      single positional host/port. Blank lines and lines
                      starting with # are ignored. Other options (CA trust,
                      STARTTLS, timeouts, ...) apply to every host checked.
  --parallel N        With --hosts-file, check up to N hosts concurrently
                      (default: 6). N=1 checks sequentially and streams
                      each host's output as it runs; N>1 buffers each
                      host's output and prints it in input-file order once
                      that host's check completes, so results still appear
                      grouped and readable even though hosts finish out of
                      order. Requires Bash 4.3+ (uses "wait -n").
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
        --summary-only) summary_only=1 ;;
        --no-cache) cache_enabled=0 ;;
        --no-caa) check_caa=0 ;;
        --fail-on-expiry-warning) fail_on_expiry_warning=1 ;;
        --cache-dir|--cache-max-age|--connect-ip|--connect-timeout|--request-timeout|--connect-retries|--retry-delay|--max-ocsp-age|--clock-skew|--proxy|--no-proxy|--ca-path|--starttls|--expiry-warn-days|--hosts-file|--parallel)
            option_name=$1
            shift
            if (( $# == 0 )); then
                echo "Error: $option_name requires a value." >&2
                exit 1
            elif [[ "$1" == --* ]]; then
                echo "Error: $option_name requires a value (got '$1', which looks like another option)." >&2
                exit 1
            fi
            case $option_name in
                --cache-dir) cache_dir=$1; cache_dir_set=1 ;;
                --cache-max-age) cache_max_age=$1 ;;
                --connect-ip) connect_ip=$1; connect_ip_set=1 ;;
                --connect-timeout) connect_timeout=$1 ;;
                --request-timeout) request_timeout=$1 ;;
                --connect-retries) connect_retries=$1 ;;
                --retry-delay) retry_delay=$1 ;;
                --max-ocsp-age) max_ocsp_age=$1; max_ocsp_age_set=1 ;;
                --clock-skew) clock_skew=$1 ;;
                --proxy) proxy=$1 ;;
                --no-proxy) no_proxy=$1 ;;
                --ca-path) ca_path=$1 ;;
                --starttls) starttls_proto=$1 ;;
                --expiry-warn-days) expiry_warn_days=$1 ;;
                --hosts-file) hosts_file=$1 ;;
                --parallel) batch_parallel=$1 ;;
            esac
            ;;
        --ca-file)
            shift
            if (( $# == 0 )); then
                echo "Error: --ca-file requires a file path." >&2
                exit 1
            elif [[ "$1" == --* ]]; then
                echo "Error: --ca-file requires a file path (got '$1', which looks like another option)." >&2
                exit 1
            fi
            ca_file=$1
            ;;
        --ca-file=*) ca_file=${1#--ca-file=} ;;
        --ca-path=*) ca_path=${1#--ca-path=} ;;
        --cache-dir=*) cache_dir=${1#--cache-dir=}; cache_dir_set=1 ;;
        --cache-max-age=*) cache_max_age=${1#--cache-max-age=} ;;
        --connect-ip=*) connect_ip=${1#--connect-ip=}; connect_ip_set=1 ;;
        --connect-timeout=*) connect_timeout=${1#--connect-timeout=} ;;
        --request-timeout=*) request_timeout=${1#--request-timeout=} ;;
        --connect-retries=*) connect_retries=${1#--connect-retries=} ;;
        --retry-delay=*) retry_delay=${1#--retry-delay=} ;;
        --max-ocsp-age=*) max_ocsp_age=${1#--max-ocsp-age=}; max_ocsp_age_set=1 ;;
        --clock-skew=*) clock_skew=${1#--clock-skew=} ;;
        --proxy=*) proxy=${1#--proxy=} ;;
        --no-proxy=*) no_proxy=${1#--no-proxy=} ;;
        --starttls=*) starttls_proto=${1#--starttls=} ;;
        --expiry-warn-days=*) expiry_warn_days=${1#--expiry-warn-days=} ;;
        --hosts-file=*) hosts_file=${1#--hosts-file=} ;;
        --parallel=*) batch_parallel=${1#--parallel=} ;;
        --) shift; positionals+=("$@"); break ;;
        -*) echo "Error: unknown option: $1" >&2; usage; exit 1 ;;
        *) positionals+=("$1") ;;
    esac
    shift
done

is_ipv4_literal() {
    local address=$1 octet
    local -a octets=()
    [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<<"$address"
    for octet in "${octets[@]}"; do
        # Avoid ambiguous octal spellings such as 012.0.0.1.
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

is_ip_literal() {
    local address=$1 compressed=0
    local -a groups=()
    if [[ "$address" != *:* ]]; then is_ipv4_literal "$address"; return $?; fi
    [[ "$address" =~ ^[[:xdigit:]:.]+$ && "$address" != *:::* ]] || return 1
    if [[ "$address" == *.* ]]; then
        # An embedded IPv4 tail occupies the last two IPv6 groups.
        is_ipv4_literal "${address##*:}" || return 1
        address="${address%:*}:0:0"
    fi
    [[ "$address" != :* || "$address" == ::* ]] || return 1
    [[ "$address" != *: || "$address" == *:: ]] || return 1
    if [[ "$address" == *::* ]]; then
        compressed=1
        [[ "${address#*::}" != *::* ]] || return 1
        address=${address/::/:}
        address=${address#:}
        address=${address%:}
    fi
    if [[ -n "$address" ]]; then
        [[ "$address" =~ ^([[:xdigit:]]{1,4}:)*[[:xdigit:]]{1,4}$ ]] || return 1
        IFS=: read -r -a groups <<<"$address"
    fi
    if (( compressed == 1 )); then
        (( ${#groups[@]} < 8 ))
    else
        (( ${#groups[@]} == 8 ))
    fi
}

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
if (( connect_ip_set == 1 )); then
    # Brackets are optional around an IPv6 literal; the port stays positional.
    if [[ "$connect_ip" =~ ^\[([^][]*:[^][]*)\]$ ]]; then connect_ip=${BASH_REMATCH[1]}; fi
    if ! is_ip_literal "$connect_ip"; then
        echo "Error: --connect-ip requires an IPv4 or IPv6 address without a port or zone ID." >&2
        exit 1
    fi
    connect_ip_json="\"$connect_ip\""
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
if ! [[ "$connect_retries" =~ ^[0-9]+$ ]]; then
    echo "Error: --connect-retries must be a non-negative integer." >&2
    exit 1
fi
if ! [[ "$retry_delay" =~ ^[0-9]{1,9}$ ]]; then
    echo "Error: --retry-delay must be a non-negative integer of at most 9 digits (seconds)." >&2
    exit 1
fi
retry_delay=$((10#$retry_delay))
if ! [[ "$batch_parallel" =~ ^[0-9]+$ ]] || (( batch_parallel < 1 )); then
    echo "Error: --parallel must be a positive integer." >&2
    exit 1
fi
if ! [[ "$cache_max_age" =~ ^[0-9]{1,9}$ ]] || (( 10#$cache_max_age < 1 )); then
    echo "Error: --cache-max-age must be a positive integer of at most 9 digits (seconds)." >&2
    exit 1
fi
cache_max_age=$((10#$cache_max_age))
if (( cache_dir_set == 1 )) && [[ -z "$cache_dir" ]]; then
    echo "Error: --cache-dir requires a non-empty directory path." >&2
    exit 1
fi
if (( cache_enabled == 1 && cache_dir_set == 1 )); then
    # Persistent evidence must not be replaceable by another local user. Never
    # chmod an existing user directory, and reject symlinked final components.
    while [[ "$cache_dir" != / && "$cache_dir" == */ ]]; do cache_dir=${cache_dir%/}; done
    if ! command -v stat >/dev/null 2>&1; then
        echo "Error: GNU stat is required with --cache-dir." >&2
        exit 3
    fi
    if [[ -L "$cache_dir" ]] || ! (umask 077; mkdir -p -- "$cache_dir") \
        || [[ ! -d "$cache_dir" || ! -O "$cache_dir" || ! -r "$cache_dir" || ! -w "$cache_dir" || ! -x "$cache_dir" ]]; then
        echo "Error: --cache-dir must be a readable/writable directory owned by you, not a symlink." >&2
        exit 1
    fi
    cache_mode=$(stat -c '%a' -- "$cache_dir") || exit 3
    if ! [[ "$cache_mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$cache_mode & 0022) != 0 )); then
        echo "Error: --cache-dir must not be group- or world-writable (use a private directory)." >&2
        exit 1
    fi
fi
for command in openssl awk sed grep mktemp timeout tr sort date tail; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "Error: '$command' is required." >&2; exit 3;
    }
done
if (( cache_enabled == 1 )) && ! command -v flock >/dev/null 2>&1; then
    echo "Error: 'flock' (util-linux) is required for caching; install it or use --no-cache." >&2
    exit 3
fi
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
if (( summary_only == 1 )) && [[ "$output_format" == text ]]; then
    # Keep the final single-host report visible while check_host suppresses
    # progress and diagnostics. Batch reports use the parent's normal stdout.
    exec 4>&1
fi
if [[ "$output_format" == json ]]; then
    exec 3>&1
    exec 1>&2
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/checkcrl.XXXXXX") || exit 3
trap 'rm -rf "$workdir"' EXIT
if (( cache_enabled == 1 && cache_dir_set == 0 )); then
    cache_dir="$workdir/cache"
    mkdir -m 700 -- "$cache_dir" || exit 3
fi

# The main trust decision (openssl verify, no -CAfile) already consults the
# system's default trust store, which is why TRUST can read TRUSTED even when
# a server omits its root. The per-host CA TREE walk only searches presented
# certs and the one AIA-fetched issuer, though, so it can still show a
# perfectly trusted root as [NOT PROVIDED]/SIGNATURE UNKNOWN. Index the
# system store (and any --ca-file) once, up front, so every host's tree walk
# can resolve those roots too, by exact subject match followed by a real
# signature check. Built once here (not per host) since the store never
# changes between hosts in a --hosts-file run.
declare -A system_ca_subjects=()
system_bundle_files=()
for system_bundle in "${SSL_CERT_FILE:-}" /etc/ssl/certs/ca-certificates.crt \
    /etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
    /etc/ssl/cert.pem /usr/local/etc/openssl/cert.pem; do
    [[ -n "$system_bundle" && -r "$system_bundle" ]] && system_bundle_files+=("$system_bundle")
done
system_openssldir=$(openssl version -d 2>/dev/null | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p')
[[ -n "$system_openssldir" && -r "$system_openssldir/cert.pem" ]] && system_bundle_files+=("$system_openssldir/cert.pem")
[[ -n "$ca_file" && -r "$ca_file" ]] && system_bundle_files+=("$ca_file")
if (( ${#system_bundle_files[@]} > 0 )); then
    : > "$workdir/sysca-combined.pem"
    cat "${system_bundle_files[@]}" >> "$workdir/sysca-combined.pem" 2>/dev/null
    awk -v output_dir="$workdir" '
            /-----BEGIN CERTIFICATE-----/ { number++; file=output_dir "/sysca-" number ".pem"; writing=1 }
            writing { print > file }
            /-----END CERTIFICATE-----/ { close(file); writing=0 }
        ' "$workdir/sysca-combined.pem" 2>/dev/null
    for sysca_file in "$workdir"/sysca-*.pem; do
        [[ -e "$sysca_file" ]] || continue
        sysca_subject=$(openssl x509 -in "$sysca_file" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')
        [[ -n "$sysca_subject" ]] && system_ca_subjects["$sysca_subject"]=$sysca_file
    done
fi

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

finish_host_metrics() {
    local now elapsed_ns event
    now=$(date +%s%N)
    elapsed_ns=$((now - host_started_ns))
    (( elapsed_ns < 0 )) && elapsed_ns=0
    printf -v batch_elapsed '%d.%d' "$((elapsed_ns / 1000000000))" "$((elapsed_ns % 1000000000 / 100000000))"
    batch_cache_hits=0
    batch_cache_misses=0
    # Fetches run in subshells. A private per-host event file carries counts
    # back without parsing diagnostics (which summary-only suppresses).
    if [[ -n "$host_cache_events" && -f "$host_cache_events" ]]; then
        while IFS= read -r event; do
            case "$event" in
                H) batch_cache_hits=$((batch_cache_hits + 1)) ;;
                M) batch_cache_misses=$((batch_cache_misses + 1)) ;;
            esac
        done < "$host_cache_events"
    fi
}

print_final_status() {
    local report_fd=1
    if (( summary_only == 1 )); then
        [[ -n "$hosts_file" ]] && return 0
        report_fd=4
    fi
    {
        echo "FINAL STATUS"
        [[ -n "$connect_ip" ]] && printf '  CONNECT IP: %s\n' "$connect_ip"
        printf '  ISSUER: %s\n' "${1:-unknown}"
        printf '  TRUST: %s\n' "$2"
        printf '  REVOCATION: %s\n' "$3"
        printf '  EXPIRY: %s\n' "$4"
        printf '  DAYS REMAINING: %s\n' "${5:-N/A}"
        printf '  OVERALL: %s\n' "$6"
        printf '  REASON: %s\n' "$7"
        printf '  ELAPSED: %ss\n' "$batch_elapsed"
        printf '  CACHE: %s hit / %s miss\n' "$batch_cache_hits" "$batch_cache_misses"
    } >&"$report_fd"
}

# Emits a JSON record for a host that failed before a full check could be
# completed (e.g. connection failure), so --json/--hosts-file consumers see
# one line per host attempted instead of that host silently disappearing.
# In text mode, also render the error as the final single-host report.
emit_error_json() {
    local err_domain=$1 err_port=$2 message=$3 err_port_json=null
    batch_overall=ERROR
    batch_reason=$message
    batch_issuer=
    batch_days_left=
    finish_host_metrics
    if [[ "$output_format" == text ]]; then
        print_final_status '' UNKNOWN UNKNOWN UNKNOWN '' ERROR "$message"
    fi
    [[ "$output_format" == json ]] || return 0
    # Invalid host-file ports must not inject bare text or leading-zero
    # numbers into JSON. The error message retains the original value.
    if [[ "$err_port" =~ ^[0-9]{1,5}$ ]]; then
        err_port_json=$((10#$err_port))
    fi
    printf '{"host":"%s","port":%s,"connect_ip":%s,"issuer":null,"trust":null,"revocation":null,"expiry":null,"expiry_days_left":null,"intermediate_revoked":null,"stapled_ocsp":null,"overall":"ERROR","reason":"%s","exit_code":3,"warnings":[],"error":"%s","elapsed_seconds":%s,"cache_hits":%s,"cache_misses":%s}\n' \
        "$(json_escape "$err_domain")" "$err_port_json" "$connect_ip_json" "$(json_escape "$message")" "$(json_escape "$message")" \
        "$batch_elapsed" "$batch_cache_hits" "$batch_cache_misses" >&3
}

retry_wait() {
    local retry_number=$1 operation=$2 delay max_delay=6
    # Each multiplier holds for two attempts before doubling, giving a
    # gentler ramp than doubling every attempt (1, 1, 2, 2, 4, then the
    # cap): more chances at each rung before escalating the wait.
    local -a schedule=(1 1 2 2 4)
    if (( retry_delay == 0 )); then
        delay=0
    elif (( retry_number <= ${#schedule[@]} )); then
        delay=$((retry_delay * schedule[retry_number - 1]))
    else
        delay=$max_delay
    fi
    (( delay > max_delay )) && delay=$max_delay
    printf '%s failed; retry %s/%s in %ss ...\n' "$operation" "$retry_number" "$connect_retries" "$delay" >&2
    if (( delay > 0 )); then sleep "$delay"; fi
}

fetch() {
    local url=$1 destination=$2 request=${3:-} operation=${4:-Download}
    local fetch_attempt=0 fetch_rc http_status retryable errors="$2.errors"
    local -a curl_args wget_args
    fetch_failure_shared=0
    while :; do
        retryable=0
        fetch_failure_shared=0
        http_status=
        if command -v curl >/dev/null 2>&1; then
            curl_args=(--fail --location --silent --show-error --retry 0 --connect-timeout "$connect_timeout" --max-time "$request_timeout")
            [[ -n "$proxy" ]] && curl_args+=(--proxy "$proxy")
            [[ -n "$no_proxy" ]] && curl_args+=(--noproxy "$no_proxy")
            if [[ -n "$request" ]]; then
                curl_args+=(--header 'Content-Type: application/ocsp-request'
                    --header 'Accept: application/ocsp-response' --data-binary "@$request")
            fi
            if http_status=$(curl "${curl_args[@]}" --write-out '%{http_code}' --output "$destination" "$url"); then return 0
            else fetch_rc=$?; fi
            case "$fetch_rc" in
                5|6|7|16|18|28|52|55|56|92) retryable=1; fetch_failure_shared=1 ;;
                22)
                    [[ "$http_status" =~ ^[45][0-9]{2}$ ]] && fetch_failure_shared=1
                    http_status_is_temporary "$http_status" && retryable=1 ;;
            esac
        elif command -v wget >/dev/null 2>&1; then
            wget_args=(--no-verbose --server-response --dns-timeout="$connect_timeout"
                --connect-timeout="$connect_timeout" --read-timeout="$request_timeout"
                --tries=1 --output-document="$destination")
            [[ -n "$proxy" ]] && wget_args+=(-e use_proxy=yes -e "http_proxy=$proxy" -e "https_proxy=$proxy")
            [[ -n "$no_proxy" ]] && wget_args+=(-e "no_proxy=$no_proxy")
            if [[ -n "$request" ]]; then
                wget_args+=(--header='Content-Type: application/ocsp-request'
                    --header='Accept: application/ocsp-response' --post-file="$request")
            fi
            if timeout "$request_timeout" wget "${wget_args[@]}" "$url" 2>"$errors"; then return 0
            else fetch_rc=$?; fi
            cat "$errors" >&2
            http_status=$(http_status_from_report "$errors")
            case "$fetch_rc" in
                4|124) retryable=1; fetch_failure_shared=1 ;;
                8)
                    [[ "$http_status" =~ ^[45][0-9]{2}$ ]] && fetch_failure_shared=1
                    http_status_is_temporary "$http_status" && retryable=1 ;;
            esac
        else
            echo "Error: curl or wget is required for CRL/AIA/OCSP requests." >&2
            return 1
        fi
        (( retryable == 1 )) || return 1
        (( fetch_attempt >= connect_retries )) && return 1
        fetch_attempt=$((fetch_attempt + 1))
        retry_wait "$fetch_attempt" "$operation"
    done
}

http_status_is_temporary() {
    case "$1" in 408|429|500|502|503|504) return 0 ;; *) return 1 ;; esac
}

http_status_from_report() {
    # Wget response headers and OpenSSL HTTP error reports, including redirects.
    sed -nE -e 's/^[[:space:]]*HTTP\/[0-9.]+ ([0-9]{3}).*/\1/p' \
        -e 's/.*[Cc]ode[=:][[:space:]]*([0-9]{3}).*/\1/p' "$1" | tail -1
}

openssl_failure_is_temporary() {
    local rc=$1 report=$2 status
    (( rc == 124 )) && return 0
    status=$(http_status_from_report "$report")
    if [[ -n "$status" ]]; then http_status_is_temporary "$status"; return; fi
    # Retry transport interruptions, not arbitrary TLS/protocol/verification errors.
    LC_ALL=C grep -Eqi 'connection (refused|reset|timed out|closed)|network is unreachable|no route to host|temporary failure in name resolution|resource temporarily unavailable|unexpected eof while reading|connect:errno=(11|101|104|110|111|113)$' "$report"
}

cache_failure_is_recent() {
    local file=$1 header failed_at now
    [[ -f "$file" && ! -L "$file" ]] || return 1
    IFS= read -r header < "$file" || return 1
    [[ "$header" =~ ^'# checkCRT-failure-v1 '([0-9]{1,12})$ ]] || return 1
    failed_at=$((10#${BASH_REMATCH[1]}))
    now=$(date -u +%s)
    (( failed_at <= now && now - failed_at < 10 ))
}

cache_record_failure() {
    # Called under the object lock, only for remote request failures. Policy or
    # issuer-specific verification failures must not suppress another caller.
    if (( lock_held == 1 && fetch_failure_shared == 1 )); then
        if cache_temp=$(mktemp "$cache_dir/.checkcrt-failure.XXXXXX") \
            && printf '# checkCRT-failure-v1 %s\n' "$(date -u +%s)" > "$cache_temp" \
            && mv -fT -- "$cache_temp" "$entry.failed"; then
            cache_temp=
        fi
    fi
}

crl_signature_is_valid() {
    local crl=$1 verifier=$2 verification
    [[ -n "$verifier" ]] || return 1
    # OpenSSL 3.0 can print "verify failure" yet exit 0. Require positive
    # signature evidence as well as success, for fresh and cached CRLs alike.
    # Some OpenSSL builds add an extra informational line (provider/engine
    # notices, deprecation banners) around a genuine "verify OK", so check
    # for that line anywhere in the output instead of requiring an exact
    # whole-output match, which would reject a validly-signed CRL on those
    # builds.
    verification=$(LC_ALL=C openssl crl -in "$crl" -noout -verify -CAfile "$verifier" 2>&1) || return 1
    grep -Fxq 'verify OK' <<<"$verification"
}

crl_is_current() {
    local crl=$1 last_update next_update last_epoch next_epoch now
    last_update=$(openssl crl -in "$crl" -noout -lastupdate | sed 's/^lastUpdate=//')
    next_update=$(openssl crl -in "$crl" -noout -nextupdate | sed 's/^nextUpdate=//')
    [[ -n "$last_update" && -n "$next_update" ]] || return 1
    last_epoch=$(date -u -d "$last_update" +%s 2>/dev/null) || return 1
    next_epoch=$(date -u -d "$next_update" +%s 2>/dev/null) || return 1
    now=$(date -u +%s)
    # Skew tolerates clock differences, never an empty or reversed interval.
    (( next_epoch > last_epoch && last_epoch <= now + clock_skew && next_epoch > now - clock_skew ))
}

crl_cache_lifetime_is_valid() {
    local crl=$1 next_update next_epoch
    crl_is_current "$crl" 2>/dev/null || return 1
    # Do not use clock-skew tolerance to extend the cache's lifetime.
    next_update=$(openssl crl -in "$crl" -noout -nextupdate 2>/dev/null | sed 's/^nextUpdate=//')
    next_epoch=$(date -u -d "$next_update" +%s 2>/dev/null) || return 1
    (( next_epoch > $(date -u +%s) ))
}

# Cache entries are evidence, never trust anchors or cached verdicts. Validate
# each object against this host's actual issuer/leaf, even on a cache hit.
cache_object_is_valid() {
    local kind=$1 object=$2 verifier=$3 cert=${4:-} report=${5:-} is_ca=${6:-0}
    if [[ "$kind" == aia ]]; then
        is_issuer_of_leaf "$object"
    elif [[ "$kind" == ocsp ]]; then
        ocsp_verify_response "$object" "$cert" "$verifier" "$report" "$is_ca" || return 1
        # Unknown responses are reported, but not retained as reusable evidence.
        grep -Fxq -- "$cert: good" "$report" || grep -Fxq -- "$cert: revoked" "$report"
    else
        [[ -n "$verifier" ]] || return 1
        crl_signature_is_valid "$object" "$verifier" || return 1
        crl_cache_lifetime_is_valid "$object"
    fi
}

cache_read() {
    local kind=$1 entry=$2 destination=$3 verifier=$4 cert=${5:-} report=${6:-} is_ca=${7:-0}
    local header fetched_at now snapshot=$3
    [[ "$kind" == ocsp ]] && snapshot="$destination.snapshot"
    [[ -f "$entry" && ! -L "$entry" ]] || return 1
    # Snapshot a single, atomically-published file: metadata and payload cannot
    # come from different downloads during parallel checks.
    cp -- "$entry" "$snapshot" 2>/dev/null || return 1
    IFS= read -r header < "$snapshot" || return 1
    [[ "$header" =~ ^'# checkCRT-cache-v1 '([0-9]{1,12})$ ]] || return 1
    fetched_at=$((10#${BASH_REMATCH[1]}))
    now=$(date -u +%s)
    (( fetched_at <= now && now - fetched_at < cache_max_age )) || return 1
    if [[ "$kind" == ocsp ]]; then
        # DER is binary: keep it out of Bash variables. The cache envelope is
        # one timestamp line followed by base64-encoded, signed response bytes.
        tail -n +2 "$snapshot" | openssl base64 -d -out "$destination" 2>/dev/null || return 1
    fi
    cache_object_is_valid "$kind" "$destination" "$verifier" "$cert" "$report" "$is_ca" || return 1
    printf 'H\n' >> "$host_cache_events"
    printf '  Cache HIT (%s): USED verified cached download (age: %ss)\n' "${kind^^}" "$((now - fetched_at))"
}

# Normalize CRL/AIA downloads to PEM and retain signed OCSP responses as DER.
# A blocking per-object flock coalesces parallel downloads, including across
# runs sharing a cache directory. Never unlink lock files: waiters must keep
# using the same inode. The kernel releases the lock when its last descriptor
# closes, including after a crash. Subshell cleanup leaves parent traps alone.
# For CRLs, success guarantees the destination's signature was verified
# against this call's issuer, including when caching is disabled. Callers
# still check freshness at use time and look up each certificate's serial.
fetch_cached_object() (
    local kind=$1 url=$2 destination=$3 verifier=${4:-} cert=${5:-} report=${6:-} is_ca=${7:-0}
    local key entry='' lock_file='' lock_fd lock_rc lock_held=0 cache_temp=''
    local decoder fetched_at cert_fp issuer_fp cacheable=0
    local fetch_failure_shared=0
    trap '[[ -z "$cache_temp" ]] || rm -f -- "$cache_temp"' EXIT
    if (( cache_enabled == 1 )); then
        if [[ "$kind" == ocsp ]]; then
            # A responder serves many certificates. Never reuse a response
            # based only on its URL, issuer name, or certificate serial number.
            if cert_fp=$(openssl x509 -in "$cert" -noout -fingerprint -sha256) \
                && issuer_fp=$(openssl x509 -in "$verifier" -noout -fingerprint -sha256); then
                key=$(printf 'ocsp\n%s\n%s\n%s' "$url" "$cert_fp" "$issuer_fp" | openssl dgst -sha256 | awk '{print $NF}')
            else key=; fi
        else
            key=$(printf '%s\n%s' "$kind" "$url" | openssl dgst -sha256 | awk '{print $NF}')
        fi
        if [[ "$key" =~ ^[[:xdigit:]]{64}$ ]]; then
            entry="$cache_dir/v1-$kind-$key.pem"
            [[ "$kind" == ocsp ]] && entry="$cache_dir/v1-ocsp-$key.ocsp"
            lock_file="$entry.lock"
            if cache_read "$kind" "$entry" "$destination" "$verifier" "$cert" "$report" "$is_ca"; then exit 0; fi
            # This subshell's umask keeps newly-created lock files private.
            # Refuse legacy mkdir locks and unsafe paths instead of allowing
            # an uncoordinated download. Opening with >> never truncates.
            umask 077
            if [[ -L "$lock_file" ]] || { [[ -e "$lock_file" ]] && [[ ! -f "$lock_file" || ! -O "$lock_file" ]]; } \
                || ! { exec {lock_fd}>>"$lock_file"; } 2>/dev/null; then
                echo "  Cache ERROR (${kind^^}): cannot open cache lock; no uncoordinated download attempted." >&2
                exit 1
            fi
            while :; do
                # Five seconds is a recheck interval, never permission to
                # download around an owner. flock wakes early on release.
                # No -E here: flock's default timeout/conflict exit code is
                # 1 on every util-linux version (the -E option to customize
                # it was only added in 2.32/2018), so relying on it without
                # a capability check would fail closed -- treating every
                # lock attempt as a hard error -- on older systems.
                if flock -x -w 5 "$lock_fd"; then
                    break
                else
                    lock_rc=$?
                fi
                if (( lock_rc != 1 )); then
                    echo "  Cache ERROR (${kind^^}): cannot acquire cache lock; no uncoordinated download attempted." >&2
                    exit 1
                fi
                printf '  Cache WAIT (%s): shared download still in progress; waiting again\n' "${kind^^}"
            done
            lock_held=1
            # The previous owner may have published while we were waiting.
            # Every host verifies the result against its own certificate.
            if cache_read "$kind" "$entry" "$destination" "$verifier" "$cert" "$report" "$is_ca"; then exit 0; fi
            if cache_failure_is_recent "$entry.failed"; then
                printf '  Cache COOLDOWN (%s): shared request failed within the last 10s; download skipped\n' "${kind^^}"
                if [[ "$kind" == ocsp ]]; then
                    echo 'Shared OCSP request failed recently; download skipped during the 10s cooldown.' > "$report"
                fi
                exit 1
            fi
            printf 'M\n' >> "$host_cache_events"
            printf '  Cache MISS (%s): NOT USED; no fresh verified entry, downloading\n' "${kind^^}"
        else
            echo "  Cache ERROR (${kind^^}): unable to compute cache key; no uncoordinated download attempted." >&2
            exit 1
        fi
    else
        printf '  Cache BYPASS (%s): NOT USED; disabled by --no-cache, downloading\n' "${kind^^}"
    fi
    fetched_at=$(date -u +%s)
    if [[ "$kind" == ocsp ]]; then
        if ! fetch_ocsp_response "$url" "$destination" "$cert" "$verifier" "$report" "$is_ca"; then cache_record_failure; exit 1; fi
    else
        if ! fetch "$url" "$destination.download"; then cache_record_failure; exit 1; fi
        decoder=crl
        [[ "$kind" == aia ]] && decoder=x509
        if openssl "$decoder" -inform DER -in "$destination.download" -out "$destination" >/dev/null 2>&1; then :
        elif openssl "$decoder" -inform PEM -in "$destination.download" -out "$destination" >/dev/null 2>&1; then :
        else
            echo "  Result: downloaded file is not a readable ${kind^^} object" >&2
            exit 1
        fi
    fi
    if [[ "$kind" == crl ]]; then
        # Verify fresh CRLs once regardless of caching. Cache publication
        # reuses this check for the same private file and issuer; it only
        # needs to enforce the stricter cache lifetime separately.
        if ! crl_signature_is_valid "$destination" "$verifier"; then
            echo "  Result: CRL signature could not be verified" >&2
            exit 1
        fi
        if (( lock_held == 1 )) && crl_cache_lifetime_is_valid "$destination"; then cacheable=1; fi
    elif (( lock_held == 1 )) && cache_object_is_valid "$kind" "$destination" "$verifier" "$cert" "$report" "$is_ca"; then
        cacheable=1
    fi
    if (( cacheable == 1 )); then
        if cache_temp=$(mktemp "$cache_dir/.checkcrt-cache.XXXXXX") \
            && { printf '# checkCRT-cache-v1 %s\n' "$fetched_at";
                 if [[ "$kind" == ocsp ]]; then openssl base64 -in "$destination"; else cat "$destination"; fi; } > "$cache_temp" \
            && mv -fT -- "$cache_temp" "$entry"; then
            cache_temp=
        else
            echo "  Warning: unable to save ${kind^^} cache entry; using the downloaded object." >&2
        fi
    fi
    # The caller still checks current validity, trust, and per-certificate
    # revocation. Invalid newly-downloaded objects never enter the cache.
    exit 0
)

# Use the summary for the requested CertID only (not every SingleResponse in
# -resp_text). OpenSSL can print a status-time warning yet exit successfully;
# explicitly enforce freshness rather than treating exit 0 as a valid status.
ocsp_report_is_current() {
    local report=$1 cert=$2 is_ca=${3:-0} this_update next_update this_epoch next_epoch now
    grep -Fxq -- "$cert: good" "$report" || grep -Fxq -- "$cert: revoked" "$report" \
        || grep -Fxq -- "$cert: unknown" "$report" || return 1
    this_update=$(sed -n 's/^[[:space:]]*This Update: *//p' "$report")
    next_update=$(sed -n 's/^[[:space:]]*Next Update: *//p' "$report")
    [[ -n "$this_update" && "$this_update" != *$'\n'* && "$next_update" != *$'\n'* ]] || return 1
    this_epoch=$(date -u -d "$this_update" +%s 2>/dev/null) || return 1
    now=$(date -u +%s)
    (( this_epoch <= now + clock_skew )) || return 1
    # Issuer CAs can publish long-lived responses. Use their signed deadline
    # unless the caller explicitly requested an age cap. Leaves and responses
    # without nextUpdate always retain the configured/default age bound.
    if (( is_ca == 0 || max_ocsp_age_set == 1 )) || [[ -z "$next_update" ]]; then
        (( now - this_epoch <= max_ocsp_age )) || return 1
    fi
    if [[ -n "$next_update" ]]; then
        next_epoch=$(date -u -d "$next_update" +%s 2>/dev/null) || return 1
        # No clock-skew extension beyond nextUpdate, even for a fresh download.
        (( next_epoch > now && next_epoch >= this_epoch )) || return 1
    fi
}

ocsp_verify_response() {
    local response=$1 cert=$2 verifier=$3 report=$4 is_ca=${5:-0}
    local -a age_args=()
    if (( is_ca == 0 || max_ocsp_age_set == 1 )); then age_args=(-status_age "$max_ocsp_age"); fi
    if ! timeout "$request_timeout" openssl ocsp -respin "$response" -issuer "$verifier" -cert "$cert" \
        -no_nonce -CAfile "$verifier" -partial_chain -validity_period "$clock_skew" \
        "${age_args[@]}" > "$report" 2>&1; then return 1; fi
    if ! ocsp_report_is_current "$report" "$cert" "$is_ca"; then
        echo 'OCSP response has no matching usable status, is stale, or has invalid update times.' >> "$report"
        return 1
    fi
}

fetch_ocsp_response() {
    local url=$1 response=$2 cert=$3 verifier=$4 report=$5 is_ca=${6:-0} request="$2.request"
    fetch_failure_shared=0
    openssl ocsp -issuer "$verifier" -cert "$cert" -no_nonce -reqout "$request" > "$report" 2>&1 || return 1
    # OpenSSL can hide an HTTP failure behind a content-type error. Use the
    # common transport to preserve HTTP status, deadlines, proxy settings, and
    # retry classification; OpenSSL still verifies the exact returned bytes.
    fetch "$url" "$response" "$request" 'OCSP request' >> "$report" 2>&1 || return 1
    ocsp_verify_response "$response" "$cert" "$verifier" "$report" "$is_ca"
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
    local cert=$1 label=$2 verifier=$3 is_ca=${4:-0}
    local cert_serial local_crl_urls idx url crl_pem
    local checked_local=0 revoked_local=0 ocsp_good_local=0
    local ocsp_url_local ocsp_output ocsp_rc ocsp_response ocsp_report

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
        crl_pem="$host_workdir/crl-$$-$RANDOM-${idx}.pem"
        echo; echo "Checking CRL ($label): $url"
        if is_ldap_url "$url"; then echo "  Result: LDAP CRL retrieval is not supported by this script" >&2; continue; fi
        if [[ -z "$verifier" ]]; then
            echo "  Result: issuer certificate unavailable; skipping CRL download because its signature cannot be verified" >&2
            continue
        fi
        if ! fetch_cached_object crl "$url" "$crl_pem" "$verifier"; then echo "  Result: unable to retrieve a usable CRL" >&2; continue; fi
        openssl crl -in "$crl_pem" -noout -issuer -lastupdate -nextupdate
        # fetch_cached_object verified this private snapshot's signature
        # against this issuer. Recheck time, which can advance after fetching.
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
            ocsp_response="$host_workdir/ocsp-$$-$RANDOM.der"
            ocsp_report="$ocsp_response.txt"
            fetch_cached_object ocsp "$ocsp_url_local" "$ocsp_response" "$verifier" "$cert" "$ocsp_report" "$is_ca"
            ocsp_rc=$?
            ocsp_output=$(cat "$ocsp_report" 2>/dev/null)
            if (( ocsp_rc != 0 )); then
                echo "  Result: OCSP query or response verification failed" >&2
                printf '%s\n' "$ocsp_output" | sed 's/^/    /' >&2
            elif grep -Fxq -- "$cert: revoked" "$ocsp_report"; then
                printf '%s\n' "$ocsp_output" | grep -Ei ': revoked|This Update|Next Update|Revocation Time' | sed 's/^/  /'
                echo "  Result: REVOKED"
                revoked_local=1
            elif grep -Fxq -- "$cert: good" "$ocsp_report"; then
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
check_host_details() {
    local domain=$1 port=$2
    if ! [[ "$port" =~ ^0*([1-9][0-9]{0,4})$ ]] || (( 10#${BASH_REMATCH[1]} > 65535 )); then
        echo "Error: port must be between 1 and 65535 (got '$port' for host '$domain')." >&2
        emit_error_json "$domain" "$port" "invalid port: $port"
        return 3
    fi
    # Normalize before both the TLS connection and numeric JSON output.
    port=$((10#${BASH_REMATCH[1]}))

    local host_workdir connection_host transport_host is_ip sni_args connect_target starttls_args
    local connect_attempt connect_ok connect_rc
    local -a warnings=()
    local leaf stapled_ocsp leaf_eku retry_workdir retry_eku status_retry_used=0
    local negotiated_protocol negotiated_cipher
    local leaf_text sig_alg pubkey_algo pubkey_bits key_usage_text
    local certificate_expired expiry_warning expiry_days_left end_date end_epoch
    local leaf_issuer issuer_cert issuer_cn
    local -a issuer_urls=()
    local index issuer_candidate
    local chain_bundle
    local -a verify_args=() chain_only_args=()
    local peer_valid=0
    local peer_trust_detail peer_verify_output peer_verify_rc certificate_names openssl_reason
    local -a chain_list=()
    local -A revocation_flag=()
    local intermediate_revoked=0
    local ci cert subj iss verifier
    local checked=0 revoked=0 ocsp_good=0
    local rc_checked rc_revoked rc_ocsp_good
    local trust_status expiry_status revocation_status overall_status exit_code reason
    local caa_records

    if ! host_workdir=$(mktemp -d "$workdir/host.XXXXXX"); then
        emit_error_json "$domain" "$port" "unable to create host working directory"
        return 3
    fi
    host_cache_events="$host_workdir/cache-events"

    connection_host=$domain
    if [[ "$connection_host" =~ ^\[(.*)\]$ ]]; then connection_host=${BASH_REMATCH[1]}; fi
    is_ip=0
    if [[ "$connection_host" == *:* || "$connection_host" =~ ^[0-9.]+$ ]]; then is_ip=1; fi
    if (( is_ip == 1 )); then
        sni_args=()
    else
        sni_args=(-servername "$connection_host")
    fi
    # Only the transport destination changes. SNI, identity validation and CAA
    # continue to use connection_host, derived from the original host argument.
    transport_host=${connect_ip:-$connection_host}
    if [[ "$transport_host" == *:* ]]; then
        connect_target="[$transport_host]:$port"
    else
        connect_target="$transport_host:$port"
    fi

    starttls_args=()
    [[ -n "$starttls_proto" ]] && starttls_args=(-starttls "$starttls_proto")
    if [[ -n "$connect_ip" && ( "$starttls_proto" == xmpp || "$starttls_proto" == xmpp-server ) ]]; then
        starttls_args+=(-xmpphost "$connection_host")
    fi

    echo "Fetching TLS certificate from ${domain}:${port} ...${starttls_proto:+ (STARTTLS: $starttls_proto)}"
    if (( cache_enabled == 0 )); then
        echo "Cache mode: DISABLED (--no-cache)"
    elif (( cache_dir_set == 1 )); then
        printf 'Cache mode: PERSISTENT (max age: %ss; directory: %s)\n' "$cache_max_age" "$cache_dir"
    else
        printf 'Cache mode: PER-RUN (max age: %ss)\n' "$cache_max_age"
    fi
    [[ -n "$connect_ip" ]] && echo "Connection target: $connect_target (identity: $connection_host)"
    connect_attempt=0
    connect_ok=0
    while :; do
        if timeout "$connect_timeout" openssl s_client -connect "$connect_target" "${sni_args[@]}" \
            "${starttls_args[@]}" -showcerts -status </dev/null >"$host_workdir/s_client.txt" 2>"$host_workdir/tls-errors.txt"; then
            connect_ok=1
            break
        else connect_rc=$?; fi
        openssl_failure_is_temporary "$connect_rc" "$host_workdir/tls-errors.txt" || break
        (( connect_attempt >= connect_retries )) && break
        connect_attempt=$((connect_attempt + 1))
        retry_wait "$connect_attempt" "TLS connection"
    done
    if (( connect_ok == 0 )); then
        cat "$host_workdir/tls-errors.txt" >&2
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

    # Some servers/load balancers misroute connections that request OCSP
    # stapling (the -status flag above) to an unrelated backend -- e.g. an
    # OCSP responder answering with its own signing certificate instead of
    # the real TLS server certificate. That cert has no serverAuth EKU and
    # cannot possibly match the hostname, so retry once without requesting
    # stapling before treating the result as a genuine trust failure.
    leaf_eku=$(openssl x509 -in "$leaf" -noout -ext extendedKeyUsage 2>/dev/null)
    if [[ -n "$leaf_eku" ]] && ! grep -q 'TLS Web Server Authentication' <<<"$leaf_eku"; then
        echo "Certificate has an unexpected purpose (no TLS Web Server Authentication); retrying without requesting OCSP stapling ..."
        retry_workdir=$(mktemp -d "$host_workdir/retry.XXXXXX")
        if timeout "$connect_timeout" openssl s_client -connect "$connect_target" "${sni_args[@]}" \
                "${starttls_args[@]}" -showcerts </dev/null >"$retry_workdir/s_client.txt" 2>/dev/null \
            && awk -v output_dir="$retry_workdir" '
                    /-----BEGIN CERTIFICATE-----/ { number++; file=output_dir "/cert-" number ".pem"; writing=1 }
                    writing { print > file }
                    /-----END CERTIFICATE-----/ { close(file); writing=0 }
                ' "$retry_workdir/s_client.txt" \
            && [[ -s "$retry_workdir/cert-1.pem" ]] \
            && openssl x509 -in "$retry_workdir/cert-1.pem" -noout >/dev/null 2>&1
        then
            retry_eku=$(openssl x509 -in "$retry_workdir/cert-1.pem" -noout -ext extendedKeyUsage 2>/dev/null)
            if [[ -z "$retry_eku" ]] || grep -q 'TLS Web Server Authentication' <<<"$retry_eku"; then
                echo "Retry without OCSP stapling returned a certificate with the expected purpose; using it instead."
                add_warning "initial connection (requesting OCSP stapling) received a certificate with the wrong purpose (no TLS Web Server Authentication, likely an OCSP responder or unrelated backend); retried without OCSP stapling and used that result instead. Stapled OCSP could not be captured for this host."
                status_retry_used=1
                rm -f "$host_workdir"/cert-*.pem
                cp "$retry_workdir"/cert-*.pem "$host_workdir"/
                cp "$retry_workdir/s_client.txt" "$host_workdir/s_client.txt"
            else
                echo "Retry without OCSP stapling still returned an unexpected certificate purpose; keeping the original result." >&2
            fi
        else
            echo "Retry without OCSP stapling failed to connect; keeping the original result." >&2
        fi
    fi

    stapled_ocsp='NOT STAPLED'
    if (( status_retry_used == 0 )); then
        if grep -q 'OCSP response: no response sent' "$host_workdir/s_client.txt"; then
            :
        elif grep -qi 'Cert Status: *good' "$host_workdir/s_client.txt"; then
            stapled_ocsp='PRESENT/GOOD (UNVERIFIED)'
        elif grep -qi 'Cert Status: *revoked' "$host_workdir/s_client.txt"; then
            stapled_ocsp='PRESENT/REVOKED (UNVERIFIED)'
        elif grep -q 'OCSP response:' "$host_workdir/s_client.txt"; then
            stapled_ocsp='PRESENT/UNKNOWN (UNVERIFIED)'
        fi
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
            issuer_candidate="$host_workdir/issuer-${index}.pem"
            if is_ldap_url "${issuer_urls[$index]}"; then continue; fi
            if ! fetch_cached_object aia "${issuer_urls[$index]}" "$issuer_candidate"; then continue; fi
            if is_issuer_of_leaf "$issuer_candidate"; then issuer_cert=$issuer_candidate; break; fi
        done
    fi
    [[ -n "$issuer_cert" ]] || echo "Warning: issuer certificate unavailable; CRL signatures cannot be verified." >&2

    issuer_cn=
    if [[ -n "$issuer_cert" ]]; then
        local issuer_multiline issuer_cn_val issuer_o_val issuer_c_val
        local -a issuer_parts=()
        issuer_multiline=$(openssl x509 -in "$issuer_cert" -noout -subject -nameopt multiline 2>/dev/null)
        issuer_cn_val=$(awk -F'= *' '/commonName/{print $2; exit}' <<<"$issuer_multiline")
        issuer_o_val=$(awk -F'= *' '/organizationName/{print $2; exit}' <<<"$issuer_multiline")
        issuer_c_val=$(awk -F'= *' '/countryName/{print $2; exit}' <<<"$issuer_multiline")
        # Escape embedded commas so a comma inside e.g. an organization name
        # can't be mistaken for the CN=/O=/C= field separator.
        issuer_cn_val=${issuer_cn_val//,/\\,}
        issuer_o_val=${issuer_o_val//,/\\,}
        issuer_c_val=${issuer_c_val//,/\\,}
        [[ -n "$issuer_cn_val" ]] && issuer_parts+=("CN=$issuer_cn_val")
        [[ -n "$issuer_o_val" ]] && issuer_parts+=("O=$issuer_o_val")
        [[ -n "$issuer_c_val" ]] && issuer_parts+=("C=$issuer_c_val")
        issuer_cn=$(IFS=,; echo "${issuer_parts[*]:-}")
    fi
    batch_issuer=$issuer_cn

    find_presented_issuer() {
        local child=$1 expected_issuer=$2 candidate candidate_subject
        local -a candidates=("$host_workdir"/cert-*.pem)
        [[ -n "$issuer_cert" ]] && candidates+=("$issuer_cert")
        # Self-signed candidates are tried last: during a root rollover a
        # server can present a same-named self-signed root alongside a
        # cross-signed sibling that continues the chain to a root actually
        # in the trust store, and both will pass this signature check (they
        # share the same key). Preferring the chain-extending candidate
        # means the walk reaches the real, trusted root instead of stopping
        # early at a same-named dead end.
        local -a self_signed_candidates=()
        for candidate in "${candidates[@]}"; do
            [[ "$candidate" == "$child" ]] && continue
            candidate_subject=$(certificate_subject "$candidate")
            [[ "$candidate_subject" == "$expected_issuer" ]] || continue
            if [[ "$candidate_subject" == "$(certificate_issuer "$candidate")" ]]; then
                self_signed_candidates+=("$candidate")
                continue
            fi
            if openssl verify -partial_chain -CAfile "$candidate" "$child" >/dev/null 2>&1; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done
        for candidate in "${self_signed_candidates[@]}"; do
            if openssl verify -partial_chain -CAfile "$candidate" "$child" >/dev/null 2>&1; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done
        if [[ -n "${system_ca_subjects[$expected_issuer]:-}" ]]; then
            candidate=${system_ca_subjects[$expected_issuer]}
            if openssl verify -partial_chain -CAfile "$candidate" "$child" >/dev/null 2>&1; then
                printf '%s\n' "$candidate"
                return 0
            fi
        fi
        return 1
    }

    # s_client does not validate the server certificate by default. A CRL signed by
    # an untrusted CA is not enough, so always validate the chain and identity.
    if (( verify_peer == 1 )); then
        chain_bundle="$host_workdir/intermediates.pem"
        : > "$chain_bundle"
        for cert in "$host_workdir"/cert-*.pem; do
            [[ "$cert" == "$leaf" ]] && continue
            # A self-signed cert in the "-untrusted" pool never usefully
            # extends the chain: it's either already a trusted root (found
            # independently via the CA store, not via this bundle) or a dead
            # end. Worse, during a root rollover a server may present both a
            # not-yet-trusted self-signed root and a cross-signed sibling
            # with the *same* subject/key; OpenSSL's chain builder locks onto
            # whichever one it meets first in this bundle and won't backtrack,
            # so a self-signed dead end here can hide a genuinely trusted
            # cross-signed path. Excluding self-signed certs avoids that trap.
            if [[ "$(certificate_subject "$cert")" == "$(certificate_issuer "$cert")" ]]; then
                continue
            fi
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
        peer_verify_output=$(openssl verify "${verify_args[@]}" "$leaf" 2>&1)
        peer_verify_rc=$?
        printf '%s\n' "$peer_verify_output"
        if (( peer_verify_rc != 0 )); then
            peer_valid=0
            if grep -qi 'hostname mismatch\|ip address mismatch' <<<"$peer_verify_output"; then
                # The chain signature/trust checks passed; only the identity
                # check failed. Re-run without -verify_hostname/-verify_ip to
                # say precisely that, instead of the vague combined message,
                # and report which name(s) the certificate actually covers.
                certificate_names=$(openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null \
                    | grep -oE 'DNS:[^, ]+|IP Address:[^, ]+' | sed -E 's/^(DNS|IP Address)://' | paste -sd, -)
                [[ -z "$certificate_names" ]] && certificate_names=$(certificate_subject "$leaf" | grep -oE 'CN=[^,]+' | sed 's/^CN=//')
                chain_only_args=(-purpose sslserver)
                [[ -s "$chain_bundle" ]] && chain_only_args+=(-untrusted "$chain_bundle")
                [[ -n "$ca_file" ]] && chain_only_args+=(-CAfile "$ca_file")
                [[ -n "$ca_path" ]] && chain_only_args+=(-CApath "$ca_path")
                if openssl verify "${chain_only_args[@]}" "$leaf" >/dev/null 2>&1; then
                    peer_trust_detail="certificate chain is trusted, but does not cover the requested name '$connection_host' (certificate covers: ${certificate_names:-none found})"
                else
                    peer_trust_detail="requested name '$connection_host' is not covered by the certificate (covers: ${certificate_names:-none found}), and the certificate chain is also not trusted"
                fi
            else
                # Not an identity problem: surface OpenSSL's own reason
                # instead of a vague default.
                openssl_reason=$(grep -oE 'depth lookup: .*' <<<"$peer_verify_output" | sed 's/^depth lookup: //' | tail -1)
                if [[ -n "$openssl_reason" ]]; then
                    peer_trust_detail="certificate chain is not trusted: $openssl_reason"
                else
                    peer_trust_detail="certificate chain or hostname/IP verification failed"
                fi
            fi
            echo "Certificate trust: INVALID ($peer_trust_detail)." >&2
            add_warning "$peer_trust_detail."
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
            check_certificate_revocation "$cert" "CA: $subj" "$verifier" 1
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
        reason=${peer_trust_detail:-"certificate chain or hostname/IP verification failed"}
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
    batch_days_left=${expiry_days_left:-}

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
        local current=$leaf parent subject issuer label source_suffix='' revocation_suffix
        local signature_status trust_result indent='' child_indent depth=0 cross_signed
        local local_root_candidate candidate_subject candidate_issuer current_fp candidate_fp
        echo "CA TREE"
        while :; do
            subject=$(certificate_subject "$current")
            issuer=$(certificate_issuer "$current")
            parent=
            cross_signed=0
            if [[ "$subject" == "$issuer" ]]; then
                label='ROOT CA'
                signature_status='SELF-SIGNED'
            elif (( depth == 0 )); then
                label=CERTIFICATE
                if parent=$(find_presented_issuer "$current" "$issuer"); then signature_status=VALID; else signature_status=UNKNOWN; fi
            else
                label=CA
                if parent=$(find_presented_issuer "$current" "$issuer"); then signature_status=VALID; else signature_status=UNKNOWN; fi
            fi
            # This cert's own stated issuer couldn't be resolved/verified, but
            # the local trust store independently trusts a *different*,
            # self-signed certificate sharing its subject name: the classic
            # cross-signed root-rollover pattern (e.g. Google's GTS Root R1
            # cross-signed by the retired GlobalSign Root CA, while a modern
            # self-signed GTS Root R1 is trusted directly). Walk into that
            # equivalent root instead of reporting a bogus untrusted/unknown
            # dead end -- this is a real, valid alternate signature path, not
            # a weakening of validation (we still require the candidate to be
            # genuinely self-signed and independently trusted on its own).
            if [[ "$signature_status" == UNKNOWN ]]; then
                local_root_candidate=${system_ca_subjects[$subject]:-}
                if [[ -n "$local_root_candidate" ]]; then
                    candidate_subject=$(certificate_subject "$local_root_candidate")
                    candidate_issuer=$(certificate_issuer "$local_root_candidate")
                    if [[ "$candidate_subject" == "$candidate_issuer" ]]; then
                        current_fp=$(openssl x509 -in "$current" -noout -fingerprint -sha256 2>/dev/null)
                        candidate_fp=$(openssl x509 -in "$local_root_candidate" -noout -fingerprint -sha256 2>/dev/null)
                        if [[ -n "$current_fp" && "$current_fp" != "$candidate_fp" ]] \
                            && openssl verify -purpose any "$local_root_candidate" >/dev/null 2>&1; then
                            cross_signed=1
                            signature_status='VALID (CROSS-SIGNED)'
                            parent=$local_root_candidate
                        fi
                    fi
                fi
            fi
            if (( depth == 0 )); then
                trust_result=$trust_status
            elif (( cross_signed == 1 )); then
                trust_result='TRUSTED (VIA EQUIVALENT ROOT)'
            else
                trust_result=$(certificate_trust "$current")
            fi
            revocation_suffix=
            [[ -n "${revocation_flag[$current]:-}" ]] && revocation_suffix=' [REVOKED]'
            printf '%s└── %s: %s%s%s [TRUST: %s] [SIGNATURE: %s]\n' \
                "$indent" "$label" "$subject" "$source_suffix" "$revocation_suffix" "$trust_result" "$signature_status"
            child_indent="${indent}    "
            if [[ "$subject" == "$issuer" ]]; then
                return
            fi
            if [[ -z "$parent" ]]; then
                printf '%s└── ISSUER: %s [NOT PROVIDED]\n' "$child_indent" "$issuer"
                return
            fi
            if [[ "$parent" == "$host_workdir"/cert-*.pem ]]; then
                source_suffix=' [PRESENTED]'
            elif [[ -n "$issuer_cert" && "$parent" == "$issuer_cert" ]]; then
                source_suffix=' [FETCHED VIA AIA]'
            else
                source_suffix=' [FROM LOCAL TRUST STORE]'
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
    finish_host_metrics
    if [[ "$output_format" == json ]]; then
        local warnings_json='['
        for index in "${!warnings[@]}"; do
            (( index > 0 )) && warnings_json+=','
            warnings_json+="\"$(json_escape "${warnings[$index]}")\""
        done
        warnings_json+=']'
        printf '{"host":"%s","port":%s,"connect_ip":%s,"issuer":"%s","trust":"%s","revocation":"%s","expiry":"%s","expiry_days_left":%s,"intermediate_revoked":%s,"stapled_ocsp":"%s","overall":"%s","reason":"%s","exit_code":%s,"warnings":%s,"elapsed_seconds":%s,"cache_hits":%s,"cache_misses":%s}\n' \
            "$(json_escape "$domain")" "$port" "$connect_ip_json" "$(json_escape "$issuer_cn")" "$(json_escape "$trust_status")" \
            "$(json_escape "$revocation_status")" "$(json_escape "$expiry_status")" \
            "${expiry_days_left:-null}" \
            "$(if (( intermediate_revoked == 1 )); then echo true; else echo false; fi)" \
            "$(json_escape "$stapled_ocsp")" "$(json_escape "$overall_status")" "$(json_escape "$reason")" "$exit_code" "$warnings_json" \
            "$batch_elapsed" "$batch_cache_hits" "$batch_cache_misses" >&3
    else
        print_final_status "$issuer_cn" "$trust_status" "$revocation_status" \
            "$expiry_status" "$expiry_days_left" "$overall_status" "$reason"
    fi
    return "$exit_code"
}

check_host() {
    local host_started_ns host_cache_events=''
    host_started_ns=$(date +%s%N)
    # Redirection does not spawn a subshell: the caller still receives the
    # same batch result variables and exit code. JSON uses its saved fd 3.
    if (( summary_only == 1 )); then
        check_host_details "$@" >/dev/null 2>&1
    else
        check_host_details "$@"
    fi
}

if [[ -n "$hosts_file" ]]; then
    declare -a job_hosts=() job_ports=()
    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        read -r parsed_host parsed_port _ <<<"$raw_line"
        [[ -z "$parsed_host" || "$parsed_host" == \#* ]] && continue
        job_hosts+=("$parsed_host")
        job_ports+=("${parsed_port:-443}")
    done < "$hosts_file"

    batch_total=${#job_hosts[@]}
    batch_worst=0
    declare -a batch_row_host=() batch_row_overall=() batch_row_issuer=() batch_row_reason=()
    declare -a batch_row_stats=()

    record_batch_result() {
        local h=$1 p=$2 rc=$3 overall=${4:-UNKNOWN} reason=${5:-"no reason recorded"} issuer=${6:-} days_left=${7:-}
        batch_row_host+=("${h}:${p}")
        batch_row_overall+=("$overall")
        batch_row_issuer+=("${issuer:-unknown}")
        batch_row_reason+=("$reason")
        batch_row_stats+=("${days_left:-N/A} ${batch_elapsed:-?}s ${batch_cache_hits:-?}/${batch_cache_misses:-?}")
        (( rc != 0 )) && batch_worst=1
    }

    if (( batch_parallel <= 1 )); then
        for job_idx in "${!job_hosts[@]}"; do
            batch_host=${job_hosts[$job_idx]}
            batch_port=${job_ports[$job_idx]}
            if (( summary_only == 0 )); then
                echo
                echo "############################################################"
                echo "### ${batch_host}:${batch_port}"
                echo "############################################################"
            fi
            batch_overall=
            batch_reason=
            batch_issuer=
            batch_days_left=
            check_host "$batch_host" "$batch_port"
            batch_rc=$?
            record_batch_result "$batch_host" "$batch_port" "$batch_rc" "$batch_overall" "$batch_reason" "$batch_issuer" "$batch_days_left"
        done
    else
        declare -a job_logs=() job_results=() active_pids=() active_idx=()
        for job_idx in "${!job_hosts[@]}"; do
            batch_host=${job_hosts[$job_idx]}
            batch_port=${job_ports[$job_idx]}
            job_logs[job_idx]=$(mktemp "$workdir/batch-log.XXXXXX")
            job_results[job_idx]=$(mktemp "$workdir/batch-res.XXXXXX")
            (
                {
                    if (( summary_only == 0 )); then
                        echo
                        echo "############################################################"
                        echo "### ${batch_host}:${batch_port}"
                        echo "############################################################"
                    fi
                    batch_overall=
                    batch_reason=
                    batch_issuer=
                    batch_days_left=
                    check_host "$batch_host" "$batch_port"
                    batch_rc=$?
                    # Put nonempty metrics first: Bash's tab IFS collapses
                    # empty trailing issuer/days fields on early errors.
                    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                        "$batch_elapsed" "$batch_cache_hits" "$batch_cache_misses" \
                        "$batch_rc" "$batch_overall" "$batch_reason" "$batch_issuer" "$batch_days_left" > "${job_results[$job_idx]}"
                } >"${job_logs[$job_idx]}" 2>&1
            ) &
            active_pids+=("$!")
            active_idx+=("$job_idx")
            if (( ${#active_pids[@]} >= batch_parallel )); then
                wait -n
                new_pids=() new_idx=()
                for i in "${!active_pids[@]}"; do
                    if kill -0 "${active_pids[$i]}" 2>/dev/null; then
                        new_pids+=("${active_pids[$i]}")
                        new_idx+=("${active_idx[$i]}")
                    fi
                done
                active_pids=("${new_pids[@]}")
                active_idx=("${new_idx[@]}")
            fi
        done
        wait

        for job_idx in "${!job_hosts[@]}"; do
            if (( summary_only == 0 )); then cat "${job_logs[$job_idx]}"; fi
            batch_rc=
            batch_overall=
            batch_reason=
            batch_issuer=
            batch_days_left=
            batch_elapsed=
            batch_cache_hits=
            batch_cache_misses=
            IFS=$'\t' read -r batch_elapsed batch_cache_hits batch_cache_misses batch_rc batch_overall batch_reason batch_issuer batch_days_left < "${job_results[$job_idx]}"
            record_batch_result "${job_hosts[$job_idx]}" "${job_ports[$job_idx]}" "${batch_rc:-3}" "$batch_overall" "$batch_reason" "$batch_issuer" "$batch_days_left"
        done
    fi

    if [[ "$output_format" != json ]]; then
        # Problems first, then healthy results; hosts within each group are
        # sorted alphabetically. Anything unforeseen falls back to first-seen
        # category order, appended after the known ones.
        batch_priority=(REVOKED EXPIRED "UNTRUSTED/INVALID" ERROR UNKNOWN "VALID (EXPIRING SOON)" VALID)
        declare -a batch_order=() batch_seen_cats=("${batch_priority[@]}")

        batch_append_sorted_category() {
            local cat=$1 i
            local -a pairs=()
            for i in "${!batch_row_overall[@]}"; do
                [[ "${batch_row_overall[$i]}" == "$cat" ]] && pairs+=("${batch_row_host[$i]}"$'\t'"$i")
            done
            (( ${#pairs[@]} == 0 )) && return
            while IFS=$'\t' read -r _ batch_sorted_i; do
                batch_order+=("$batch_sorted_i")
            done < <(printf '%s\n' "${pairs[@]}" | sort -t $'\t' -k1,1)
        }

        for batch_cat in "${batch_priority[@]}"; do
            batch_append_sorted_category "$batch_cat"
        done
        for batch_i in "${!batch_row_overall[@]}"; do
            batch_cat=${batch_row_overall[$batch_i]}
            batch_seen=0
            for batch_done_cat in "${batch_seen_cats[@]}"; do
                [[ "$batch_done_cat" == "$batch_cat" ]] && { batch_seen=1; break; }
            done
            if (( batch_seen == 0 )); then
                batch_seen_cats+=("$batch_cat")
                batch_append_sorted_category "$batch_cat"
            fi
        done

        # Column widths: HOST/STATUS/ISSUER/DL TIME H/M/REASON size to their
        # widest value, but ISSUER and REASON are capped (longer values are
        # shown truncated with an ellipsis) so one long entry cannot blow up
        # the whole table or wrap the terminal line; run the single host (or
        # use --json) for the untruncated reason.
        batch_issuer_cap=52
        batch_reason_cap=62
        declare -a batch_issuer_disp=() batch_reason_disp=()
        batch_host_w=4
        batch_status_w=6
        batch_issuer_w=6
        batch_stats_w=11
        for batch_i in "${!batch_row_host[@]}"; do
            (( ${#batch_row_host[$batch_i]} > batch_host_w )) && batch_host_w=${#batch_row_host[$batch_i]}
            (( ${#batch_row_overall[$batch_i]} > batch_status_w )) && batch_status_w=${#batch_row_overall[$batch_i]}
            (( ${#batch_row_stats[$batch_i]} > batch_stats_w )) && batch_stats_w=${#batch_row_stats[$batch_i]}
            batch_disp=${batch_row_issuer[$batch_i]}
            if (( ${#batch_disp} > batch_issuer_cap )); then
                batch_disp="${batch_disp:0:$((batch_issuer_cap - 1))}…"
            fi
            batch_issuer_disp[batch_i]=$batch_disp
            (( ${#batch_disp} > batch_issuer_w )) && batch_issuer_w=${#batch_disp}
            batch_reason_disp[batch_i]=${batch_row_reason[$batch_i]}
            if (( ${#batch_reason_disp[$batch_i]} > batch_reason_cap )); then
                batch_reason_disp[batch_i]="${batch_row_reason[$batch_i]:0:$((batch_reason_cap - 1))}…"
            fi
        done

        echo
        echo "BATCH SUMMARY (${batch_total} host(s) checked)"
        [[ -n "$connect_ip" ]] && printf '  CONNECT IP: %s\n' "$connect_ip"
        echo
        printf '  %-*s  %-*s  %-*s  %*s  %s\n' \
            "$batch_status_w" STATUS "$batch_host_w" HOST "$batch_issuer_w" ISSUER "$batch_stats_w" "DL TIME H/M" REASON
        printf '  %s  %s  %s  %s  %s\n' \
            "$(printf '%*s' "$batch_status_w" '' | tr ' ' '-')" \
            "$(printf '%*s' "$batch_host_w" '' | tr ' ' '-')" \
            "$(printf '%*s' "$batch_issuer_w" '' | tr ' ' '-')" \
            "$(printf '%*s' "$batch_stats_w" '' | tr ' ' '-')" \
            "$(printf '%*s' 6 '' | tr ' ' '-')"
        for batch_i in "${batch_order[@]}"; do
            printf '  %-*s  %-*s  %-*s  %*s  %s\n' \
                "$batch_status_w" "${batch_row_overall[$batch_i]}" \
                "$batch_host_w" "${batch_row_host[$batch_i]}" \
                "$batch_issuer_w" "${batch_issuer_disp[$batch_i]}" \
                "$batch_stats_w" "${batch_row_stats[$batch_i]}" \
                "${batch_reason_disp[$batch_i]}"
        done
    fi
    exit "$batch_worst"
else
    check_host "$domain" "$port"
    exit $?
fi
