#!/usr/bin/env bash
# Record Axel calls; normally run the real binary against local HTTP.
set -euo pipefail
printf 'attempt\n' >> "$CHECKCRT_AXEL_LOG"
printf '%s\n' "$@" > "$CHECKCRT_AXEL_ARGS"
output=
while (( $# )); do
    if [[ "$1" == -o ]]; then output=$2; break; fi
    shift
done
case "${CHECKCRT_AXEL_MODE:-real}" in
    failure) exit 1 ;;
    timeout) exec sleep 20 ;;
    invalid) cp "$CHECKCRT_AXEL_INVALID" "$output"; exit 0 ;;
    resume)
        if [[ ! -f "$output.st" ]]; then
            printf 'partial Axel data\n' > "$output"
            printf 'Axel state\n' > "$output.st"
            exec sleep 20
        fi
        grep -q '^partial Axel data$' "$output"
        cp "$CHECKCRT_AXEL_VALID" "$output"
        exit 0
        ;;
esac
# Recover original arguments, one per line, after parsing the output path.
mapfile -t args < "$CHECKCRT_AXEL_ARGS"
exec "$CHECKCRT_AXEL_BIN" "${args[@]}"
