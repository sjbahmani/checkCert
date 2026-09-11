# Changelog

## 1.5.0

- `--hosts-file` now checks hosts concurrently by default: new `--parallel N` (default 6, requires Bash 4.3+); `--parallel 1` restores strictly sequential, streaming-as-it-runs behavior. Per-host output stays in input-file order regardless; NDJSON lines in `--json` mode are written in completion order.
- `BATCH SUMMARY` now groups hosts by outcome (problems first: REVOKED, EXPIRED, UNTRUSTED/INVALID, ERROR, UNKNOWN, then VALID) with a full plain-language reason per host, instead of a flat list of bare exit codes.
- Fixed: a host that failed before completing a check (connection failure, no certificate presented, etc.) previously vanished from `--json`/`--hosts-file` output entirely; it now emits a minimal JSON record (`overall: ERROR`, `exit_code: 3`, an `error` message).

## 1.4.0

- Added `--hosts-file FILE` batch mode to check a list of hosts in one run (NDJSON in `--json` mode); process exit is 0 only if every host exited 0, otherwise 1.
- Revocation checking now also covers every intermediate CA in the resolvable chain, not just the leaf; a revoked intermediate is flagged `[REVOKED]` in the CA TREE, warned about, and escalates `REVOCATION`/`OVERALL` to REVOKED.
- Added `--fail-on-expiry-warning` to opt into a dedicated exit code 6 for an otherwise-valid certificate that is only expiring soon (default behavior, exit 0, is unchanged).
- Fixed: chain trust verification now includes the issuer certificate recovered via AIA, so servers that omit their intermediate are no longer incorrectly reported UNTRUSTED/INVALID.
- Added `tests/functional/` — a local, disposable PKI + `openssl s_server`/`http.server` harness that exercises the full pipeline end-to-end (valid, revoked leaf, revoked intermediate, AIA chain recovery, batch mode) without depending on real Internet hosts; wired into CI.

## 1.3.0

- Added `--starttls PROTO` for SMTP/IMAP/POP3/FTP/LDAP/XMPP/etc. services that upgrade to TLS.
- Added an expiry-warning threshold (`--expiry-warn-days`, default 30) and `expiry_days_left` in JSON output; `EXPIRY` can now report `EXPIRING SOON`.
- Added non-fatal advisory checks for weak TLS protocol/cipher, weak certificate signature algorithm, undersized public keys, missing serverAuth EKU, and Certificate Transparency SCT presence, surfaced in a new `ADVISORY WARNINGS` section and JSON `warnings` array.
- Added DNS CAA record lookup (`--no-caa` to disable) using `dig`, `host`, or `nslookup`.
- LDAP CRL and AIA issuer URLs are now detected and skipped with a clear message instead of silently failing to fetch.

## 1.2.0

- Added JSON output, timeout and proxy controls, and CA-path support.
- Require fresh CRL and OCSP data.
- Report OCSP stapling and per-certificate trust/signature results in the CA tree.
- Added project security, contribution, and regression-test documentation.

## 1.1.0

- Added trust, revocation, expiry, and overall status fields.
- Added CA tree output and mandatory hostname/chain validation.
