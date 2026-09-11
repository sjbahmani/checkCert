# Changelog

## 1.10.0

- `BATCH SUMMARY` is now rendered as an aligned table (STATUS, HOST, ISSUER, REASON columns) instead of per-category text blocks; rows are still ordered problems-first (REVOKED, EXPIRED, UNTRUSTED/INVALID, ERROR, UNKNOWN, then VALID). The ISSUER column truncates past 42 characters with `…`; REASON is never truncated.

## 1.9.1

- The issuing CA shown in `ISSUER`, `BATCH SUMMARY`, and the JSON `issuer` field now includes organization and country, not just the common name — e.g. `CN=WE2,O=Google Trust Services,C=US` instead of just `WE2`. A comma embedded in a field value (e.g. an organization name) is escaped as `\,` so it can't be mistaken for the CN=/O=/C= separator.

## 1.9.0

- `CA TREE` now recognizes cross-signed root rollovers accurately: when a node's own stated issuer can't be verified but the local trust store independently trusts a different, self-signed certificate with the same subject name (e.g. Google's `GTS Root R1` cross-signed by the retired `GlobalSign Root CA`), the tree walks into that equivalent root instead of ending in `[NOT PROVIDED]`, and the node reads `TRUST: TRUSTED (VIA EQUIVALENT ROOT)` / `SIGNATURE: VALID (CROSS-SIGNED)` instead of a misleading `UNTRUSTED/INVALID` / `UNKNOWN`. The candidate must itself be genuinely self-signed and independently trusted — this recognizes a real alternate signature path, not a public-key-matching shortcut. The leaf's overall `TRUST` line is unaffected either way.

## 1.8.0

- Added an automatic retry for a rare but real failure mode: some servers/load balancers misroute connections that request OCSP stapling to an unrelated backend (e.g. an OCSP responder answering with its own signing certificate, observed on `msn.com`). When the received certificate's `extendedKeyUsage` excludes TLS Web Server Authentication, checkCRT.sh now retries once without requesting OCSP stapling and uses that result if it looks like a normal server certificate, noting the fallback in `ADVISORY WARNINGS` (and skipping `STAPLED OCSP` for that host, since it wasn't requested on the retry). If the retry is still wrong, the original result stands.
- Added a functional test (local PKI leaf with OCSP-signing-only EKU) covering the retry trigger and its "still wrong" fallback path.

## 1.7.0

- `CA TREE` can now resolve and verify roots that the server didn't present but that are already in the system's default trust store (checked once per run, plus `SSL_CERT_FILE`/`--ca-file`), instead of always showing them as `[NOT PROVIDED]`/`SIGNATURE: UNKNOWN` even when `TRUST` was already correctly `TRUSTED` via that same store.
- Every `CA TREE` node now tags how it was obtained: `[PRESENTED]`, `[FETCHED VIA AIA]`, or `[FROM LOCAL TRUST STORE]` — previously `[PRESENTED]` was applied to any self-signed root reached, which became misleading once roots could also be resolved locally.
- A locally-resolved root now also gets a real CRL/OCSP signature check (previously reported "could not be verified" when the true root wasn't presented).

## 1.6.0

- `FINAL STATUS` and `BATCH SUMMARY` now name the immediate issuing intermediate CA (its common name) before the leaf's own trust/revocation/expiry status, e.g. `ISSUER: Certum OV TLS G2 R39 CA` / `bmi.ir:443 [issuer: Certum OV TLS G2 R39 CA]: leaf certificate is revoked`. Added a matching `"issuer"` field to JSON output (`null` for hosts that never connected).

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
