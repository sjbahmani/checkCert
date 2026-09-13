# checkCRT

`checkCRT.sh` verifies the trust chain and hostname/IP of the certificate
presented by a TLS endpoint, then checks its expiry and revocation through CRL
distribution points and OCSP.

## Requirements

Linux or another environment with Bash 4.3+ (needed for `wait -n`, used by
`--hosts-file`'s default parallel mode), OpenSSL, `curl` or `wget`, GNU
`timeout`, `date`, `awk`, `sed`, `grep`, `sort`, `tr`, and `mktemp`. LDAP CRL
and AIA issuer URLs are detected and skipped with a clear message, since they
cannot be fetched by `curl`/`wget` in this script. `dig`, `host`, or
`nslookup` (any one of them) is required for the CAA record lookup; the
lookup is skipped, not fatal, when none are installed.

## Usage

```bash
./checkCRT.sh example.com
./checkCRT.sh example.com 8443
./checkCRT.sh --ca-file company-ca.pem internal.example
./checkCRT.sh 2001:db8::10 443
./checkCRT.sh --json example.com
./checkCRT.sh --proxy http://proxy.example:8080 --no-proxy localhost example.com
./checkCRT.sh --starttls smtp mail.example.com 587
./checkCRT.sh --expiry-warn-days 14 example.com
./checkCRT.sh --no-caa internal.example
./checkCRT.sh --hosts-file hosts.txt
./checkCRT.sh --summary-only example.com
./checkCRT.sh --summary-only --hosts-file hosts.txt
```

The script always validates the chain and the supplied hostname (or IP address)
against OpenSSL's system trust store. Use `--ca-file` to add a private CA. The
`--verify-peer` option is accepted for compatibility but is already the default.
This is an OpenSSL/system-trust decision; browser trust stores may differ, so a
result does not guarantee identical treatment by every browser.

See [`examples/`](examples/) for sample private trust anchors to pass via
`--ca-file`, such as `examples/iran-root-ca.pem` for checking sites under
Iran's national PKI:

```bash
./checkCRT.sh --ca-file examples/iran-root-ca.pem bankmellat.ir
```

A ready-made `--hosts-file`, `examples/hosts-iran.txt`, covers major Iranian
banks, marketplaces, telecoms, crypto exchanges, cloud providers, and
government sites, plus `google.com` as a non-Iranian baseline:

```bash
./checkCRT.sh --hosts-file examples/hosts-iran.txt
```

`--json` reserves standard output for one JSON object; progress and diagnostic
messages are written to standard error. This makes it suitable for monitoring:

```json
{"host":"example.com","port":443,"issuer":"CN=WE2,O=Google Trust Services,C=US","trust":"TRUSTED","revocation":"NOT REVOKED","expiry":"NOT EXPIRED","expiry_days_left":46,"intermediate_revoked":false,"stapled_ocsp":"NOT STAPLED","overall":"VALID","exit_code":0,"warnings":[]}
```

Use `--summary-only` to hide certificate details, the CA tree, progress, and
diagnostics. A single-host check prints only `FINAL STATUS`; a hosts-file
check prints only `BATCH SUMMARY`, in both sequential and parallel modes.
All checks and exit codes stay the same, and the batch table keeps its existing
issuer and reason truncation.

With `--json --summary-only`, standard output still contains the complete
JSON/NDJSON records (including warnings and failure reasons), but per-host
diagnostics on standard error are suppressed. Invalid command-line arguments
and startup errors are still reported. If a single-host check cannot complete,
the text summary reports `OVERALL: ERROR`, `UNKNOWN` check statuses, and the
failure reason (exit 3).

## Batch mode

`--hosts-file FILE` checks every host in `FILE` instead of a single
positional host/port, one `host [port]` per line (port defaults to 443).
Blank lines and lines starting with `#` are ignored:

```text
# production endpoints
example.com
internal.example 8443
mail.example.com 587
```

Every other option (`--ca-file`, `--starttls`, timeouts, `--expiry-warn-days`,
...) applies to every host in the file — there is no per-host override. In
`--json` mode each host writes one JSON object, so standard output becomes
newline-delimited JSON (NDJSON), not a single array. The process exit code is
`0` only if every host exited `0`; otherwise it's `1` — inspect each host's
own `exit_code`/`OVERALL` for detail rather than relying on the aggregate.

Hosts are checked `--parallel N` at a time (default `6`; requires Bash 4.3+).
With `N=1`, hosts run strictly in order and each one's output streams as it
runs. With `N>1`, each host's output is buffered and printed once that host
finishes, but always in the file's original order — so results stay
readable and easy to scan even though hosts may finish out of order (NDJSON
lines in `--json` mode, however, are written in *completion* order, not
input order, since they stream live as each host finishes). After the
per-host reports, `BATCH SUMMARY` lists every host as a table — rows grouped
problems first (`REVOKED`, `EXPIRED`, `UNTRUSTED/INVALID`, `ERROR`,
`UNKNOWN`), then `VALID`, and alphabetized by host within each group — with
the immediate issuing CA and a plain-language reason instead of a bare exit
code:

```text
BATCH SUMMARY (4 host(s) checked)

  STATUS   HOST            ISSUER                                      DAYS LEFT  REASON
  -------  --------------  ------------------------------------------  ---------  ------
  REVOKED  bmi.ir:443      CN=Certum OV TLS G2 R39 CA,O=Asseco Data …        42  leaf certificate is revoked
  VALID    example.com:443 CN=WE2,O=Google Trust Services,C=US               46  trusted, not revoked, not expiring soon
  ...
```

The `ISSUER` column is truncated with `…` past 42 characters and `REASON`
past 60 characters to keep the table readable. Run a single-host check or use
`--json` to obtain the complete reason.

## STARTTLS

Use `--starttls PROTO` to check mail and other protocols that upgrade a plain
connection to TLS instead of connecting directly, e.g.
`--starttls smtp mail.example.com 587` or `--starttls imap mail.example.com 143`.
Supported values come from the local OpenSSL build's `s_client -starttls`
(typically `smtp`, `imap`, `pop3`, `ftp`, `nntp`, `ldap`, `xmpp`/`xmpp-server`,
`postgres`, `mysql`, `lmtp`, `irc`, `sieve`).

## Advisory checks

Beyond trust/expiry/revocation, every run also reports and collects into a
non-fatal `ADVISORY WARNINGS` list (and the JSON `warnings` array):

- **Expiry warning** — `--expiry-warn-days N` (default 14; `0` disables it)
  flags certificates expiring soon. `EXPIRY` can now report `EXPIRING SOON` in
  addition to `NOT EXPIRED`/`EXPIRED`. By default this does not change the
  exit code; pass `--fail-on-expiry-warning` to exit `6` instead of `0` for
  an otherwise-valid certificate that is only expiring soon.
- **Weak cryptography** — deprecated TLS protocol versions/ciphers negotiated
  on the connection, MD5/SHA-1 certificate signatures, and undersized RSA/DSA
  (< 2048 bit) or EC (< 224 bit) public keys.
- **Key usage / EKU** — flags a certificate whose `extendedKeyUsage`
  extension is present but omits TLS Web Server Authentication.
- **Certificate Transparency** — reports whether an SCT is embedded in the
  certificate or present via the TLS extension (presence only; log signatures
  are not independently verified).
- **CAA records** — looks up DNS `CAA` records at the exact hostname using
  `dig`, `host`, or `nslookup` (whichever is available); skipped for IP
  targets, when none of those tools are present, or with `--no-caa`. Parent
  domains are not walked, so an empty result is not proof that any CA may
  issue.

These checks are informational: they never change `TRUST`, `REVOCATION`, or
the exit code, since browsers and CAs vary in how strictly they enforce them.

## Revocation checks

CRLs must have a valid signature and a current `lastUpdate`/`nextUpdate`
period. OCSP responses are signature-verified, tolerate only the configured
clock skew, and are rejected when older than `--max-ocsp-age` (24 hours by
default). `STAPLED OCSP` reports the status sent during the TLS handshake; it
is marked `UNVERIFIED` because OpenSSL's `s_client` text output does not expose
the raw staple for independent signature verification. The direct OCSP query
remains the verified revocation result.

The script always requests OCSP stapling (the TLS `status_request` extension)
so it can report `STAPLED OCSP`. A few servers/load balancers misroute
connections that request it to an unrelated backend — e.g. an internal OCSP
responder answering with its own signing certificate instead of the real
site certificate (observed on `msn.com` from some network paths). When the
received leaf has an `extendedKeyUsage` that excludes TLS Web Server
Authentication, the script automatically retries once without requesting
stapling; if that retry comes back with a normal server certificate, it's
used for the rest of the check, `STAPLED OCSP` is skipped for that host (it
wasn't requested on the retry), and an `ADVISORY WARNINGS` entry records
that this happened. If the retry is still the wrong purpose, the original
result stands — this is not a fallback to "assume valid," just a way to
avoid a false `UNTRUSTED/INVALID` caused purely by asking for stapling.

Every intermediate CA in the resolvable chain (leaf → ... → root) is checked
against its *own* CRL/OCSP too, not just the leaf: a revoked intermediate
invalidates everything it issued even when the leaf's own certificate looks
fine. A revoked intermediate is reported as `[REVOKED]` in the `CA TREE`, adds
an `ADVISORY WARNINGS` entry naming it, sets JSON `intermediate_revoked: true`,
and escalates `REVOCATION`/`OVERALL` to `REVOKED` (exit 2) exactly like a
revoked leaf. The chain walk stops at the root (never revocation-checked
against itself) or at the first unresolvable issuer.

Use `--connect-timeout`, `--request-timeout`, `--max-ocsp-age`, and
`--clock-skew` to tune monitoring behavior. `--proxy` and `--no-proxy` apply
to CRL and OCSP HTTP requests; direct TLS certificate retrieval is not routed
through an HTTP proxy.

If a network operation fails (transient blips, filtering, etc.) — the
initial TLS connection, a CRL download, or an OCSP query — it's retried
automatically. `--connect-retries` sets how many extra attempts to make for
each of these (default 4; `0` disables retrying) and `--retry-delay` sets
the pause between attempts in seconds (default 3). This applies per host, so
in `--hosts-file` batch mode each host gets its own retries. Without this, a
single transient CRL/OCSP failure for a certificate that has no other usable
revocation source would surface as `REVOCATION: UNKNOWN` even though the
certificate itself is fine.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Trusted, identity-valid, not expired, and not revoked by at least one verified CRL or OCSP response. |
| 2 | Revoked (the leaf certificate or an intermediate CA in its chain). |
| 3 | Unknown or operational/verification error. |
| 4 | Expired. |
| 5 | CA chain is untrusted, invalid, or does not match the supplied hostname/IP. |
| 6 | Valid but expiring soon — only with `--fail-on-expiry-warning`; otherwise this case still exits `0` (see [Advisory checks](#advisory-checks)). |

In `--hosts-file` mode the *process* exit code is `0` only if every host
exited `0`, otherwise `1` (see [Batch mode](#batch-mode)); these per-host
codes still apply to each host's own result within the run.

Every completed check ends with this machine-readable, uppercase summary:

```text
FINAL STATUS
  ISSUER: <immediate issuing CA's CN, O, and C (e.g. CN=WE2,O=Google Trust Services,C=US), or "unknown">
  TRUST: TRUSTED | UNTRUSTED/INVALID
  REVOCATION: NOT REVOKED | REVOKED | UNKNOWN
  EXPIRY: NOT EXPIRED | EXPIRING SOON | EXPIRED
  OVERALL: VALID | REVOKED | EXPIRED | UNTRUSTED/INVALID | UNKNOWN
```

Immediately before it, `CA TREE` displays the leaf and each cryptographically
linked CA certificate, tagging how each was obtained: `[PRESENTED]` (sent by
the server), `[FETCHED VIA AIA]` (recovered from the Authority Information
Access URL), or `[FROM LOCAL TRUST STORE]` (found by exact subject match in
the system's default CA bundle, `SSL_CERT_FILE`, or `--ca-file` — this is
also why the main `TRUST` decision can already read `TRUSTED` even when a
server omits its root: `openssl verify` consults that same store directly).
An issuer marked `[NOT PROVIDED]` could not be found in any of those places;
it is not evidence that the issuer is untrusted, only that this script
couldn't locate a copy of it to display or independently verify its
signature. Each displayed certificate includes its individual `TRUST` and
parent-signature status.

A node can also read `SIGNATURE: VALID (CROSS-SIGNED)` / `TRUST: TRUSTED
(VIA EQUIVALENT ROOT)`: its own stated issuer couldn't be verified, but the
local trust store independently trusts a *different*, self-signed
certificate sharing its subject name — the classic root-rollover pattern,
e.g. Google's `GTS Root R1` is often presented cross-signed by the retired
`GlobalSign Root CA` for legacy-client compatibility, while modern trust
stores (including yours) already trust a separate, purely self-signed
`GTS Root R1` directly. When this is detected, the tree walks into that
equivalent root instead of ending in `[NOT PROVIDED]`, since it's a real,
independently-verified alternate signature path (the candidate must itself
be genuinely self-signed and separately trusted) — not a weakening of
validation by matching public keys across unrelated files. The leaf's
overall `TRUST` line is unaffected either way, since it already reflects the
real, successfully-built chain.

Before `CA TREE`, an `ADVISORY WARNINGS` section lists every non-fatal issue
found (see [Advisory checks](#advisory-checks)), or `none`.

An `UNKNOWN` result is expected when an endpoint provides no usable CRL/OCSP
information or revocation data is unreachable or invalid. A successful result
is not a replacement for full TLS policy enforcement in a client application.

## Security notes

The script follows issuer and CRL URLs contained in the server certificate.
Run it only against endpoints/certificates you intend to inspect. Network
availability and CA revocation-publishing practices affect whether a definitive
result can be obtained. For OCSP, the certificate's verified issuing CA is
used as the trust anchor; this supports private PKI chains whose root is not in
the local system store.

## Development

Tests additionally require `jq` for JSON/NDJSON assertions and BusyBox with the
`httpd` applet for the local HTTP fixture. Install ShellCheck for linting too.
On Debian/Ubuntu:

```bash
sudo apt-get install jq busybox-static shellcheck
```

These are development dependencies; running `checkCRT.sh` does not require
`jq` or BusyBox. The test suite does not require Python.

```bash
bash -n checkCRT.sh
shellcheck -s bash checkCRT.sh
./tests/test_cli.sh          # CLI parsing/validation, no network
./tests/functional/run.sh    # end-to-end against a local throwaway PKI
```

`tests/functional/run.sh` builds a disposable root CA, two intermediates, and
three leaves (see `tests/functional/setup_pki.sh`), serves them over local
`openssl s_server`/`busybox httpd` instances on 127.0.0.1, and asserts
`checkCRT.sh`'s exit code and output for: a valid chain, a revoked leaf, a
revoked intermediate (with an otherwise-fine leaf), a server that omits its
intermediate (regression test for AIA-based chain recovery), and
`--hosts-file` batch mode. It binds local TCP ports, so it needs permission
to do so in restricted/sandboxed environments; it makes no real network
requests.
