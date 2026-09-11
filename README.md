# checkCRT

`checkCRT.sh` verifies the trust chain and hostname/IP of the certificate
presented by a TLS endpoint, then checks its expiry and revocation through CRL
distribution points and OCSP.

## Requirements

Linux or another environment with Bash 4+, OpenSSL, `curl` or `wget`, GNU
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

`--json` reserves standard output for one JSON object; progress and diagnostic
messages are written to standard error. This makes it suitable for monitoring:

```json
{"host":"example.com","port":443,"trust":"TRUSTED","revocation":"NOT REVOKED","expiry":"NOT EXPIRED","expiry_days_left":46,"stapled_ocsp":"NOT STAPLED","overall":"VALID","exit_code":0,"warnings":[]}
```

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

- **Expiry warning** — `--expiry-warn-days N` (default 30; `0` disables it)
  flags certificates expiring soon. `EXPIRY` can now report `EXPIRING SOON` in
  addition to `NOT EXPIRED`/`EXPIRED`; this does not change the exit code.
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

Use `--connect-timeout`, `--request-timeout`, `--max-ocsp-age`, and
`--clock-skew` to tune monitoring behavior. `--proxy` and `--no-proxy` apply
to CRL and OCSP HTTP requests; direct TLS certificate retrieval is not routed
through an HTTP proxy.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Trusted, identity-valid, not expired, and not revoked by at least one verified CRL or OCSP response. |
| 2 | Revoked. |
| 3 | Unknown or operational/verification error. |
| 4 | Expired. |
| 5 | CA chain is untrusted, invalid, or does not match the supplied hostname/IP. |

Every completed check ends with this machine-readable, uppercase summary:

```text
FINAL STATUS
  TRUST: TRUSTED | UNTRUSTED/INVALID
  REVOCATION: NOT REVOKED | REVOKED | UNKNOWN
  EXPIRY: NOT EXPIRED | EXPIRING SOON | EXPIRED
  OVERALL: VALID | REVOKED | EXPIRED | UNTRUSTED/INVALID | UNKNOWN
```

Immediately before it, `CA TREE` displays the leaf and each cryptographically
linked CA certificate supplied by the server or retrieved from AIA. An issuer
marked `[NOT PROVIDED]` was not available to the script; it is not evidence
that the issuer is trusted. Each displayed certificate includes its individual
`TRUST` and parent-signature status. Before `CA TREE`, an `ADVISORY WARNINGS`
section lists every non-fatal issue found (see [Advisory checks](#advisory-checks)),
or `none`.

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

```bash
bash -n checkCRT.sh
shellcheck -s bash checkCRT.sh
```
