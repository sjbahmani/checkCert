# checkCRT

`checkCRT.sh` verifies the trust chain and hostname/IP of the certificate
presented by a TLS endpoint, then checks its expiry and revocation through CRL
distribution points and OCSP.

## Requirements

Linux or another environment with Bash 4+, OpenSSL, `curl` or `wget`, GNU
`timeout`, `date`, `awk`, `sed`, `grep`, `sort`, `tr`, and `mktemp`. LDAP CRL
URLs are not supported because they cannot be fetched by `curl`/`wget` in this
script.

## Usage

```bash
./checkCRT.sh example.com
./checkCRT.sh example.com 8443
./checkCRT.sh --ca-file company-ca.pem internal.example
./checkCRT.sh 2001:db8::10 443
./checkCRT.sh --json example.com
./checkCRT.sh --proxy http://proxy.example:8080 --no-proxy localhost example.com
```

The script always validates the chain and the supplied hostname (or IP address)
against OpenSSL's system trust store. Use `--ca-file` to add a private CA. The
`--verify-peer` option is accepted for compatibility but is already the default.
This is an OpenSSL/system-trust decision; browser trust stores may differ, so a
result does not guarantee identical treatment by every browser.

`--json` reserves standard output for one JSON object; progress and diagnostic
messages are written to standard error. This makes it suitable for monitoring:

```json
{"host":"example.com","port":443,"trust":"TRUSTED","revocation":"NOT REVOKED","expiry":"NOT EXPIRED","stapled_ocsp":"NOT STAPLED","overall":"VALID","exit_code":0}
```

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
  EXPIRY: NOT EXPIRED | EXPIRED
  OVERALL: VALID | REVOKED | EXPIRED | UNTRUSTED/INVALID | UNKNOWN
```

Immediately before it, `CA TREE` displays the leaf and each cryptographically
linked CA certificate supplied by the server or retrieved from AIA. An issuer
marked `[NOT PROVIDED]` was not available to the script; it is not evidence
that the issuer is trusted. Each displayed certificate includes its individual
`TRUST` and parent-signature status.

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
