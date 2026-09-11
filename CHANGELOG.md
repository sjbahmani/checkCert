# Changelog

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
