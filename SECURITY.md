# Security policy

## Reporting a vulnerability

Do not publish security-sensitive findings in a public issue. Contact the
repository owner privately with a description, reproduction steps, affected
version, and any suggested mitigation.

## Scope and limitations

This tool fetches URLs embedded in certificates (AIA, CRL distribution points,
and OCSP URLs). Run it only for endpoints and certificates you are authorized
to inspect. Its trust decision is based on OpenSSL's configured trust store;
browser trust decisions may differ.
