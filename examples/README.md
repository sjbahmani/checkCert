# Examples

## iran-root-ca.pem

The self-signed root certificate for `Islamic Republic of Iran Root CA-G3`
(`C=IR, O=I.R.Government, OU=Root CA`), extracted from the full chain
presented by `bankmellat.ir:443`. It is not in OpenSSL's or browsers'
standard trust store, so sites under Iran's national PKI report
`UNTRUSTED/INVALID` by default. Use it as a private trust anchor to check
such sites:

```bash
./checkCRT.sh --ca-file examples/iran-root-ca.pem bankmellat.ir
```

SHA-256 fingerprint:
`AA:7F:F6:37:D0:61:29:5A:6A:00:3E:9D:66:21:A5:4F:47:80:BA:E7:AE:F9:60:43:A7:1B:7C:2A:F2:76:D5:56`

## hosts-iran.txt

A sample `--hosts-file` covering a few major Iranian banks, marketplaces,
telecoms, and media sites, plus `google.com` as a non-Iranian baseline. Pair
it with the CA file above so `bankmellat.ir` resolves as trusted too:

```bash
./checkCRT.sh --ca-file examples/iran-root-ca.pem --hosts-file examples/hosts-iran.txt
```
