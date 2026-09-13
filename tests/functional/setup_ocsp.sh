#!/usr/bin/env bash
# Generate an OCSP-only chain and leaves; no checked-in keys or certificates.
set -euo pipefail
fixture_dir=$1
http_port=$2
cd "$fixture_dir"
openssl req -new -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj '/CN=checkCRT OCSP Root' -addext 'basicConstraints=critical,CA:true' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout root.key -out root.pem >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=checkCRT OCSP Issuer' \
    -keyout issuer.key -out issuer.csr >/dev/null 2>&1
cat > issuer.ext <<EOF
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
authorityInfoAccess=OCSP;URI:http://127.0.0.1:$http_port/cgi-bin/ocsp/root
EOF
openssl x509 -req -in issuer.csr -CA root.pem -CAkey root.key -set_serial 100 \
    -days 20 -extfile issuer.ext -out issuer.pem >/dev/null 2>&1
cat > leaf.ext <<EOF
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1,DNS:ocsp.test
authorityInfoAccess=OCSP;URI:http://127.0.0.1:$http_port/cgi-bin/ocsp/leaf
EOF
serial=200
for leaf in good revoked other; do
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=checkCRT OCSP $leaf" \
        -keyout "$leaf.key" -out "$leaf.csr" >/dev/null 2>&1
    openssl x509 -req -in "$leaf.csr" -CA issuer.pem -CAkey issuer.key -set_serial "$serial" \
        -days 15 -extfile leaf.ext -out "$leaf.pem" >/dev/null 2>&1
    serial=$((serial + 1))
done
index_row() {
    local cert=$1 status=$2 expiry serial subject revoked=''
    expiry=$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')
    expiry=$(date -u -d "$expiry" +%y%m%d%H%M%SZ)
    serial=$(openssl x509 -in "$cert" -noout -serial | sed 's/^serial=//')
    subject=$(openssl x509 -in "$cert" -noout -subject -nameopt compat | sed 's/^subject=//')
    [[ "$status" != R ]] || revoked=$(date -u +%y%m%d%H%M%SZ)
    printf '%s\t%s\t%s\t%s\tunknown\t%s\n' "$status" "$expiry" "$revoked" "$serial" "$subject"
}
index_row good.pem V > issuer.index
index_row other.pem V >> issuer.index
index_row revoked.pem R >> issuer.index
index_row issuer.pem V > root.index
index_row issuer.pem R > root-revoked.index
: > empty.index
: > requests.log
printf 'dynamic\n' > mode
openssl ocsp -issuer issuer.pem -cert revoked.pem -no_nonce -reqout revoked.req >/dev/null 2>&1
