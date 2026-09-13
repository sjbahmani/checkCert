#!/usr/bin/env bash
# Builds a throwaway local PKI (root CA, two intermediates, three leaves, and
# two CRLs) used by run.sh to exercise checkCRT.sh end to end without relying
# on any real Internet host. Pure local file/openssl operations, no network.
#
# Layout produced under $PKI_DIR (default: a fresh mktemp -d):
#   certs/root.pem                self-signed trust anchor
#   certs/intermediate.pem        signs leaf-good and leaf-revoked
#   certs/intermediate2.pem       signs leaf3; gets revoked by root's CRL
#   certs/leaf-good.pem           not revoked
#   certs/leaf-revoked.pem        listed on intermediate's CRL
#   certs/leaf3.pem               itself fine, but its issuer is revoked
#   www/intermediate.crl          intermediate's CRL (revokes leaf-revoked)
#   www/root.crl                  root's CRL (revokes intermediate2)
#   www/intermediate.crt          PEM copy, served for AIA fetch tests
#   chain-good.pem, chain3.pem    leaf+chain bundles for s_server -cert_chain
set -euo pipefail

HTTPPORT=${HTTPPORT:-8990}
PKI_DIR=${PKI_DIR:-$(mktemp -d)}
mkdir -p "$PKI_DIR"/{ca,certs,private,www}
cd "$PKI_DIR"

get_exp() { openssl x509 -in "$1" -noout -enddate | sed 's/^notAfter=//' | xargs -I{} date -u -d {} +%y%m%d%H%M%SZ; }
get_serial() { openssl x509 -in "$1" -noout -serial | sed 's/^serial=//'; }
get_subj() { openssl x509 -in "$1" -noout -subject -nameopt compat | sed 's/^subject=//'; }

echo "Building PKI under $PKI_DIR ..." >&2

# --- Root CA ---
openssl genrsa -out private/root.key 2048 >/dev/null 2>&1
openssl req -x509 -new -key private/root.key -sha256 -days 3650 \
    -subj "/O=checkCRT Test/CN=checkCRT Test Root CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out certs/root.pem >/dev/null 2>&1

# A cross-signed copy of the trusted root whose actual issuer is deliberately
# omitted from the server chain and trust store. Its CRL cannot be verified.
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -subj "/O=checkCRT Test/CN=Unavailable Legacy Root" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout private/legacy-root.key -out certs/legacy-root.pem >/dev/null 2>&1
openssl req -new -key private/root.key \
    -subj "/O=checkCRT Test/CN=checkCRT Test Root CA" \
    -out root-cross.csr >/dev/null 2>&1
cat > root_cross_ext.cnf <<EOF
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
crlDistributionPoints=URI:http://127.0.0.1:${HTTPPORT}/unavailable-root.crl
EOF
openssl x509 -req -in root-cross.csr -CA certs/legacy-root.pem \
    -CAkey private/legacy-root.key -CAcreateserial -days 1825 -sha256 \
    -extfile root_cross_ext.cnf -out certs/root-cross.pem >/dev/null 2>&1

# --- Intermediate CA (signs leaf-good, leaf-revoked) ---
openssl genrsa -out private/intermediate.key 2048 >/dev/null 2>&1
openssl req -new -key private/intermediate.key \
    -subj "/O=checkCRT Test/CN=checkCRT Test Intermediate CA" \
    -out intermediate.csr >/dev/null 2>&1
cat > intermediate_ext.cnf <<EOF
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
EOF
openssl x509 -req -in intermediate.csr -CA certs/root.pem -CAkey private/root.key -CAcreateserial \
    -days 1825 -sha256 -extfile intermediate_ext.cnf -out certs/intermediate.pem >/dev/null 2>&1

# --- Intermediate2 CA (signs leaf3; this CA itself gets revoked) ---
openssl genrsa -out private/intermediate2.key 2048 >/dev/null 2>&1
openssl req -new -key private/intermediate2.key \
    -subj "/O=checkCRT Test/CN=checkCRT Test Intermediate2 CA (revoked)" \
    -out intermediate2.csr >/dev/null 2>&1
cat > intermediate2_ext.cnf <<EOF
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
crlDistributionPoints=URI:http://127.0.0.1:${HTTPPORT}/root.crl
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
EOF
openssl x509 -req -in intermediate2.csr -CA certs/root.pem -CAkey private/root.key -CAcreateserial \
    -days 1825 -sha256 -extfile intermediate2_ext.cnf -out certs/intermediate2.pem >/dev/null 2>&1

# --- Leaves signed by 'intermediate' ---
cat > leaf_ext.cnf <<EOF
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1,DNS:backend.test
crlDistributionPoints=URI:http://127.0.0.1:${HTTPPORT}/intermediate.crl
authorityInfoAccess=caIssuers;URI:http://127.0.0.1:${HTTPPORT}/intermediate.crt
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
EOF
for name in leaf-good leaf-revoked; do
    openssl genrsa -out "private/${name}.key" 2048 >/dev/null 2>&1
    openssl req -new -key "private/${name}.key" -subj "/CN=${name}.test" -out "${name}.csr" >/dev/null 2>&1
    openssl x509 -req -in "${name}.csr" -CA certs/intermediate.pem -CAkey private/intermediate.key -CAcreateserial \
        -days 825 -sha256 -extfile leaf_ext.cnf -out "certs/${name}.pem" >/dev/null 2>&1
done

# --- Leaf with the "wrong purpose" (OCSP-signing only, no serverAuth) used to
# exercise the OCSP-stapling-misroute retry fallback in checkCRT.sh ---
cat > leaf_ocsp_purpose_ext.cnf <<EOF
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=OCSPSigning
subjectAltName=IP:127.0.0.1
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
EOF
openssl genrsa -out private/leaf-ocsp-purpose.key 2048 >/dev/null 2>&1
openssl req -new -key private/leaf-ocsp-purpose.key -subj "/CN=leaf-ocsp-purpose.test" -out leaf-ocsp-purpose.csr >/dev/null 2>&1
openssl x509 -req -in leaf-ocsp-purpose.csr -CA certs/intermediate.pem -CAkey private/intermediate.key -CAcreateserial \
    -days 825 -sha256 -extfile leaf_ocsp_purpose_ext.cnf -out certs/leaf-ocsp-purpose.pem >/dev/null 2>&1

# --- Leaf signed by 'intermediate2' (itself fine; issuer will be revoked) ---
cat > leaf3_ext.cnf <<EOF
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
EOF
openssl genrsa -out private/leaf3.key 2048 >/dev/null 2>&1
openssl req -new -key private/leaf3.key -subj "/CN=leaf3.test" -out leaf3.csr >/dev/null 2>&1
openssl x509 -req -in leaf3.csr -CA certs/intermediate2.pem -CAkey private/intermediate2.key -CAcreateserial \
    -days 825 -sha256 -extfile leaf3_ext.cnf -out certs/leaf3.pem >/dev/null 2>&1

# --- Intermediate's CRL: revokes leaf-revoked only ---
cat > ca_intermediate.cnf <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir             = $PKI_DIR
database        = \$dir/ca/index.txt
new_certs_dir   = \$dir/ca
certificate     = \$dir/certs/intermediate.pem
private_key     = \$dir/private/intermediate.key
serial          = \$dir/ca/serial
crlnumber       = \$dir/ca/crlnumber
default_md      = sha256
default_crl_days = 30
policy          = policy_any
email_in_dn     = no
unique_subject  = no
[ policy_any ]
commonName = supplied
organizationName = optional
countryName = optional
[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF
good_exp=$(get_exp certs/leaf-good.pem); good_serial=$(get_serial certs/leaf-good.pem); good_subj=$(get_subj certs/leaf-good.pem)
rev_exp=$(get_exp certs/leaf-revoked.pem); rev_serial=$(get_serial certs/leaf-revoked.pem); rev_subj=$(get_subj certs/leaf-revoked.pem)
rev_date=$(date -u +%y%m%d%H%M%SZ)
: > ca/index.txt
printf 'V\t%s\t\t%s\tunknown\t%s\n' "$good_exp" "$good_serial" "$good_subj" >> ca/index.txt
printf 'R\t%s\t%s\t%s\tunknown\t%s\n' "$rev_exp" "$rev_date" "$rev_serial" "$rev_subj" >> ca/index.txt
echo 1000 > ca/serial
echo 1000 > ca/crlnumber
openssl ca -config ca_intermediate.cnf -gencrl -out www/intermediate.crl >/dev/null 2>&1

# --- Root's CRL: revokes intermediate2 only ---
cat > ca_root.cnf <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir             = $PKI_DIR
database        = \$dir/ca/root_index.txt
new_certs_dir   = \$dir/ca
certificate     = \$dir/certs/root.pem
private_key     = \$dir/private/root.key
serial          = \$dir/ca/root_serial
crlnumber       = \$dir/ca/root_crlnumber
default_md      = sha256
default_crl_days = 30
policy          = policy_any
email_in_dn     = no
unique_subject  = no
[ policy_any ]
commonName = supplied
organizationName = optional
countryName = optional
[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF
int_exp=$(get_exp certs/intermediate.pem); int_serial=$(get_serial certs/intermediate.pem); int_subj=$(get_subj certs/intermediate.pem)
int2_exp=$(get_exp certs/intermediate2.pem); int2_serial=$(get_serial certs/intermediate2.pem); int2_subj=$(get_subj certs/intermediate2.pem)
rev_date2=$(date -u +%y%m%d%H%M%SZ)
: > ca/root_index.txt
printf 'V\t%s\t\t%s\tunknown\t%s\n' "$int_exp" "$int_serial" "$int_subj" >> ca/root_index.txt
printf 'R\t%s\t%s\t%s\tunknown\t%s\n' "$int2_exp" "$rev_date2" "$int2_serial" "$int2_subj" >> ca/root_index.txt
echo 1000 > ca/root_serial
echo 1000 > ca/root_crlnumber
openssl ca -config ca_root.cnf -gencrl -out www/root.crl >/dev/null 2>&1

# --- Files served over HTTP for CRL DP / AIA fetches ---
cp certs/intermediate.pem www/intermediate.crt

# --- Chain bundles for s_server -cert_chain ---
cat certs/intermediate.pem > chain-good.pem
cat certs/intermediate.pem certs/root-cross.pem > chain-cross.pem
cat certs/intermediate2.pem certs/root.pem > chain3.pem

echo "PKI ready: $PKI_DIR" >&2
printf '%s\n' "$PKI_DIR"
