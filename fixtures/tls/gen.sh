#!/usr/bin/env bash
# Regenerate the test-only PKI under fixtures/tls/ (OpenSSL 3.0, EC P-256).
#
#   fixtures/tls/gen.sh
#
# Used by the Kafka TLS tests (crates/robodr-export) and the remote head
# anchor TLS tests (crates/robodr-blackbox, crates/robodr-agentd). The
# private keys are TEST-ONLY and public: never deploy them.
#
# | file                      | what                                                   |
# | ------------------------- | ------------------------------------------------------ |
# | ca.pem                    | test CA (2000-01-01 .. 2125-01-01)                     |
# | server.pem / server.key   | leaf, SAN DNS:localhost IP:127.0.0.1 IP:::1, serverAuth |
# | client.pem / client.key   | leaf CN=robodr-test-client, clientAuth                 |
# | wrong-host.pem / .key     | leaf by ca.pem, SAN DNS:wrong.example only, serverAuth |
# | expired.pem / .key        | leaf by ca.pem, localhost SANs, expired 2001-01-01     |
# | client-only.pem / .key    | leaf by ca.pem, localhost SANs, clientAuth EKU only    |
# | other-ca.pem              | an unrelated CA                                        |
# | other-server.pem / .key   | leaf by other-ca.pem, localhost SANs, serverAuth       |
# | other-client.pem / .key   | leaf by other-ca.pem, clientAuth                       |
#
# Certificate revocation (CRL) set: its own CA, so that it can be
# regenerated alone (`gen.sh crl`; every file above stays as it is). Used
# by the CRL tests of robodr-blackbox, robodr-export (Kafka, uplink),
# robodr-fleet and agentd's control plane.
#
# | file                          | what                                                  |
# | ----------------------------- | ----------------------------------------------------- |
# | crl-ca.pem                    | test CA with CRLs (2000-01-01 .. 2125-01-01)          |
# | crl-server.pem / .key         | leaf by crl-ca.pem, localhost SANs, serverAuth        |
# | crl-revoked-server.pem / .key | as crl-server, revoked in crl-ca.crl.pem              |
# | crl-client.pem / .key         | leaf by crl-ca.pem, CN=robodr-test-client, clientAuth |
# | crl-revoked-client.pem / .key | as crl-client, revoked in crl-ca.crl.pem              |
# | crl-ca.crl.pem                | CRL of crl-ca: both revoked leaves (next update 2125) |
# | crl-ca-empty.crl.pem          | CRL of crl-ca revoking nothing (next update 2125)     |
# | crl-ca-expired.crl.pem        | as crl-ca.crl.pem, issued 2000, next update 2001      |
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

ca_conf() { # name
  mkdir -p "$1/new"
  : >"$1/index.txt"
  echo 1000 >"$1/serial"
  cat >"$1/ca.cnf" <<EOF
[ ca ]
default_ca = d
[ d ]
dir = $work/$1
database = \$dir/index.txt
new_certs_dir = \$dir/new
serial = \$dir/serial
default_md = sha256
policy = p
unique_subject = no
copy_extensions = none
crlnumber = \$dir/crlnumber
crl_extensions = crl_ext
[ crl_ext ]
authorityKeyIdentifier = keyid:always
[ p ]
commonName = supplied
[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ server ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
authorityKeyIdentifier = keyid
[ wrong ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:wrong.example
authorityKeyIdentifier = keyid
[ client ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
authorityKeyIdentifier = keyid
[ clientlocal ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
authorityKeyIdentifier = keyid
EOF
}

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

make_ca() { # name cn out
  ca_conf "$1"
  key "$1/ca.key"
  openssl req -new -key "$1/ca.key" -subj "/CN=$2" -out "$1/ca.csr"
  openssl ca -batch -config "$1/ca.cnf" -selfsign -keyfile "$1/ca.key" -in "$1/ca.csr" \
    -extensions v3_ca -startdate 20000101000000Z -enddate 21250101000000Z \
    -out "$1/ca.full" 2>/dev/null
  openssl x509 -in "$1/ca.full" -out "$here/$3"
}

leaf() { # ca ext cn out start end
  key "$4.key"
  openssl req -new -key "$4.key" -subj "/CN=$3" -out "$4.csr"
  openssl ca -batch -config "$1/ca.cnf" -cert "$here/$( [ "$1" = ca ] && echo ca.pem || echo other-ca.pem)" \
    -keyfile "$1/ca.key" -in "$4.csr" -extensions "$2" -startdate "$5" -enddate "$6" \
    -out "$4.full" 2>/dev/null
  openssl x509 -in "$4.full" -out "$here/$4.pem"
  openssl pkey -in "$4.key" -out "$here/$4.key"
}

gencrl() { # out lastupdate nextupdate
  openssl ca -gencrl -config crl/ca.cnf -cert "$here/crl-ca.pem" -keyfile crl/ca.key \
    -crl_lastupdate "$2" -crl_nextupdate "$3" -out "$here/$1" 2>/dev/null
}

crl_pki() {
  ca_conf crl
  echo 01 >crl/crlnumber
  key crl/ca.key
  openssl req -new -key crl/ca.key -subj "/CN=RoboDR test CA with CRLs" -out crl/ca.csr
  openssl ca -batch -config crl/ca.cnf -selfsign -keyfile crl/ca.key -in crl/ca.csr \
    -extensions v3_ca -startdate 20000101000000Z -enddate 21250101000000Z \
    -out crl/ca.full 2>/dev/null
  openssl x509 -in crl/ca.full -out "$here/crl-ca.pem"
  local ext cn out
  while read -r ext cn out; do
    key "$out.key"
    openssl req -new -key "$out.key" -subj "/CN=$cn" -out "$out.csr"
    openssl ca -batch -config crl/ca.cnf -cert "$here/crl-ca.pem" -keyfile crl/ca.key \
      -in "$out.csr" -extensions "$ext" -startdate 20000101000000Z -enddate 21250101000000Z \
      -out "$out.full" 2>/dev/null
    openssl x509 -in "$out.full" -out "$here/$out.pem"
    openssl pkey -in "$out.key" -out "$here/$out.key"
  done <<EOF
server localhost crl-server
server localhost crl-revoked-server
client robodr-test-client crl-client
client robodr-test-client crl-revoked-client
EOF
  gencrl crl-ca-empty.crl.pem 20000101000000Z 21250101000000Z
  for r in crl-revoked-server crl-revoked-client; do
    openssl ca -config crl/ca.cnf -cert "$here/crl-ca.pem" -keyfile crl/ca.key \
      -revoke "$r.full" -crl_reason keyCompromise 2>/dev/null
  done
  gencrl crl-ca.crl.pem 20000101000000Z 21250101000000Z
  gencrl crl-ca-expired.crl.pem 20000101000000Z 20010101000000Z
}

if [ "${1:-}" = crl ]; then
  crl_pki
  echo "wrote the CRL set to $here"
  exit 0
fi

make_ca ca "RoboDR test CA" ca.pem
make_ca other "RoboDR unrelated test CA" other-ca.pem
long_a=20000101000000Z
long_b=21250101000000Z
leaf ca server localhost server "$long_a" "$long_b"
leaf ca client robodr-test-client client "$long_a" "$long_b"
leaf ca wrong wrong.example wrong-host "$long_a" "$long_b"
leaf ca server localhost expired 20000101000000Z 20010101000000Z
leaf ca clientlocal localhost client-only "$long_a" "$long_b"
leaf other server localhost other-server "$long_a" "$long_b"
leaf other client robodr-test-client other-client "$long_a" "$long_b"
crl_pki
echo "wrote $(ls "$here"/*.pem "$here"/*.key | wc -l) files to $here"
