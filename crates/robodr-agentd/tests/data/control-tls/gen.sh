#!/usr/bin/env bash
# Regenerates the TEST-ONLY PKI of the control-plane mTLS tests
# (crates/robodr-agentd/tests/control_plane.rs). OpenSSL 3, EC P-256.
#
#   robot-ca.pem      CA of the robot's server certificate (the SOC trusts it)
#   robot.pem/.key    server: SAN DNS:localhost, IP:127.0.0.1, IP:::1; serverAuth
#   soc-ca.pem        CA of the SOC's client certificates (control_plane.tls.client_ca)
#   soc.pem/.key      SOC client: clientAuth
#   soc2.pem/.key     a second SOC client of the same CA, another key (pin tests)
#   soc-expired.pem/.key  SOC client valid 2001-01-01 .. 2002-01-01 only
#   other-ca.pem, other.pem/.key  an unrelated CA and its client
#   crl-ca.pem        a SOC client CA with a CRL (control_plane.tls.client_crl)
#   soc-crl.pem/.key  its client, not revoked
#   soc-revoked.pem/.key  its client, revoked in crl-ca.crl.pem
#   crl-ca.crl.pem    crl-ca's CRL (next update 2125)
#
# Validity 2000-01-01 .. 2125-01-01 (except soc-expired). The CA keys are
# not kept. The private keys are test-only and worthless.
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/ca.cnf" <<CNF
[ ca ]
default_ca = test
[ test ]
dir = $work
database = \$dir/index.txt
new_certs_dir = \$dir
serial = \$dir/serial
default_md = sha256
policy = any
unique_subject = no
copy_extensions = none
crlnumber = \$dir/crlnumber
crl_extensions = crl_ext
[ crl_ext ]
authorityKeyIdentifier = keyid:always
[ any ]
commonName = supplied
organizationName = optional
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
[ client ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
authorityKeyIdentifier = keyid
CNF

ca() { # name cn
    : > "$work/index.txt"
    echo 01 > "$work/serial"
    openssl ecparam -name prime256v1 -genkey -noout -out "$work/$1.key"
    openssl req -new -key "$work/$1.key" -subj "/O=RoboDR test/CN=$2" -out "$work/$1.csr"
    openssl ca -batch -config "$work/ca.cnf" -selfsign -keyfile "$work/$1.key" \
        -extensions v3_ca -startdate 20000101000000Z -enddate 21250101000000Z \
        -in "$work/$1.csr" -out "$work/$1.full" 2>/dev/null
    openssl x509 -in "$work/$1.full" -out "$1.pem"
}

leaf() { # name cn ca ext start end [serial]
    : > "$work/index.txt"
    echo "${7:-10}" > "$work/serial"
    openssl ecparam -name prime256v1 -genkey -noout -out "$work/$1.ec"
    openssl pkcs8 -topk8 -nocrypt -in "$work/$1.ec" -out "$1.key"
    openssl req -new -key "$1.key" -subj "/O=RoboDR test/CN=$2" -out "$work/$1.csr"
    openssl ca -batch -config "$work/ca.cnf" -cert "$3.pem" -keyfile "$work/$3.key" \
        -extensions "$4" -startdate "$5" -enddate "$6" \
        -in "$work/$1.csr" -out "$work/$1.full" 2>/dev/null
    openssl x509 -in "$work/$1.full" -out "$1.pem"
    chmod 0600 "$1.key"
}

if [ "${1:-}" != crl ]; then
ca robot-ca "RoboDR test robot CA"
ca soc-ca "RoboDR test SOC CA"
ca other-ca "Unrelated test CA"
leaf robot "ugv-007" robot-ca server 20000101000000Z 21250101000000Z
leaf soc "soc-a" soc-ca client 20000101000000Z 21250101000000Z
leaf soc2 "soc-b" soc-ca client 20000101000000Z 21250101000000Z
leaf soc-expired "soc-old" soc-ca client 20010101000000Z 20020101000000Z
leaf other "intruder" other-ca client 20000101000000Z 21250101000000Z
fi

# A SOC client CA with a CRL (control_plane.tls.client_crl tests). Can be
# regenerated alone: `gen.sh crl` (the files above stay as they are).
crl_pki() {
    ca crl-ca "RoboDR test SOC CA with CRL"
    leaf soc-crl "soc-c" crl-ca client 20000101000000Z 21250101000000Z
    leaf soc-revoked "soc-revoked" crl-ca client 20000101000000Z 21250101000000Z 11
    echo 01 > "$work/crlnumber"
    openssl ca -config "$work/ca.cnf" -cert crl-ca.pem -keyfile "$work/crl-ca.key" \
        -revoke "$work/soc-revoked.full" 2>/dev/null
    openssl ca -gencrl -config "$work/ca.cnf" -cert crl-ca.pem -keyfile "$work/crl-ca.key" \
        -crldays 36500 -out crl-ca.crl.pem 2>/dev/null
}
crl_pki
chmod 0644 ./*.pem
