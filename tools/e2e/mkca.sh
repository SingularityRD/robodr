#!/usr/bin/env bash
# Throwaway test CA + server certificate for 127.0.0.1/localhost (E2E only).
# usage: mkca.sh OUT_DIR
set -euo pipefail
d=$1; mkdir -p "$d"; cd "$d"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
  -subj "/CN=robodr-e2e-test-ca" -keyout ca.key -out ca.pem \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 7 \
  -extfile ext.cnf -out server.pem 2>/dev/null
chmod 600 ca.key server.key
echo "$d/ca.pem $d/server.pem"
