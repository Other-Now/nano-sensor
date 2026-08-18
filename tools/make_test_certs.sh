#!/usr/bin/env bash
# Generate the throwaway PKI the mTLS tests run against.
#
# Everything here is a TEST credential with no passphrase, valid for one year,
# and regenerated on demand. None of it is checked in -- a repository containing
# a private key trains people to ignore the fact that a repository contains a
# private key.
#
# Produces, in the output directory:
#   ca.crt / ca.key          the test certificate authority
#   server.crt / server.key  the mock cloud's identity
#   client.crt / client.key  the agent's identity (PEM, for the OpenSSL backend)
#   client.pfx              the same identity as PKCS#12 (for the WinHTTP backend)
#   server.pin              hex SHA-256 of server.crt's DER, the value the agent pins
set -euo pipefail

# Git Bash / MSYS rewrites any argument that looks like a Unix path into a
# Windows one, which turns the X.509 subject "/C=IN/O=.../CN=..." into
# "C:/Program Files/Git/C=IN/..." and makes openssl reject it. Excluding all
# arguments from that conversion is the documented escape hatch; it is a no-op
# on real Linux.
export MSYS2_ARG_CONV_EXCL="*"

OUT="${1:-build/testpki}"
mkdir -p "$OUT"
cd "$OUT"

SUBJ_BASE="/C=IN/O=nano-sensor test"

# --- CA -------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout ca.key -out ca.crt \
    -subj "$SUBJ_BASE/CN=nano-sensor test CA" 2>/dev/null

# --- server ---------------------------------------------------------------
# A SAN is mandatory: CN-only certificates have been rejected by modern TLS
# stacks for years, and the failure mode is an unhelpful handshake error.
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj "$SUBJ_BASE/CN=localhost" 2>/dev/null

cat > server.ext <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile server.ext 2>/dev/null

# --- client ---------------------------------------------------------------
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
    -subj "$SUBJ_BASE/CN=test-sensor-01" 2>/dev/null

cat > client.ext <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -extfile client.ext 2>/dev/null

# PKCS#12 for the Windows backend. -legacy selects RC2/3DES encryption, which
# OpenSSL 3 no longer uses by default but Windows' PFXImportCertStore still
# reads most reliably; the alternative is a modern bundle that some Windows
# builds reject with a bare "invalid password".
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt \
    -certfile ca.crt -passout pass: -legacy 2>/dev/null \
  || openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt \
       -certfile ca.crt -passout pass: 2>/dev/null

# --- the pin --------------------------------------------------------------
# SHA-256 over the DER encoding, which is exactly what both transport backends
# hash at runtime.
openssl x509 -in server.crt -outform DER 2>/dev/null \
  | openssl dgst -sha256 \
  | sed 's/^.*= *//' \
  | tr -d '\r\n' > server.pin

rm -f server.csr client.csr server.ext client.ext

echo "test PKI written to $(pwd)"
echo "server pin: $(cat server.pin)"
