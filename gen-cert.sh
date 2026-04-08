#!/bin/bash
# Regenerates wt-cert.pem / wt-key.pem (ECDSA P-256, 14-day validity required
# for WebTransport serverCertificateHashes) and patches the hash in client.js.
set -e

cd "$(dirname "$0")"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout wt-key.pem -out wt-cert.pem \
  -days 14 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" 2>/dev/null

# Byte array for new Uint8Array([...]) in client.js
BYTE_ARRAY=$(openssl x509 -in wt-cert.pem -outform DER | \
  openssl dgst -sha256 -binary | \
  xxd -p | tr -d '\n' | \
  sed 's/\(..\)/0x\1, /g' | sed 's/, $//')

echo "New cert fingerprint (bytes): $BYTE_ARRAY"

# Build the 4-line formatted block that client.js expects
LINE1=$(echo "$BYTE_ARRAY" | awk -F', ' '{printf "  %s, %s, %s, %s, %s, %s, %s, %s,\n",$1,$2,$3,$4,$5,$6,$7,$8}')
LINE2=$(echo "$BYTE_ARRAY" | awk -F', ' '{printf "  %s, %s, %s, %s, %s, %s, %s, %s,\n",$9,$10,$11,$12,$13,$14,$15,$16}')
LINE3=$(echo "$BYTE_ARRAY" | awk -F', ' '{printf "  %s, %s, %s, %s, %s, %s, %s, %s,\n",$17,$18,$19,$20,$21,$22,$23,$24}')
LINE4=$(echo "$BYTE_ARRAY" | awk -F', ' '{printf "  %s, %s, %s, %s, %s, %s, %s, %s\n",$25,$26,$27,$28,$29,$30,$31,$32}')

NEW_BLOCK="const CERT_HASH_BYTES = new Uint8Array([\n$LINE1\n$LINE2\n$LINE3\n$LINE4\n]);"

# Patch client.js — replace the Uint8Array block between the comment and ]);
python3 - <<PYEOF
import re, pathlib

js = pathlib.Path("static/client.js").read_text()
new_block = """const CERT_HASH_BYTES = new Uint8Array([
$LINE1
$LINE2
$LINE3
$LINE4
]);"""
js = re.sub(
    r'const CERT_HASH_BYTES = new Uint8Array\(\[[\s\S]*?\]\);',
    new_block,
    js
)
pathlib.Path("static/client.js").write_text(js)
print("Updated static/client.js with new hash.")
PYEOF

echo "Restart the QUIC server and hard-refresh the browser."
