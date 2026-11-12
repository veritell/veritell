#!/usr/bin/env bash
# Makes the key pair that partners' exports are encrypted to, once:
#   tools/export/export_key.sh <private key out> <certificate out>
#   e.g. export_key.sh ~/.veritell/export-key.pem deploy/recipient.pem
# The private key (mode 0600) stays on the workstation, never in the repository.
# The certificate goes into the kit. Refuses to overwrite either file.
set -euo pipefail
KEY=${1:?usage: export_key.sh <private key out> <certificate out>}
CERT=${2:?usage: export_key.sh <private key out> <certificate out>}
OPENSSL=${OPENSSL:-openssl}
for f in "$KEY" "$CERT"; do
  [ ! -e "$f" ] || { echo "$f exists: not overwriting it (nothing was made)" >&2; exit 1; }
done
umask 077
mkdir -p "$(dirname "$KEY")" "$(dirname "$CERT")"
tmp=$(mktemp -d "$(dirname "$KEY")/.keygen.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$tmp/key.pem" 2>/dev/null
"$OPENSSL" req -x509 -new -key "$tmp/key.pem" -subj "/CN=veritell export recipient" -days 1826 -out "$tmp/cert.pem"
chmod 0600 "$tmp/key.pem"; chmod 0644 "$tmp/cert.pem"
mv "$tmp/key.pem" "$KEY"
mv "$tmp/cert.pem" "$CERT"
echo "private key: $KEY (keep it; without it exports cannot be opened)"
echo "certificate: $CERT (goes into the kit)"
