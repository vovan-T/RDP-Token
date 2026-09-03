#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
destination=${1:-.env}
if [ -e "$destination" ]; then
    echo "Refusing to overwrite existing file: $destination" >&2
    exit 1
fi
command -v openssl
secret=$(openssl rand -hex 32)
umask 077
set -C
sed "s/^RDP_TOKEN_SECRET=.*/RDP_TOKEN_SECRET=$secret/" .env.example > "$destination"
echo "Created $destination. Edit hostname, certificate paths and administrator certificate serial before starting."
