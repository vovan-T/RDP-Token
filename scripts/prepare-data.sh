#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then
    echo 'Run with sudo: sh scripts/prepare-data.sh' >&2
    exit 1
fi
install -d -m 700 -o 10001 -g 10001 data
install -d -m 755 certs
echo 'Data directory prepared for container UID/GID 10001. No software installed.'
