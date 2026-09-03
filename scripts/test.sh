#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
python tests/check_rdp.py app/main.py
python tests/test_gateway.py
python tests/test_proxy.py
