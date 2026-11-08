#!/usr/bin/env bash
# Clean-start reproduction: install, run both pipelines, build UI, serve.
set -euo pipefail
cd "$(dirname "$0")/.."
make setup
make run-all
make build
echo "Open http://127.0.0.1:8000"
make serve
