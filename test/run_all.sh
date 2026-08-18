#!/usr/bin/env bash
# Cookie Vault v3 — run every automated check. Requires: node>=18, deno, python3
# with `cryptography` + `requests`. Run from the repo root: bash test/run_all.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== 1/4 Deno type-check (broker) ==="
deno check supabase/functions/cookie-broker/index.ts

echo "=== 2/4 Cross-runtime crypto interop ==="
python3 test/interop/run_interop.py

echo "=== 3/4 Broker + clients e2e (real function, mock DB) ==="
node test/e2e/run_e2e.mjs

echo "=== 4/4 Full loop (extension writer -> broker -> clients) ==="
node test/e2e/run_fullloop.mjs

echo ""
echo "ALL COOKIE VAULT v3 CHECKS PASSED ✅"
