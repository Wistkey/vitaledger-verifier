#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
BLOCKFROST_URL="https://cardano-preprod.blockfrost.io/api/v0"
OUTPUT="$ROOT/.tools/bloxbean-preprod-anchor.json"
EVIDENCE="${TOOLING_EVIDENCE:-$ROOT/.tools/evidence/bloxbean-preprod.json}"

: "${BLOCKFROST_PROJECT_ID:?dedicated Preprod Blockfrost project id is required}"
: "${BLOXBEAN_CANARY_MNEMONIC:?dedicated faucet-funded Preprod canary mnemonic is required}"
if [ -z "${JAVA_HOME:-}" ]; then export JAVA_HOME="$($ROOT/scripts/install-jdk25.sh)"; fi
export PATH="$JAVA_HOME/bin:$($ROOT/scripts/install-maven.sh)/bin:$PATH"

cd "$ROOT"
npm ci
cd "$HERE"
BLOXBEAN_MODE=preprod mvn -q compile exec:java \
  -Dexec.args="$BLOCKFROST_URL $ROOT/test-vectors/v1.json $OUTPUT"
BLOXBEAN_MODE=preprod TOOLING_EVIDENCE="$EVIDENCE" \
  "$ROOT/node_modules/.bin/tsx" verify.ts "$BLOCKFROST_URL" "$OUTPUT"
"$ROOT/node_modules/.bin/tsx" "$ROOT/scripts/tooling-evidence.ts" "$EVIDENCE"
