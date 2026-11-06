#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
STORE_URL="${YACI_STORE_URL:-http://127.0.0.1:8080/api/v1}"
EVIDENCE="${TOOLING_EVIDENCE:-$ROOT/.tools/evidence/bloxbean-yaci.json}"
if [ -z "${JAVA_HOME:-}" ]; then export JAVA_HOME="$("$ROOT/scripts/install-jdk25.sh")"; fi
export PATH="$JAVA_HOME/bin:$("$ROOT/scripts/install-maven.sh")/bin:$PATH"

if [[ ! "$STORE_URL" =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/.*)?$ ]]; then
  printf 'YACI_STORE_URL must use loopback HTTP\n' >&2
  exit 1
fi

cleanup() {
  (cd "$ROOT/aiken/scripts" && npm run yaci:stop) || true
}
trap cleanup EXIT
(cd "$ROOT" && npm ci)
(cd "$ROOT/aiken/scripts" && npm ci && npm run yaci:up) >"$ROOT/.tools/bloxbean-yaci.log" 2>&1 &
YACI_PID=$!
trap 'kill "$YACI_PID" 2>/dev/null || true; wait "$YACI_PID" 2>/dev/null || true; cleanup' EXIT

for _ in $(seq 1 240); do
  if curl -fsS "$STORE_URL/network" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "$STORE_URL/network" >/dev/null

cd "$HERE"
mvn -q compile exec:java -Dexec.args="$STORE_URL $ROOT/test-vectors/v1.json $ROOT/.tools/bloxbean-anchor.json"
TOOLING_EVIDENCE="$EVIDENCE" "$ROOT/node_modules/.bin/tsx" verify.ts "$STORE_URL" "$ROOT/.tools/bloxbean-anchor.json"
"$ROOT/node_modules/.bin/tsx" "$ROOT/scripts/tooling-evidence.ts" "$EVIDENCE"
