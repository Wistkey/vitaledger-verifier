#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
if [ -z "${JAVA_HOME:-}" ]; then export JAVA_HOME="$("$ROOT/scripts/install-jdk25.sh")"; fi
export PATH="$JAVA_HOME/bin:$PATH"
DIST="$("$HERE/setup.sh")"
SHOWCASE="$DIST/examples/showcase"
INSTANCE="${YANO_INSTANCE:-vitaledger-poc}"
EVIDENCE="$ROOT/.tools/yano-x-evidence/$INSTANCE"
RECORD_DIGEST="$(jq -er '.records[0].recordDigest' "$ROOT/test-vectors/v1.json")"
DOCUMENT_ID="vitaledger-${RECORD_DIGEST:0:16}"
mkdir -p "$EVIDENCE"

for command in java python3 curl jq; do
  command -v "$command" >/dev/null || { printf 'missing required command: %s\n' "$command" >&2; exit 1; }
done

cleanup() {
  "$SHOWCASE/showcase.sh" stop --instance "$INSTANCE" >"$EVIDENCE/stop.log" 2>&1 || true
}
trap cleanup EXIT

run_step() {
  local name="$1"
  shift
  printf '\n== %s ==\n' "$name"
  "$@" 2>&1 | tee "$EVIDENCE/$name.log"
}

run_step doctor "$SHOWCASE/showcase.sh" doctor --profile light
run_step quickstart "$SHOWCASE/showcase.sh" quickstart --profile light --instance "$INSTANCE" --nodes 3
run_step documents "$SHOWCASE/demos/submit-documents.sh" "$INSTANCE" "$DOCUMENT_ID"
run_step document-review "$SHOWCASE/showcase.sh" run document-review --instance "$INSTANCE"
run_step verify-before-restart "$SHOWCASE/showcase.sh" verify all --instance "$INSTANCE"
run_step anchor-status curl -fsS "http://127.0.0.1:7070/api/v1/app-chain/chains/workflow-chain/status"
run_step restart "$SHOWCASE/showcase.sh" restart --instance "$INSTANCE"
run_step verify-after-restart "$SHOWCASE/showcase.sh" verify all --instance "$INSTANCE"

jq -n \
  --arg instance "$INSTANCE" \
  --arg documentId "$DOCUMENT_ID" \
  --arg recordDigest "$RECORD_DIGEST" \
  --arg version "v0.1.0-pre4" \
  '{tool:"Yano X",version:$version,instance:$instance,documentId:$documentId,recordDigest:$recordDigest,anchorScope:"workflow-chain",network:"local devnet",status:"local proof of concept"}' \
  | tee "$EVIDENCE/scenario.json"
printf '\nYano X local proof of concept passed. Evidence: %s\n' "$EVIDENCE"
