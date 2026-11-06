#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
INSTANCE="${YANO_INSTANCE:-vitaledger-poc}"
EVIDENCE="$ROOT/.tools/yano-x-evidence/$INSTANCE"
STARTED_AT="$(date -u +%FT%T.000Z)"
API_BASE="${VITALEDGER_API_BASE:-}"
PROOF_URL=""
RECORD_DIGEST=""
MODE="$(if [ -n "$API_BASE" ]; then printf shadow-canary; else printf local; fi)"
SHOWCASE=""
mkdir -p "$EVIDENCE"

cleanup() {
  local code=$?
  trap - EXIT
  if [ -x "$SHOWCASE/showcase.sh" ]; then
    "$SHOWCASE/showcase.sh" stop --instance "$INSTANCE" >"$EVIDENCE/stop.log" 2>&1 || true
  fi
  if [ ! -f "$EVIDENCE/evidence.json" ]; then
    jq -n \
      --arg startedAt "$STARTED_AT" --arg finishedAt "$(date -u +%FT%T.000Z)" \
      --arg mode "$MODE" --arg recordDigest "$RECORD_DIGEST" --arg proofUrl "$PROOF_URL" \
      --arg error "Yano X scenario exited before all assertions completed (exit $code)" \
      '{schema:"vitaledger.tooling-evidence.v1",tool:"Yano X",toolVersion:"0.1.0-pre6",mode:$mode,
        network:"yano-local",startedAt:$startedAt,finishedAt:$finishedAt,status:"failed",
        assertions:[{name:"scenario completed",ok:false,detail:$error}],
        source:((if $recordDigest == "" then {} else {recordDigest:$recordDigest} end) +
          (if $proofUrl == "" then {} else {proofUrl:$proofUrl} end)),error:$error}' \
      > "$EVIDENCE/evidence.json"
  fi
  exit "$code"
}
trap cleanup EXIT

if [ -z "${JAVA_HOME:-}" ]; then export JAVA_HOME="$("$ROOT/scripts/install-jdk25.sh")"; fi
export PATH="$JAVA_HOME/bin:$PATH"
for command in java python3 curl jq; do
  command -v "$command" >/dev/null || { printf 'missing required command: %s\n' "$command" >&2; exit 1; }
done
DIST="$("$HERE/setup.sh")"
SHOWCASE="$DIST/examples/showcase"

if [ -n "$API_BASE" ]; then
  API_BASE="${API_BASE%/}"
  RECORD_DIGEST="$(curl -fsS "$API_BASE/api/v1/proofs?limit=1" | jq -er '.data.records[0].recordDigest')"
  PROOF_URL="$API_BASE/api/v1/proofs/$RECORD_DIGEST"
  curl -fsS "$PROOF_URL" | jq -e --arg digest "$RECORD_DIGEST" '.data.bundle.record and .data.bundle.proof and .data.bundle.anchor.txHash and (.data.recordDigest == $digest or .data.recordDigest == null)' \
    > /dev/null
else
  RECORD_DIGEST="$(jq -er '.records[0].recordDigest' "$ROOT/test-vectors/v1.json")"
fi
SUFFIX="${RECORD_DIGEST:0:24}"
DOCUMENT_ID="vitaledger-$SUFFIX"

run_step() {
  local name="$1"
  shift
  printf '\n== %s ==\n' "$name"
  "$@" 2>&1 | tee "$EVIDENCE/$name.log"
}

run_step doctor "$SHOWCASE/showcase.sh" doctor --profile light
run_step quickstart "$SHOWCASE/showcase.sh" quickstart --profile light --instance "$INSTANCE" --nodes 3
run_step documents "$SHOWCASE/demos/submit-documents.sh" "$INSTANCE" "$DOCUMENT_ID"
run_step document-review "$SHOWCASE/showcase.sh" run document-review "$SUFFIX" --instance "$INSTANCE"
run_step anchor-document-review "$SHOWCASE/showcase.sh" anchor document-review-chain --instance "$INSTANCE"
run_step verify-before-restart "$SHOWCASE/showcase.sh" verify all --instance "$INSTANCE"

capture_statuses() {
  local phase="$1" node port
  for node in 0 1 2; do
    port=$((7070 + node))
    curl -fsS "http://127.0.0.1:$port/api/v1/app-chain/chains/document-review-chain/status" \
      > "$EVIDENCE/node-$node-$phase.json"
  done
}

for _ in $(seq 1 90); do
  status="$(curl -fsS "http://127.0.0.1:7070/api/v1/app-chain/chains/document-review-chain/status")"
  [ "$(printf '%s' "$status" | jq -r '(.anchor.anchoredCount // 0) >= 1 and (.anchor.lastAnchorTx | length == 64)')" = true ] && break
  sleep 2
done
printf '%s\n' "$status" | tee "$EVIDENCE/anchor-status.log" | jq -e '.anchor.enabled == true and .anchor.anchoredCount >= 1 and (.anchor.lastAnchorTx | length == 64)' > /dev/null
capture_statuses before
run_step restart "$SHOWCASE/showcase.sh" restart --instance "$INSTANCE"
run_step verify-after-restart "$SHOWCASE/showcase.sh" verify all --instance "$INSTANCE"
capture_statuses after

BEFORE="$(jq -s '.' "$EVIDENCE"/node-*-before.json)"
AFTER="$(jq -s '.' "$EVIDENCE"/node-*-after.json)"
MEMBERS_OK="$(printf '%s' "$BEFORE" | jq 'all(.[]; .members == 3 and .threshold == 2 and .membershipActiveMembers == 3 and .membershipActiveThreshold == 2)')"
ROOTS_OK="$(printf '%s' "$BEFORE" | jq '(map(.stateRoot) | unique | length) == 1 and (map(.tipHeight) | unique | length) == 1 and .[0].tipHeight >= 4')"
RESTART_OK="$(jq -n --argjson before "$BEFORE" --argjson after "$AFTER" '($before | map({tipHeight,stateRoot})) == ($after | map({tipHeight,stateRoot}))')"
REVIEW_OK="$(if grep -q 'approval consumed once' "$EVIDENCE/document-review.log" && grep -q '"presence": "PRESENT"' "$EVIDENCE/document-review.log"; then printf true; else printf false; fi)"
DOCUMENT_OK="$(if grep -q '"chainId": "documents-chain"' "$EVIDENCE/documents.log" && grep -q '"valueHex"' "$EVIDENCE/documents.log"; then printf true; else printf false; fi)"
ANCHOR_TX="$(jq -r '.anchor.lastAnchorTx' "$EVIDENCE/anchor-status.log")"
ANCHOR_OK="$(jq '.anchor.enabled == true and .anchor.bootstrapped == true and (.anchor.lastAnchorTx | length == 64) and .anchor.anchoredCount >= 1' "$EVIDENCE/anchor-status.log")"

jq -n \
  --arg startedAt "$STARTED_AT" --arg finishedAt "$(date -u +%FT%T.000Z)" \
  --arg mode "$MODE" --arg instance "$INSTANCE" --arg documentId "$DOCUMENT_ID" \
  --arg recordDigest "$RECORD_DIGEST" --arg proofUrl "$PROOF_URL" --arg txHash "$ANCHOR_TX" \
  --argjson members "$MEMBERS_OK" --argjson roots "$ROOTS_OK" --argjson review "$REVIEW_OK" \
  --argjson document "$DOCUMENT_OK" --argjson anchor "$ANCHOR_OK" --argjson restart "$RESTART_OK" \
  '{schema:"vitaledger.tooling-evidence.v1",tool:"Yano X",toolVersion:"0.1.0-pre6",mode:$mode,
    network:"yano-local",startedAt:$startedAt,finishedAt:$finishedAt,
    assertions:[
      {name:"three members use 2-of-3 finality",ok:$members},
      {name:"all members agree on the reviewed chain tip and root",ok:$roots},
      {name:"digest-derived document proof is present",ok:$document},
      {name:"issuer and two auditors produced a one-use review receipt",ok:$review},
      {name:"document-review-chain is anchored on the local Cardano devnet",ok:$anchor},
      {name:"tip and state root survive restart",ok:$restart}],
    status:(if ($members and $roots and $document and $review and $anchor and $restart) then "passed" else "failed" end),
    source:({recordDigest:$recordDigest} + (if $proofUrl == "" then {} else {proofUrl:$proofUrl} end)),
    transaction:{txHash:$txHash,provider:"Yano X local Cardano devnet"},
    cluster:{instance:$instance,documentId:$documentId,members:3,threshold:2,anchorScope:"document-review-chain"}}' \
  | tee "$EVIDENCE/evidence.json" "$EVIDENCE/scenario.json"
jq -e '.status == "passed"' "$EVIDENCE/evidence.json" > /dev/null
printf '\nYano X local proof of concept passed. Evidence: %s\n' "$EVIDENCE"
