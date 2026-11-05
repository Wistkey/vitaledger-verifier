# Yano X local proof of concept

**Experimental only: Yano X v0.1.0-pre4 is pre-release. This is not a VitaLedger production integration and is not mandatory CI.**

The experiment uses the unmodified Yano X light showcase to check whether its app-chain model is useful for future product-evidence workflows. It runs three local members with 2-of-3 finality, adds a document-trail key derived from the first public VitaLedger test vector, executes the stock issuer/two-auditor document review, checks all scenarios, restarts, and checks them again. All data and evidence stay under the gitignored `.tools/` directory.

```sh
experiments/yano-x/run.sh
# With the cluster running:
experiments/yano-x/verify.sh
```

Requirements are Python 3, `curl`, `jq`, and `unzip`. The scripts install the pinned, checksum-verified JDK 25 and Yano X JVM distribution locally. Use a fresh instance for a new run (`YANO_INSTANCE=vitaledger-poc-2 experiments/yano-x/run.sh`). `stop` preserves state; no reset is performed.

The quickstart's script anchoring targets **`workflow-chain` on Yano X's local Cardano devnet**. The separate `document-review-chain` and `documents-chain` entries are app-chain proofs; the experiment does **not** claim that either is independently L1-anchored. No Preprod or mainnet options, credentials, or transactions are used. See [EVIDENCE_NOTES.md](EVIDENCE_NOTES.md) for the evaluation boundary.
