# Yano X local proof of concept

**Experimental only: Yano X v0.1.0-pre6 is pre-release. This is not a VitaLedger production integration and is not mandatory CI.**

The experiment uses the unmodified Yano X light showcase to check whether its app-chain model is useful for future product-evidence workflows. It runs three local members with 2-of-3 finality, binds one VitaLedger digest to the document trail and issuer/two-auditor document review, anchors `document-review-chain` to Yano's local Cardano devnet, then checks convergence and persistence across restart. All data and evidence stay under the gitignored `.tools/` directory.

```sh
experiments/yano-x/run.sh
# With the cluster running:
experiments/yano-x/verify.sh
```

Requirements are Python 3, `curl`, `jq`, and `unzip`. The scripts install the pinned, checksum-verified JDK 25 and Yano X JVM distribution locally. Use a fresh instance for a new run (`YANO_INSTANCE=vitaledger-poc-2 experiments/yano-x/run.sh`). Set `VITALEDGER_API_BASE=https://api.vitababy.ai` to shadow a public anchored proof instead of the bundled vector. `stop` preserves state; no reset is performed.

The quickstart still anchors `workflow-chain`; this experiment additionally bootstraps and checks **`document-review-chain` on Yano X's local Cardano devnet**. `documents-chain` remains a separate app-chain proof. No Preprod or mainnet options, credentials, or transactions are used. See [EVIDENCE_NOTES.md](EVIDENCE_NOTES.md) for the evaluation boundary.
