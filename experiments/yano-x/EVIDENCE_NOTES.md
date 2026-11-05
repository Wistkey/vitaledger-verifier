# Product-evidence experiment notes

## Input

- Public test vector: GTIN `4006381333931`, record digest `c4aef3fff747fe292056bd427df7a93b466cbb108c68d282102b5469a56260ab`.
- Local document key: `vitaledger-c4aef3fff747fe29`.
- Built-in review flow: issuer proposal, approvals by two independent auditor organizations, document-head mutation, and a one-use receipt.
- Finality: three app-chain members, threshold two. This is separate from the two-auditor business rule.

## Evidence retained

`run.sh` writes doctor, quickstart, document proof, review, verification, anchor status, restart, and stop logs plus `scenario.json` under `.tools/yano-x-evidence/<instance>/`. These are local demo artifacts, not portable production proofs.

## Evaluation

- **Demonstrated:** deterministic app-chain history and inclusion proofs, multi-party approval, workflow-chain script anchoring to a local Cardano devnet, and successful verification after restart.
- **Not demonstrated:** VitaLedger record-schema validation, our issuer registry, Merkle batch format, public verification compatibility, production security, key custody, scalability, or a production connector.
- **Decision needed:** whether these workflow capabilities justify a separate integration design. Nothing here replaces the existing label-22092 anchor or TypeScript verifier.
