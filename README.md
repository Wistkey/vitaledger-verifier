# vitaledger-verifier

Reference specification and verifier for VitaLedger food-evidence records anchored on Cardano.

> **Testnet only.** Records are anchored on Cardano **Preprod** during the pilot. Nothing here is live on mainnet.

An issuer (brand, lab, certifier or recall authority) publishes a record about a product. VitaLedger takes the record's SHA-256 digest, batches the digests into a Merkle tree, and writes the root into Cardano transaction metadata. Anyone can check later that a record is unchanged. That check needs no wallet, account or VitaLedger server.

- **[SPEC.md](SPEC.md)**: record format, canonicalisation, digest, Merkle tree, on-chain anchor, verification steps, revocation and versioning.
- **[schema/record.v1.json](schema/record.v1.json)**: JSON Schema for records.
- **[test-vectors/v1.json](test-vectors/v1.json)**: values every implementation must reproduce.

## Verify a record

```bash
npm ci
npm run verify -- bundle.json          # or: npx vitaledger-verify bundle.json
```

A bundle is `{ record, proof, anchor: { network, txHash } }` (SPEC §6). The verifier:
1. recomputes the digest;
2. walks the proof;
3. fetches the transaction's **raw CBOR** from Koios (by default; pass `--blockfrost <id>` or set `BLOCKFROST_PROJECT_ID` to use Blockfrost), and checks those bytes hash to the transaction id;
4. compares the anchored Merkle root with the one it computed.

Exit codes: `0` valid, `1` invalid, `2` error. Pass `--json` for machine-readable output.

## Library

```ts
import { recordDigest, merkleRoot, inclusionProof, verifyBundle } from "vitaledger-verifier";
```

The package's only runtime dependency is `@noble/hashes`. The CBOR reader is built in, and all the code runs in both Node and browsers.

## Develop

```bash
npm test          # unit tests, test vectors, real Preprod transaction fixture
npm run typecheck
npm run vectors   # regenerate test-vectors/v1.json
```

Licence: Apache-2.0.
