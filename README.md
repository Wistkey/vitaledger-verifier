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
npm run verify -- bundle.json          # from a clone
npx -p vitaledger-verifier vitaledger-verify bundle.json   # from npm, no clone needed
```

A bundle is `{ record, proof, anchor: { network, txHash, label? } }` (SPEC §6). The verifier:
1. recomputes the digest;
2. walks the proof;
3. fetches the transaction's **raw CBOR** from Koios (by default; pass `--blockfrost <id>` or set `BLOCKFROST_PROJECT_ID` to use Blockfrost), and checks those bytes hash to the transaction id;
4. compares the anchored Merkle root with the one it computed.

Exit codes: `0` valid, `1` invalid, `2` error. Pass `--json` for machine-readable output.

**No indexer trust:** add `--mithril` to also prove the transaction is on chain with a Mithril certificate, verified back to the network's genesis key (pinned in the package). It needs the optional Mithril client:

```bash
npx -p vitaledger-verifier -p @mithril-dev/mithril-client-wasm vitaledger-verify bundle.json --mithril
```

## For issuers

Brands, labs, certifiers and recall authorities publish records with `vitaledger-issuer` (keygen, check, sign, submit). See **[issuer-pack/ISSUERS.md](issuer-pack/ISSUERS.md)** and the templates in `issuer-pack/templates/`.

## Library

```ts
import { recordDigest, merkleRoot, inclusionProof, verifyBundle } from "vitaledger-verifier";
```

The package's only runtime dependency is `@noble/hashes`. The CBOR reader is built in, and all the code runs in both Node and browsers.

## Independent implementation

`python/` holds a second verifier written **from SPEC.md alone**, without reading the TypeScript source. It uses only the Python standard library. It reproduces every test vector and verifies live Preprod anchors:

```bash
python3 python/test_vectors.py
python3 python/vitaledger_verify.py python/bundle-live.json   # exit 0 = valid
```

## Develop

```bash
npm test          # unit tests, test vectors, real Preprod transaction fixture
npm run typecheck
npm run vectors   # regenerate test-vectors/v1.json
```

Licence: Apache-2.0.

## Releasing

Bump `version` in `package.json`, commit, then push a matching tag:

```bash
git tag -a v0.2.1 -m "vitaledger-verifier 0.2.1" && git push origin v0.2.1
```

`.github/workflows/release.yml` runs the tests (TypeScript and the independent Python implementation) and publishes to npm through Trusted Publishing, with provenance. No npm token is stored anywhere.
