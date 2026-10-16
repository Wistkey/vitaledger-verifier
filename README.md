# vitaledger-verifier

[![Public verification](https://github.com/Wistkey/vitaledger-verifier/actions/workflows/public-verification.yml/badge.svg)](https://github.com/Wistkey/vitaledger-verifier/actions/workflows/public-verification.yml)

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

**Issuer on chain:** add `--registry` (it works with `--all` too, checking every record and comparing the API's issuer keys with the registry) to look up the record's issuer in the on-chain issuer registry, an Aiken Plutus V3 contract (see [`aiken/`](aiken/README.md)). The entry is decoded from raw transaction bytes, like the anchor. When the bundle carries `issuerSignature`, the signature is checked against the registered key. With `--mithril`, the entry's transaction is certified too. The result is informational and never changes VALID or INVALID.

**Operator attestation (CIP-0170):** when an anchor transaction also carries a label-170 `ATTEST`, `--keri` checks it, using the operator log pinned for the network; `--kel <oobi url>` overrides it. It verifies VitaLedger's KERI key event log from inception and confirms that the event named in the ATTEST anchors the Blake3 digest of the exact label-22092 bytes (SPEC §9). This check is informational.

## Reproduce the whole pilot

One command re-verifies **every** record VitaLedger has anchored, from public data, so anyone outside the team can check our claims in a few minutes (Node.js 20+):

```bash
npx -p vitaledger-verifier@0.5 -p @mithril-dev/mithril-client-wasm vitaledger-verify --all https://api.vitababy.ai --mithril
```

It lists the anchored records (`GET /api/v1/proofs`), fetches each record and its proof, checks that the record really hashes to the listed digest, and verifies it against the transaction bytes fetched from Koios (or Blockfrost), exactly like a single bundle. Each transaction is fetched once per batch. With `--mithril`, block inclusion is also proven from Cardano's own certificates, once per transaction; anchors from the last few hours may show as "not certified yet". The API is trusted for nothing: a changed or swapped record is reported invalid. Output ends with a summary such as `6 records in 3 transactions …: 6 valid, 0 invalid.`

**Is anything missing?** Add `--complete` to also find VitaLedger's anchors **from the chain**: every label-22092 transaction paid from the operator's anchor address, which is pinned in the package, read from its own bytes. Batches name the previous one (`p`), so they form one chain. Every batch on it must be listed by the API with all its records, and anything off the chain (such as a pre-launch test anchor) is reported but not counted. The indexer is trusted to return the address's full transaction list, since no chain proof can show absence. An incomplete listing exits `1`.

Exit codes: `0` all valid, `1` at least one record invalid, `2` some records couldn't be checked (network) or use a newer format than your verifier (SPEC §9: shown as "newer format; upgrade", never as tampering).

Spec 1.1 (verifier 0.5.0) adds relayed official notices: `recall_notice` records whose subject is `{ "kind": "official_notice", "value": "uk-fsa:FSA-AA-45-2026" }` (SPEC §3, §3.1). Verifiers before 0.5.0 report those as invalid record format; upgrade. Add `--json` for the full report.

**Every day, in public.** The [public-verification](https://github.com/Wistkey/vitaledger-verifier/actions/workflows/public-verification.yml) workflow runs this with the published package and `--complete --registry --keri --mithril`. It checks four things:
- every record, against the chain bytes and Mithril;
- that the API lists every batch;
- every issuer signature, against the on-chain registry, along with whether the API's issuer keys match it;
- each batch's CIP-0170 attestation.

A real failure opens a `public-verification` issue. The badge above shows the latest result.

**If you ran it, tell us.** An independent re-run is one of the pilot's measures: open an issue on this repository with your output (or just "ran it, all valid"), or email alfred@vitaledger.info.

## For issuers

Brands, labs, certifiers and recall authorities publish records with `vitaledger-issuer` (keygen, check, sign, submit). See **[issuer-pack/ISSUERS.md](issuer-pack/ISSUERS.md)** and the templates in `issuer-pack/templates/`.

## Library

```ts
import { recordDigest, merkleRoot, inclusionProof, verifyBundle } from "vitaledger-verifier";
```

The package's runtime dependencies are `@noble/hashes` and `@noble/curves` (Ed25519, for the registry signature check). The CBOR reader is built in, and all the code runs in both Node and browsers.

## Independent implementation

`python/` holds a second verifier written **from SPEC.md alone**, without reading the TypeScript source. It uses only the Python standard library. It reproduces every test vector and verifies live Preprod anchors:

```bash
python3 python/test_vectors.py
python3 python/vitaledger_verify.py python/bundle-live.json   # exit 0 = valid
```


**Spec 1.2 extensions in Python.** `python/vitaledger_ext.py` (standard library only, with pure-Python Ed25519 and BLAKE3) covers CIP-8 signatures, registry entries, and KERI KEL plus CIP-0170 ATTEST checks. It isn't clean-room: it has the same author as the TypeScript. It is checked against fixtures made by other tools: keripy, Lucid Evolution/CML, @noble/hashes and RFC 8032 (`python3 python/test_extensions.py`).
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
