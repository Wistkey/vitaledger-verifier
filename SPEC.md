# VitaLedger Record Anchoring — Specification v1

Status: **Draft for pilot (Cardano Preprod testnet)**. Nothing in this document is live on mainnet.

This document explains how VitaLedger turns an issuer's statement about a food product into a fingerprint, anchors batches of fingerprints on Cardano, and how anyone can check later that a record is unchanged. Verification needs no wallet, account or VitaLedger server. The reference implementation is in `src/`, and `test-vectors/v1.json` holds values every implementation must reproduce.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

1. An **issuer** (a brand, lab, certifier or recall authority) publishes a **record** about a product.
2. VitaLedger computes the record's **digest**, the SHA-256 of its canonical JSON.
3. It collects the digests into a **batch** and builds a **Merkle tree**.
4. It writes the tree's root in the **metadata** of one Cardano transaction.
5. Each record gets a **proof bundle**: the record, its inclusion proof, and the transaction hash.
6. A verifier recomputes the digest, walks the proof to a root, reads the transaction from any Cardano indexer, checks the bytes itself, and compares the roots.

Only digests, counts, version tags and identifiers go on chain. The records stay off chain.

## 2. Privacy rule

Records describe **products**, never people. A record MUST NOT contain data about a child, parent, user or any other natural person. That includes data in encrypted, hashed or pseudonymised form. Issuers and implementations MUST reject such records. The v1 schema rejects unknown top-level fields. The `claim` object is issuer-defined, so the issuer registry (§8) is responsible for keeping personal data out of it.

## 3. Record (`vitaledger.record.v1`)

A record is a JSON object with exactly these members:

| Field | Required | Rule |
|---|---|---|
| `schema` | yes | The string `"vitaledger.record.v1"` |
| `eventType` | yes | `attestation_created`, `record_updated` or `revoked` (§7) |
| `subject` | yes | Exactly `{ "kind": "gtin", "value": <GTIN-8/12/13/14 digits with valid GS1 check digit> }`, `{ "kind": "vl_product", "value": <lowercase UUID> }`, or (spec 1.1) `{ "kind": "official_notice", "value": "<authority>:<notice id>" }` where `<authority>` matches `[a-z][a-z0-9-]{1,15}` and `<notice id>` matches `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` (for example `uk-fsa:FSA-AA-45-2026`); no other members |
| `issuer` | yes | `vl:issuer:<slug>`, where the slug is 1–48 characters of `a-z 0-9 -`, not starting or ending with `-` |
| `claim` | yes | An object with `type` ∈ `allergen_declaration`, `certification`, `lab_result`, `label_snapshot`, `recall_notice`. The other members depend on the claim type and are free-form JSON |
| `sourceDigest` | no | 64 lowercase hex characters: the SHA-256 of a source document, such as a lab report PDF |
| `issuedAt` | yes | UTC timestamp with second precision: `YYYY-MM-DDTHH:MM:SSZ`, naming a real calendar date (`2026-02-30` is invalid); no fractional seconds or offsets |
| `prev` | see §7 | 64 lowercase hex characters: the record digest of the record this one updates or revokes. **Required** for `record_updated` and `revoked`; **forbidden** for `attestation_created` |

The machine-readable form is `schema/record.v1.json` (JSON Schema 2020-12); it expresses everything above, including the `prev` rule, **except** the GS1 check digit and calendar validity of `issuedAt`, which validators MUST check in code. `test-vectors/v1.json` → `invalidRecords` lists records every implementation must reject.

Records MUST be I-JSON (RFC 7493): no duplicate member names and no unpaired surrogates. Verifiers SHOULD reject such input; JSON parsers that silently keep the last duplicate MUST NOT be relied on to detect it.

Every number is an IEEE 754 double, as in JavaScript: an integer above 2^53 is canonicalised as its nearest double (`9007199254740993` → `9007199254740992`), so issuers SHOULD keep numbers within ±2^53 and send large identifiers as strings. Non-finite values are not JSON and are invalid. Put units in the field name, for example `valueMgPerKg`.

### 3.1 Claim conventions (non-normative)

`claim` is free-form apart from `type`. These conventions keep records from different issuers comparable, and the VitaBaby app relies on them for display:

| `claim.type` | Recommended members |
|---|---|
| `allergen_declaration` | `contains`, `mayContain`: arrays of allergen tokens; `basis` |
| `lab_result` | `analyte`, `value<Unit>`, `limit<Unit>`, `result` ∈ `below_limit` / `above_limit` / `not_detected`, `method`, `accreditation`, `batchOrLot`, `testedOn` (YYYY-MM-DD) |
| `certification` | `scheme`, `certificateId`, `certifiedBy`, `validFrom`, `validUntil` |
| `label_snapshot` | `ingredientsText`, `allergens`, `per100` `{unit: "g"\|"ml", energyKcal, fatG, carbsG, sugarsG, proteinG, saltG}`, `labelVersion` |
| `recall_notice` | `reason`, `allergens`, `lots`, `bestBefore`, `action`, `officialNoticeUrl` |

**Relayed official notices (spec 1.1).** A registry may relay a public authority's recall or allergy alert as a `recall_notice` whose subject is `official_notice`. The issuer is the relay (for example `vl:issuer:vitaledger-relay`), never the authority: the record attests *what the authority published and when it was relayed*, not that any particular product is affected. Recommended members: `authority` (name), `title`, `reason`, `allergens`, `products` (array of `{ name, packSize?, batchCodes?, bestBefore? }` as the authority describes them), `action`, `officialNoticeUrl`, `officialPublishedAt`, `officialModifiedAt`; and `sourceDigest` = SHA-256 of the canonical form (§4.1) of the authority's machine-readable notice exactly as fetched. When the authority changes a notice, the relay publishes `record_updated` with `prev`. Consumers must not present a relayed notice as a verified statement about a specific product: notices identify products by name and batch, not by GTIN.

Allergen tokens: `dairy`, `egg`, `peanut`, `tree_nut`, `soy`, `gluten`, `fish`, `shellfish`, `sesame`, `celery`, `mustard`, `sulphites`, `lupin`, `molluscs`. Templates are in `issuer-pack/templates/`.

## 4. Digest and Merkle tree

### 4.1 Canonical form
The canonical form of a record is its **RFC 8785 (JCS)** serialisation, encoded as UTF-8:
- no whitespace;
- object members sorted by the UTF-16 code units of their names;
- strings escaped as RFC 8785 §3.2.2.2 requires;
- numbers written in ECMAScript's shortest round-trip form;
- members whose value is `undefined` are omitted.

### 4.2 Record digest
`recordDigest = lowercase-hex( SHA-256( canonical bytes ) )`

This equals `sha256sum` of a file that holds the canonical JSON with no trailing newline.

### 4.3 Merkle tree
The tree follows **RFC 9162 §2.1**. It is built over the ordered list of record digests in a batch, where `D` is the list and `n = |D|` with `n ≥ 1`:
- `leaf(d) = SHA-256(0x00 ‖ bytes(d))`, where `bytes(d)` is the 32 raw bytes of the digest;
- `MTH([d]) = leaf(d)`;
- for `n > 1`, let `k` be the largest power of two with `k < n`. Then `MTH(D) = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))`.

The different prefixes for leaves (`0x00`) and nodes (`0x01`) stop an interior node from being passed off as a leaf.

### 4.4 Inclusion proof
An inclusion proof has three fields:
- `leafIndex`: the zero-based position of the record in the batch;
- `treeSize`: `n`;
- `path`: the RFC 9162 audit path, as 64-character lowercase hex hashes ordered from the leaf upwards.

To verify it, reject the proof unless `treeSize ≥ 1` and `0 ≤ leafIndex < treeSize`, then run the loop of RFC 9162 §2.1.3.2 starting from the leaf hash. The value it ends with is the proof's root, which step 7 of §6 compares with the anchored `r`. The proof MUST be rejected if it has more or fewer path elements than the tree size implies.

**Hex everywhere** (digests, `path`, `r`, `p`, `txHash`) is lowercase. Verifiers MUST reject uppercase or mixed case rather than normalise it.

## 5. On-chain anchor

### 5.1 Label
The anchor goes in transaction metadata under label **22092** ("VL" in ASCII). This label is **provisional**: when checked on 2026-09-30 it was not in the CIP-10 registry, and it will be registered before any mainnet use. Implementations SHOULD make the label configurable.

### 5.2 Value (anchor format v1)
The value is a metadata map with text keys:

| Key | Type | Required | Meaning |
|---|---|---|---|
| `v` | int | yes | Anchor format version, `1` |
| `s` | text | yes | Record schema of every record in the batch, `"vitaledger.record.v1"` |
| `r` | text (64) | yes | Merkle root, lowercase hex |
| `n` | int | yes | Number of records in the batch, `≥ 1` |
| `i` | text | yes | The issuer registry that resolves the batch's `issuer` ids: `vl:registry:<name>`, where `<name>` is 1–52 characters of `a-z 0-9 -` |
| `p` | text (64) | no | Transaction hash of the previous batch from the same registry. Chaining batches lets a verifier notice if one is missing |

Every text value MUST fit Cardano's 64-byte metadata string limit. Keys are text; `v` and `n` are integers; the others are text. Verifiers MUST reject a value of the wrong type, MUST ignore keys they don't recognise (for forward compatibility), and MUST reject any `v` or `s` they don't support.

A batch holds records of exactly one schema. A transaction carries at most one VitaLedger anchor.

### 5.3 Example
```json
{ "22092": { "v": 1, "s": "vitaledger.record.v1", "r": "1010a2ad…ff2b", "n": 3, "i": "vl:registry:vitaledger" } }
```

## 6. Verification

A **proof bundle** is JSON:
```json
{
  "record":  { …record… },
  "proof":   { "leafIndex": 1, "treeSize": 3, "path": ["…", "…"] },
  "anchor":  { "network": "preprod", "txHash": "…", "label": 22092 }
}
```
`anchor.label` is optional and defaults to 22092. `anchor.network` is `preprod`, `preview` or `mainnet`; the reference verifier fetches from the matching public Koios endpoint (`https://{preprod,preview}.koios.rest/api/v1`, `https://api.koios.rest/api/v1`) unless told otherwise.

A verifier MUST perform all of these steps, and the record is **valid** only if every one passes:

1. **Record format.** The record meets §3.
2. **Digest.** Compute `recordDigest` as in §4.2.
3. **Proof.** Compute the root from the digest and the proof, as in §4.4.
4. **Transaction bytes.** Get the transaction's raw CBOR from any source: Koios `POST /tx_cbor` with `{"_tx_hashes":[hash]}` (answers `[{tx_hash, cbor, tx_timestamp, block_height, …}]`, or `[]` if unknown), Blockfrost `GET /txs/{hash}/cbor`, or your own node. A transaction is the CBOR array `[body, witnesses, is_valid, auxiliary_data]` (Alonzo and later) or `[body, witnesses, auxiliary_data]` (earlier eras, where `is_valid` counts as true). Then:
   a. check that `blake2b-256(transaction body bytes)` equals `anchor.txHash`;
   b. check that the body's auxiliary-data hash (field 7) equals `blake2b-256(auxiliary data bytes)`.

   If `auxiliary_data` is null, or the body has no field 7, the transaction carries no anchor and the check fails. The metadata MUST be read from these bytes. It MUST NOT be read from an indexer's JSON rendering, which can reorder keys or change encodings.
5. **Validity.** The transaction's `is_valid` flag is not `false`.
6. **Anchor.** Take the metadata map out of `auxiliary_data`, which comes in three era encodings: a plain map (Shelley), `[metadata, scripts]` (Allegra/Mary), or tag 259 wrapping `{0: metadata, …}` (Alonzo and later). Decode the metadatum at the label as in §5.2. Its `s` MUST equal the record's `schema`.
7. **Root.** The anchored `r` equals the root from step 3.
8. **Size.** The anchored `n` equals `proof.treeSize`.

The source can be any relay, including VitaLedger's own API. Browsers need a relay because public indexers such as Koios don't send CORS headers. Step 4 means a relay can't forge or change an anchor: it can only return the real transaction bytes or fail. The block time the source reports is shown as the time the record was anchored. The verifier checks the bytes itself (step 4). It still relies on the source for the fact that the transaction is in a block, and for the block time. A verifier that wants no trust in any indexer can confirm inclusion with **Mithril** instead: fetch the transaction's proof from the network's Mithril aggregator (`/proof/cardano-transaction`), verify the certificate chain back to the network's genesis verification key, and check that the proof matches the certificate's signed message. The reference CLI does this with `--mithril`, using the official Mithril client and genesis keys pinned in `src/mithril.ts`. Mithril certifies the transaction set every few blocks, so a very recent transaction may not be certified yet; that is "not yet checkable" (exit `2`), not invalid. The block time still comes from the indexer.

The reference CLI prints each check. Exit codes:

| Code | Meaning | Examples |
|---|---|---|
| `0` | Valid | Every step passed |
| `1` | Invalid: the evidence doesn't hold | Bad record, bad proof, bytes that don't hash to `txHash`, no anchor at the label, root or size mismatch, `is_valid = false` |
| `2` | Couldn't check | Transaction not found, network failure, unreadable bundle file |

Bytes that don't hash to the requested transaction count as invalid (`1`), because the verifier can't tell a faulty source from a forged one; retry with another source before concluding.

"Valid" means *this record is byte-for-byte the record that was anchored at that time.* It does **not** mean the claim is true, or that the issuer is who they say they are. Those questions are answered by the issuer registry (§8), and by the revocation status (§7).

## 7. Updates and revocation

Records are immutable. To change or withdraw one, the issuer publishes a new record:
- `record_updated`: `prev` is the digest of the record being replaced. The new record supersedes it.
- `revoked`: `prev` is the digest of the record being withdrawn. The claim should be taken as the issuer's last statement on the matter.
- `attestation_created` MUST NOT have `prev`.

The chain of `prev` links forms a record's history, and the latest anchored record is its current status. A consumer interface MUST NOT show a record as current once a later `record_updated` or `revoked` record exists for it.

## 8. Issuer registry (pilot)

In the pilot, VitaLedger keeps the issuer registry off chain (`vl:registry:vitaledger`). It maps each `vl:issuer:<slug>` to a legal name, a kind (brand, lab, certifier, recall authority) and an Ed25519 public key. Issuers sign each record with that key, and VitaLedger checks the signature before accepting the record into a batch. The signed message is the UTF-8 encoding of the string `vitaledger.record.v1:` followed by the lowercase hex record digest; the signature is the 64-byte Ed25519 signature as 128 lowercase hex characters. The domain prefix keeps a record signature from being replayed as any other kind of signed message. `vitaledger-issuer` (`src/issuer-cli.ts`) creates keys and signs records.

In Phase 2, issuer identities move to verifiable credentials; see §9. A smart-contract registry is considered only if issuer membership or revocation has to be enforced on chain.

## 9. Versioning and the CIP-0170 path

- `schema` versions the record, and `v` versions the anchor format. A breaking change means a new value. Existing proofs stay valid indefinitely, because verification depends only on the bytes already on chain.
- **Additive extensions within v1.** A new subject kind or claim type may be added to `vitaledger.record.v1` when every record valid before stays valid with the same digest; this is a spec revision (1.1, 1.2, …), not a new schema. A verifier that meets a subject kind or claim type it doesn't know must report the record as **unsupported** (upgrade the verifier), not as tampered. Verifiers before 0.5.0 predate this rule and report such records as invalid record format.
- **Spec revisions.** 1.0: initial. 1.1 (October 2026): subject kind `official_notice` and the relayed-notice convention in §3.1; test vectors gain `extensionRecords` (existing vectors unchanged).
- **CIP-0170.** The anchor value at label 22092 is designed to serve directly as the application data of a CIP-0170 `ATTEST`. A later version can anchor a digest of the exact CBOR bytes of that value in the issuer's KERI key event log, and add the label-170 entry beside it in the same transaction. Label 22092 and its format would not change, so v1 verifiers keep working. (This is the approach of CIPs#1253: digest the metadatum's CBOR bytes, not a JSON rendering.)

## 10. Test vectors

`test-vectors/v1.json` gives:
- `records`: three example records with canonical string, record digest, leaf hash and inclusion proof, plus the batch root and anchor metadata;
- `edgeRecords` and `chainedBatch`: an update with `prev`, a `vl_product` subject, ECMAScript number edge cases, non-ASCII strings and keys that sort by UTF-16 code units, and an anchor that carries `p`;
- `invalidRecords`: records that MUST be rejected, each with the reason;
- `merkleSizes`: roots for batches of 1–9 digests.

A conforming implementation reproduces every value exactly. An independent, clean-room Python implementation written from this document alone (`python/`) passes all of them.

## References
- RFC 8785, JSON Canonicalization Scheme
- RFC 9162, Certificate Transparency Version 2.0, §2.1
- CIP-10, Transaction Metadata Label Registry
- CIP-0170 and CIPs#1253
- GS1 General Specifications, check digit calculation
