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
| `subject` | yes | `{ "kind": "gtin", "value": <GTIN-8/12/13/14 with valid GS1 check digit> }` or `{ "kind": "vl_product", "value": <lowercase UUID> }` |
| `issuer` | yes | `vl:issuer:<slug>`, where the slug is 1–48 characters of `a-z 0-9 -`, not starting or ending with `-` |
| `claim` | yes | An object with `type` ∈ `allergen_declaration`, `certification`, `lab_result`, `label_snapshot`, `recall_notice`. The other members depend on the claim type and are free-form JSON |
| `sourceDigest` | no | 64 lowercase hex characters: the SHA-256 of a source document, such as a lab report PDF |
| `issuedAt` | yes | UTC timestamp with second precision: `YYYY-MM-DDTHH:MM:SSZ` |
| `prev` | see §7 | The record digest of the record this one updates or revokes |

The machine-readable form is `schema/record.v1.json` (JSON Schema 2020-12). The GS1 check-digit rule and the `prev` rules cannot be expressed in JSON Schema, so only the reference validator (`validateRecord`) checks them.

Numbers SHOULD be integers or decimals that round-trip through IEEE 754 double precision. Put units in the field name, for example `valueMgPerKg`.

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

To verify it, use the algorithm in RFC 9162 §2.1.3.2 with the leaf hash as the starting hash. The proof MUST be rejected if it has more or fewer path elements than the tree size implies.

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
| `i` | text | yes | The issuer registry that resolves the batch's `issuer` ids: `vl:registry:<name>` |
| `p` | text (64) | no | Transaction hash of the previous batch from the same registry. Chaining batches lets a verifier notice if one is missing |

Every text value MUST fit Cardano's 64-byte metadata string limit. Verifiers MUST ignore keys they don't recognise (for forward compatibility) and MUST reject any `v` or `s` they don't support.

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
`anchor.label` is optional and defaults to 22092.

A verifier MUST perform all of these steps, and the record is **valid** only if every one passes:

1. **Record format.** The record meets §3.
2. **Digest.** Compute `recordDigest` as in §4.2.
3. **Proof.** Compute the root from the digest and the proof, as in §4.4.
4. **Transaction bytes.** Get the transaction's raw CBOR from any source, such as Koios `/tx_cbor`, Blockfrost `/txs/{hash}/cbor`, or your own node. Then:
   a. check that `blake2b-256(transaction body bytes)` equals `anchor.txHash`;
   b. check that the body's auxiliary-data hash (field 7) equals `blake2b-256(auxiliary data bytes)`.

   The metadata MUST be read from these bytes. It MUST NOT be read from an indexer's JSON rendering, which can reorder keys or change encodings.
5. **Validity.** The transaction's `is_valid` flag is not `false`.
6. **Anchor.** Decode the metadatum at the label as in §5.2.
7. **Root.** The anchored `r` equals the root from step 3.
8. **Size.** The anchored `n` equals `proof.treeSize`.

The source can be any relay, including VitaLedger's own API. Browsers need a relay because public indexers such as Koios don't send CORS headers. Step 4 means a relay can't forge or change an anchor: it can only return the real transaction bytes or fail. The block time the source reports is shown as the time the record was anchored. The verifier checks the bytes itself (step 4). It still relies on the source for the fact that the transaction is in a block, and for the block time. A verifier that wants no trust in any indexer can confirm both against its own node or a Mithril-certified snapshot.

The reference CLI prints each check. Its exit codes are `0` valid, `1` invalid, `2` error (for example, the transaction was not found).

"Valid" means *this record is byte-for-byte the record that was anchored at that time.* It does **not** mean the claim is true, or that the issuer is who they say they are. Those questions are answered by the issuer registry (§8), and by the revocation status (§7).

## 7. Updates and revocation

Records are immutable. To change or withdraw one, the issuer publishes a new record:
- `record_updated`: `prev` is the digest of the record being replaced. The new record supersedes it.
- `revoked`: `prev` is the digest of the record being withdrawn. The claim should be taken as the issuer's last statement on the matter.
- `attestation_created` MUST NOT have `prev`.

The chain of `prev` links forms a record's history, and the latest anchored record is its current status. A consumer interface MUST NOT show a record as current once a later `record_updated` or `revoked` record exists for it.

## 8. Issuer registry (pilot)

In the pilot, VitaLedger keeps the issuer registry off chain (`vl:registry:vitaledger`). It maps each `vl:issuer:<slug>` to a legal name, a kind (brand, lab, certifier, recall authority) and an Ed25519 public key. Issuers sign each record digest with that key, and VitaLedger checks the signature before accepting the record into a batch.

In Phase 2, issuer identities move to verifiable credentials; see §9. A smart-contract registry is considered only if issuer membership or revocation has to be enforced on chain.

## 9. Versioning and the CIP-0170 path

- `schema` versions the record, and `v` versions the anchor format. A breaking change means a new value. Existing proofs stay valid indefinitely, because verification depends only on the bytes already on chain.
- **CIP-0170.** The anchor value at label 22092 is designed to serve directly as the application data of a CIP-0170 `ATTEST`. A later version can anchor a digest of the exact CBOR bytes of that value in the issuer's KERI key event log, and add the label-170 entry beside it in the same transaction. Label 22092 and its format would not change, so v1 verifiers keep working. (This is the approach of CIPs#1253: digest the metadatum's CBOR bytes, not a JSON rendering.)

## 10. Test vectors

`test-vectors/v1.json` gives, for three example records: the canonical string, record digest, leaf hash and inclusion proof, the batch root, and the anchor metadata. It also gives roots for batches of 1–9 digests. A conforming implementation reproduces every value exactly.

## References
- RFC 8785, JSON Canonicalization Scheme
- RFC 9162, Certificate Transparency Version 2.0, §2.1
- CIP-10, Transaction Metadata Label Registry
- CIP-0170 and CIPs#1253
- GS1 General Specifications, check digit calculation
