# DRAFT — CIP-10 registration for metadata label 22092 (not submitted)

**Status: draft, not submitted.** Prerequisites before opening the PR against `cardano-foundation/CIPs`:
1. Make `Wistkey/vitaledger-verifier` **public**: the registry asks for documentation of the label, and `SPEC.md` is that documentation.
2. Re-check that 22092 is still free in `CIP-0010/registry.json` (it was on 2026-09-30).
3. Decide who submits it (a Wistkey GitHub account), and whether to wait for more pilot anchors than the single Preprod smoke test.

## Change to `CIP-0010/registry.json`

Insert in numeric order:

```json
  {
    "transaction_metadatum_label": 22092,
    "description": "VitaLedger - food product record anchor (Merkle root of issuer-signed records)"
  },
```

## PR title

`CIP-0010 | Add label 22092 for VitaLedger food record anchors`

## PR body

> ## Summary
>
> This registers transaction metadata label `22092` ("VL" in ASCII) for VitaLedger:
>
> - `22092`: VitaLedger - food product record anchor (Merkle root of issuer-signed records)
>
> The label is used in a pilot on Preprod during the Cardano Accelerator Programme (Nov 2026 – Feb 2027). The format is specified in full in an open repository with a reference verifier, an independent clean-room implementation, and test vectors.
>
> ## Background
>
> VitaLedger lets anyone check that a food-product record (an allergen declaration, lab result, certification, label snapshot or recall notice) is exactly what the brand, lab or authority published, and when. Issuers sign records off chain with Ed25519. VitaLedger batches the SHA-256 digests of the records' RFC 8785 canonical JSON into an RFC 9162 Merkle tree, and anchors only the root, so one transaction covers a whole batch. Anyone can verify a record with no wallet or account: recompute the digest, walk the inclusion proof, then compare the root with the metadata read from the transaction's own CBOR bytes, after checking those bytes against the transaction id and auxiliary-data hash.
>
> Records describe products only. No personal data is ever anchored or stored in records.
>
> **Relation to existing labels.** We considered label 1904 (supply-chain proof of origin, as used by the Georgian wine resolver). 1904 carries per-producer signatures on chain. VitaLedger anchors only a Merkle root: issuer signatures stay off chain under an issuer registry, which keeps one constant-size transaction per batch, whatever the number of records. The format is designed to be wrapped by a CIP-0170 `ATTEST` later: the value at 22092 can serve as its application data.
>
> ## Record structure
>
> ```
> {
>   22092: {
>     "v": 1,                          // anchor format version
>     "s": "vitaledger.record.v1",     // schema of every record in the batch
>     "r": "<hex 64>",                 // Merkle root (RFC 9162) of record digests
>     "n": <uint>,                     // number of records in the batch
>     "i": "vl:registry:vitaledger",   // issuer registry resolving issuer ids
>     "p": "<hex 64>"                  // optional: tx hash of the previous batch
>   }
> }
> ```
>
> All text values fit the 64-byte metadata string limit. Full specification: https://github.com/Wistkey/vitaledger-verifier/blob/main/SPEC.md
>
> ## Worked example (Preprod)
>
> Transaction `7111eecc3510eb132bc4ec1794514a58f9ca812b2995a23a02bc7bcc7a6a50ff` anchors one record:
> - the record digest is `fe1f83fdd5e6f7ff0a8f0aa0a499f91ff1198ecb4f037a725198257d10f656b9`;
> - with one leaf, the root is `SHA-256(0x00 ‖ digest)` = `1e459e042a4148859142913ff4b91a62830c8695959a6a467e6564d3d0f30e28`;
> - the transaction's metadata at label 22092 carries that value as `r`.
>
> To check it independently:
> ```
> npx -p vitaledger-verifier vitaledger-verify bundle.json   # TypeScript reference
> python3 python/vitaledger_verify.py bundle.json   # independent implementation
> ```
>
> ## Links
> - Specification and verifier: https://github.com/Wistkey/vitaledger-verifier
> - Test vectors: `test-vectors/v1.json`
