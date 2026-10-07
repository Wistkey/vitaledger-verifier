#!/usr/bin/env python3
"""Check the clean-room Python verifier against test-vectors/v1.json and the real Preprod fixture."""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vitaledger_verify as vv  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = 0
passes = 0


def eq(name, got, want):
    global fails, passes
    if got == want:
        passes += 1
    else:
        fails += 1
        print(f"FAIL {name}\n  got  {got}\n  want {want}")


def audit_path(digests, m):
    """RFC 9162 §2.1.3.1 PATH(m, D)."""
    leaves = [vv.leaf_hash(d) for d in digests]

    def path(m, D):
        n = len(D)
        if n == 1:
            return []
        k = 1
        while k * 2 < n:
            k *= 2
        if m < k:
            return path(m, D[:k]) + [vv._mth(D[k:])]
        return path(m - k, D[k:]) + [vv._mth(D[:k])]

    return [h.hex() for h in path(m, leaves)]


with open(os.path.join(ROOT, "test-vectors/v1.json"), encoding="utf-8") as f:
    V = vv.load_json(f.read())

# Records: validation, canonical, digest, leaf, proof -> root, generated path
digests = []
for i, rv in enumerate(V["records"]):
    rec = rv["record"]
    eq(f"records[{i}].valid", vv.validate_record(rec), [])
    eq(f"records[{i}].canonical", vv.jcs(rec), rv["canonical"])
    eq(f"records[{i}].recordDigest", vv.record_digest(rec), rv["recordDigest"])
    eq(f"records[{i}].sha256(canonical)", hashlib.sha256(rv["canonical"].encode()).hexdigest(), rv["recordDigest"])
    eq(f"records[{i}].leafHash", vv.leaf_hash(rv["recordDigest"]).hex(), rv["leafHash"])
    eq(f"records[{i}].proof->root", vv.root_from_proof(rv["recordDigest"], rv["proof"]), V["batch"]["merkleRoot"])
    digests.append(rv["recordDigest"])
for i, rv in enumerate(V["records"]):
    eq(f"records[{i}].proof.path (generated)", audit_path(digests, i), rv["proof"]["path"])
    eq(f"records[{i}].proof.treeSize", rv["proof"]["treeSize"], len(digests))

# Batch root + anchor metadata
eq("batch.merkleRoot", vv.merkle_root(digests), V["batch"]["merkleRoot"])
md = V["batch"]["metadata"]
eq("batch.metadata label", list(md.keys()), [str(vv.DEFAULT_LABEL)])
anchor = vv.parse_anchor(md[str(vv.DEFAULT_LABEL)])
eq("batch.metadata parsed", anchor,
   {"v": 1, "s": vv.SCHEMA_V1, "r": vv.merkle_root(digests), "n": len(digests), "i": "vl:registry:vitaledger"})

# Merkle sizes 1..9 (as given)
for ms in V["merkleSizes"]:
    ds = ms["recordDigests"]
    eq(f"merkleSizes[n={len(ds)}].root", vv.merkle_root(ds), ms["merkleRoot"])
    # every leaf's generated proof must walk back to the root
    for m in range(len(ds)):
        eq(f"merkleSizes[n={len(ds)}] proof m={m}",
           vv.root_from_proof(ds[m], {"leafIndex": m, "treeSize": len(ds), "path": audit_path(ds, m)}),
           ms["merkleRoot"])

# Edge records: canonical form, digest, proof -> chained batch root
edge_digests = []
for i, ev in enumerate(V["edgeRecords"]):
    rec = ev["record"]
    eq(f"edgeRecords[{i}].valid", vv.validate_record(rec), [])
    eq(f"edgeRecords[{i}].canonical", vv.jcs(rec), ev["canonical"])
    eq(f"edgeRecords[{i}].recordDigest", vv.record_digest(rec), ev["recordDigest"])
    eq(f"edgeRecords[{i}].proof->root", vv.root_from_proof(ev["recordDigest"], ev["proof"]), V["chainedBatch"]["merkleRoot"])
    edge_digests.append(ev["recordDigest"])
eq("chainedBatch.merkleRoot", vv.merkle_root(edge_digests), V["chainedBatch"]["merkleRoot"])
canchor = vv.parse_anchor(V["chainedBatch"]["metadata"][str(vv.DEFAULT_LABEL)])
eq("chainedBatch.p", canchor.get("p"), "7111eecc3510eb132bc4ec1794514a58f9ca812b2995a23a02bc7bcc7a6a50ff")

# Invalid records: every one must be rejected
for i, xv in enumerate(V.get("extensionRecords", [])):
    rec = xv["record"]
    eq(f"extensionRecords[{i}].valid", vv.validate_record(rec), [])
    eq(f"extensionRecords[{i}].canonical", vv.jcs(rec), xv["canonical"])
    eq(f"extensionRecords[{i}].recordDigest", vv.record_digest(rec), xv["recordDigest"])

for i, iv in enumerate(V["invalidRecords"]):
    eq(f"invalidRecords[{i}] rejected ({iv['why']})", bool(vv.validate_record(iv["record"])), True)

# Negative proof checks
d0 = V["records"][0]
for bad in ({**d0["proof"], "path": d0["proof"]["path"][:1]},
            {**d0["proof"], "path": d0["proof"]["path"] + [d0["leafHash"]]},
            {**d0["proof"], "leafIndex": 3}):
    try:
        vv.root_from_proof(d0["recordDigest"], bad)
        eq("bad proof rejected", "accepted", "rejected")
    except ValueError:
        eq("bad proof rejected", "rejected", "rejected")

# JCS number formatting spot checks (ECMAScript Number::toString)
for x, s in [(0.01, "0.01"), (1e21, "1e+21"), (1e-7, "1e-7"), (123456789012345680000.0, "123456789012345680000"),
             (-0.0, "0"), (5, "5"), (0.000001, "0.000001"), (1.5e300, "1.5e+300"), (4.35, "4.35")]:
    eq(f"es_number({x!r})", vv.es_number(x), s)

# Real Preprod transaction fixture
with open(os.path.join(ROOT, "test/fixtures/preprod-046c0ce9.json"), encoding="utf-8") as f:
    fx = json.load(f)[0]
tx = vv.parse_tx(bytes.fromhex(fx["cbor"]))
eq("fixture tx hash", tx["tx_hash"], fx["tx_hash"])
adh = tx["body"].get(7)
eq("fixture aux data hash", adh.hex(), vv.blake2b256(tx["aux_bytes"]).hex())
eq("fixture is_valid", tx["is_valid"], True)
meta = vv.metadata_from_aux(tx["aux"])
print("fixture metadata labels:", [k for k, _ in meta])

print(f"\n{passes} passed, {fails} failed")
sys.exit(1 if fails else 0)
