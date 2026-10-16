#!/usr/bin/env python3
"""Check vitaledger_ext.py against fixtures produced by other tools:
BLAKE3 vectors (@noble/hashes), the RFC 8032 Ed25519 vector, KELs (keripy),
CIP-8 signatures and registry / ATTEST transactions (Lucid Evolution / CML)."""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vitaledger_ext as ext  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
passes = fails = 0


def eq(name, got, want):
    global passes, fails
    if got == want:
        passes += 1
    else:
        fails += 1
        print(f"FAIL {name}\n  got  {got}\n  want {want}")


def load(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return json.load(f)


# BLAKE3: official input pattern, many chunk counts (tree shapes).
for c in load("test-vectors/blake3.json")["cases"]:
    eq(f"blake3 len {c['len']}", ext.blake3(bytes(i % 251 for i in range(c["len"]))).hex(), c["hash"])

# Ed25519: RFC 8032 §7.1 test 1, plus rejections.
pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
eq("rfc8032 test 1", ext.ed25519_verify(pub, b"", sig), True)
eq("rfc8032 wrong message", ext.ed25519_verify(pub, b"x", sig), False)
eq("rfc8032 non-canonical S", ext.ed25519_verify(pub, b"", sig[:32] + (int.from_bytes(sig[32:], "little") + ext._L).to_bytes(32, "little")), False)

# CIP-8 from Lucid signMessage.
c8 = load("test/fixtures/cip8-lucid.json")
key = ext.vv.CBORReader(bytes.fromhex(c8["key"])).read()[0].get(-2).hex()
msg = f"vitaledger.record.v1:{c8['recordDigest']}".encode()
eq("cip8 valid", ext.verify_message_signature(key, msg, c8["signature"]), True)
eq("cip8 other digest", ext.verify_message_signature(key, msg, c8["signatureOverOtherDigest"]), False)
eq("cip8 other key", ext.verify_message_signature("11" * 32, msg, c8["signature"]), False)
flip = c8["signature"][:-2] + ("01" if c8["signature"][-2:] == "00" else "00")
eq("cip8 tampered", ext.verify_message_signature(key, msg, flip), False)

# Registry entries from emulator transactions.
rg = load("test/fixtures/registry-emulator.json")
e = ext.read_registry_entry(bytes.fromhex(rg["register"]["cborHex"]), 0, rg["policyId"])
eq("registry entry", (e["issuerId"], e["kind"], e["pubkey"], e["status"]), (rg["entry"]["issuerId"], "brand", rg["entry"]["pubkey"], "active"))
eq("registry revoked", ext.read_registry_entry(bytes.fromhex(rg["revoke"]["cborHex"]), 0, rg["policyId"])["status"], "revoked")
for case in ("fakeDatumNoToken", "referenceScript"):
    try:
        ext.read_registry_entry(bytes.fromhex(rg[case]["cborHex"]), 0, rg["policyId"])
        eq(f"registry rejects {case}", "accepted", "rejected")
    except ext.vv.VerifyError:
        eq(f"registry rejects {case}", "rejected", "rejected")
eq("registry signature", ext.verify_message_signature(e["pubkey"], f"vitaledger.record.v1:{rg['recordDigest']}".encode(), rg["signature"]), True)

# KERI: keripy KEL, then CIP-0170 ATTEST on a CML-built transaction.
k = load("test/fixtures/keri-kel.json")
eq("cip170 digest vector", ext.blake3_qb64(bytes.fromhex(k["cip170Vector"]["cborHex"])), k["cip170Vector"]["d"])
events = ext.verify_kel(k["kel"], k["aid"])
eq("kel event types", [ev["t"] for ev in events], ["icp", "ixn", "ixn", "rot", "ixn", "ixn"])
for name, bad in (("tampered seal", k["kel"].replace(k["seals"][0]["d"], k["seals"][1]["d"])), ("other aid", None)):
    try:
        ext.verify_kel(bad or k["kel"], k["aid"] if bad else "E" + "A" * 43)
        eq(f"kel rejects {name}", "accepted", "rejected")
    except ext.vv.VerifyError:
        eq(f"kel rejects {name}", "rejected", "rejected")
tx = bytes.fromhex(load("test/fixtures/cip170-tx.json")["cborHex"])
eq("metadatum bytes (CML)", ext.metadatum_bytes(tx, 22092).hex(), k["attested"]["cborHex"])
eq("attest valid", ext.verify_attest(tx, k["kel"], k["aid"])["status"], "valid")
eq("attest wrong aid", ext.verify_attest(tx, k["kel"], "E" + "A" * 43)["status"], "invalid")

print(f"{passes} passed, {fails} failed")
sys.exit(1 if fails else 0)
