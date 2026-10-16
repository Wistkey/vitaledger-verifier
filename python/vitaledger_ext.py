#!/usr/bin/env python3
"""Python checks for the spec 1.2 extensions (SPEC §8, §9), standard library only.

  - CIP-8 wallet signatures (COSE_Sign1, RFC 9052) and raw Ed25519 (RFC 8032)
  - on-chain issuer registry entries (aiken/, prototype)
  - CIP-0170 ATTEST: KERI key event log (KEL) verification and the
    Blake3-256 digest of the exact label-22092 metadatum bytes

Written from SPEC.md, RFC 8032, RFC 9052, the BLAKE3 specification and the
KERI/CESR specifications. Unlike vitaledger_verify.py (a clean-room
implementation of v1), this module has the same author as the TypeScript
one; its independence comes from the fixtures it is checked against, which
other tools produced: keripy (KELs), Lucid Evolution / CML (CIP-8 signatures,
registry transactions), @noble/hashes (BLAKE3 vectors). See test_extensions.py.

CLI:
  python3 vitaledger_ext.py attest <tx-hash> --kel <file-or-url> [--aid <AID>] [--network preprod]
  python3 vitaledger_ext.py cip8 <public-key-hex> <message> <signature-hex>
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vitaledger_verify as vv  # noqa: E402

# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032 §5.1.7), cofactorless, canonical S only
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _encode(P) -> bytes:
    x, y, z, _ = P
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (_P + 3) // 8, _P)
        if (x * x - x2) % _P:
            x = x * _SQRT_M1 % _P
        if (x * x - x2) % _P:
            return None
        if (x & 1) != sign:
            x = _P - x
    return (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_B = _decode(_GY.to_bytes(32, "little"))


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    A = _decode(public_key)
    R = _decode(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    return _encode(_mul(s, _B)) == _encode(_add(R, _mul(h, A)))


# ---------------------------------------------------------------------------
# BLAKE3-256 (BLAKE3 specification, §2), unkeyed hash mode
# ---------------------------------------------------------------------------

_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
_CHUNK_START, _CHUNK_END, _PARENT, _ROOT = 1, 2, 4, 8
_M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


def _g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & _M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & _M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block, counter, block_len, flags):
    m = [int.from_bytes(block[i * 4:i * 4 + 4], "little") for i in range(16)]
    s = list(cv) + _IV[:4] + [counter & _M32, (counter >> 32) & _M32, block_len, flags]
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1]); _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5]); _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9]); _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13]); _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in _PERM]
    return [s[i] ^ s[i + 8] for i in range(8)] + [s[i + 8] ^ cv[i] for i in range(8)]


class _Output:
    def __init__(self, cv, block, counter, block_len, flags):
        self.args = (cv, block, counter, block_len, flags)

    def chaining_value(self):
        return _compress(*self.args)[:8]

    def root(self) -> bytes:
        cv, block, _counter, block_len, flags = self.args
        words = _compress(cv, block, 0, block_len, flags | _ROOT)[:8]
        return b"".join(w.to_bytes(4, "little") for w in words)


def _chunk_output(chunk: bytes, index: int) -> _Output:
    cv = list(_IV)
    blocks = [chunk[i:i + 64] for i in range(0, len(chunk), 64)] or [b""]
    for j, block in enumerate(blocks):
        flags = (_CHUNK_START if j == 0 else 0) | (_CHUNK_END if j == len(blocks) - 1 else 0)
        padded = block.ljust(64, b"\0")
        if j == len(blocks) - 1:
            return _Output(cv, padded, index, len(block), flags)
        cv = _compress(cv, padded, index, 64, flags)[:8]
    raise AssertionError("unreachable")


def _parent(left, right) -> _Output:
    block = b"".join(w.to_bytes(4, "little") for w in left + right)
    return _Output(list(_IV), block, 0, 64, _PARENT)


def blake3(data: bytes) -> bytes:
    chunks = [data[i:i + 1024] for i in range(0, len(data), 1024)] or [b""]
    stack = []
    for index, chunk in enumerate(chunks[:-1]):
        cv = _chunk_output(chunk, index).chaining_value()
        total = index + 1
        while total & 1 == 0:
            cv = _parent(stack.pop(), cv).chaining_value()
            total >>= 1
        stack.append(cv)
    out = _chunk_output(chunks[-1], len(chunks) - 1)
    while stack:
        out = _parent(stack.pop(), out.chaining_value())
    return out.root()


# ---------------------------------------------------------------------------
# CESR qb64 helpers
# ---------------------------------------------------------------------------

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64int(s: str) -> int:
    n = 0
    for ch in s:
        n = n * 64 + _B64.index(ch)
    return n


def blake3_qb64(data: bytes) -> str:
    return "E" + base64.urlsafe_b64encode(b"\0" + blake3(data)).decode().rstrip("=")[1:]


def _raw1(qb64: str, code: str) -> bytes:
    if len(qb64) != 44 or qb64[0] != code:
        raise vv.VerifyError(f"expected a {code} primitive")
    return _b64d(qb64)[1:]


# ---------------------------------------------------------------------------
# CBOR spans: exact bytes of a metadatum, outputs of a transaction
# ---------------------------------------------------------------------------

def _head(rd: vv.CBORReader):
    ib = rd._take(1)[0]
    return ib >> 5, rd._arg(ib & 0x1F)


def _map_spans(data: bytes, pos: int):
    """[(key, (start, end) of value)] for the definite or indefinite map at pos."""
    rd = vv.CBORReader(data)
    rd.pos = pos
    mt, n = _head(rd)
    if mt != 5:
        raise ValueError("expected a CBOR map")
    out = []
    i = 0
    while (n is None and data[rd.pos] != 0xFF) or (n is not None and i < n):
        key, _, _ = rd.read()
        _, vs, ve = rd.read()
        out.append((key, (vs, ve)))
        i += 1
    return out


def metadatum_bytes(tx_bytes: bytes, label: int):
    """The exact CBOR bytes of the metadatum value at `label`, or None."""
    tx = vv.parse_tx(tx_bytes)
    if tx["aux"] is None:
        return None
    committed = tx["body"].get(7)
    if committed != vv.blake2b256(tx["aux_bytes"]):
        raise vv.VerifyError("auxiliary data does not match the body's hash")
    aux = tx["aux_bytes"]
    if aux[0] == 0xD9 and aux[1:3] == (259).to_bytes(2, "big"):
        inner = dict((k, span) for k, span in _map_spans(aux, 3) if isinstance(k, int))
        if 0 not in inner:
            return None
        start = inner[0][0]
    elif aux[0] >> 5 == 5:
        start = 0
    elif aux[0] >> 5 == 4:
        rd = vv.CBORReader(aux)
        _head(rd)
        start = rd.pos
    else:
        raise vv.VerifyError("unrecognised auxiliary data")
    for key, (s, e) in _map_spans(aux, start):
        if key == label:
            return aux[s:e]
    return None


# ---------------------------------------------------------------------------
# CIP-8 / raw Ed25519 issuer signatures (SPEC §8, spec 1.2)
# ---------------------------------------------------------------------------

def _bstr(b: bytes) -> bytes:
    n = len(b)
    if n < 24:
        return bytes([0x40 | n]) + b
    if n < 256:
        return bytes([0x58, n]) + b
    return bytes([0x59, n >> 8, n & 0xFF]) + b


def cip8_verify(cose_hex: str, message: bytes, public_key_hex: str) -> bool:
    try:
        v = vv.CBORReader(bytes.fromhex(cose_hex)).read()[0]
        if isinstance(v, vv.Tag) and v.tag == 18:
            v = v.value
        if not isinstance(v, list) or len(v) != 4:
            return False
        prot, unprot, payload, sig = v
        if not (isinstance(prot, bytes) and isinstance(unprot, vv.CMap) and isinstance(payload, bytes) and isinstance(sig, bytes)):
            return False
        headers = vv.CBORReader(prot).read()[0]
        if not isinstance(headers, vv.CMap) or headers.get(1) != -8 or unprot.get("hashed") is True:
            return False
        if payload != message:
            return False
        pub = bytes.fromhex(public_key_hex)
        addr = headers.get("address")
        if isinstance(addr, bytes):
            if len(addr) < 29 or (addr[0] >> 4) & 1 or addr[0] >> 4 > 7:
                return False
            if addr[1:29] != hashlib.blake2b(pub, digest_size=28).digest():
                return False
        sig_structure = b"\x84" + b"\x6aSignature1" + _bstr(prot) + b"\x40" + _bstr(payload)
        return ed25519_verify(pub, sig_structure, sig)
    except (ValueError, KeyError, IndexError):
        return False


def verify_message_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        if len(public_key_hex) != 64:
            return False
        if len(signature_hex) == 128:
            return ed25519_verify(bytes.fromhex(public_key_hex), message, bytes.fromhex(signature_hex))
        return 128 < len(signature_hex) <= 4096 and cip8_verify(signature_hex, message, public_key_hex)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# On-chain issuer registry entries (aiken/, prototype)
# ---------------------------------------------------------------------------

KINDS = ["brand", "lab", "certifier", "recall_authority", "vitaledger"]


def _constr(v):
    if isinstance(v, vv.Tag) and 121 <= v.tag <= 127 and isinstance(v.value, list):
        return v.tag - 121, v.value
    return None


def read_registry_entry(tx_bytes: bytes, index: int, policy_id: str) -> dict:
    tx = vv.parse_tx(tx_bytes)
    if not tx["is_valid"]:
        raise vv.VerifyError("transaction failed validation")
    outputs = tx["body"].get(1)
    if not isinstance(outputs, list) or index >= len(outputs) or not isinstance(outputs[index], vv.CMap):
        raise vv.VerifyError("no such output with an inline datum")
    out = outputs[index]
    addr = out.get(0)
    if not isinstance(addr, bytes) or len(addr) < 29 or not (addr[0] >> 4) & 1 or addr[1:29].hex() != policy_id:
        raise vv.VerifyError("output is not at the registry script address")
    value = out.get(1)
    tokens = []
    if isinstance(value, list) and len(value) == 2 and isinstance(value[1], vv.CMap):
        for pol, assets in value[1]:
            if isinstance(pol, bytes) and pol.hex() == policy_id and isinstance(assets, vv.CMap):
                tokens = [(name.hex(), qty) for name, qty in assets]
    if len(tokens) != 1 or tokens[0][1] != 1:
        raise vv.VerifyError("output does not hold exactly one registry token")
    opt = out.get(2)
    if not (isinstance(opt, list) and len(opt) == 2 and opt[0] == 1 and isinstance(opt[1], vv.Tag) and opt[1].tag == 24):
        raise vv.VerifyError("output has no inline datum")
    entry = _constr(vv.CBORReader(opt[1].value).read()[0])
    if not entry or entry[0] != 0 or len(entry[1]) != 5:
        raise vv.VerifyError("datum is not an IssuerEntry")
    ident, kind, pub, status, updated = entry[1]
    k, s = _constr(kind), _constr(status)
    if not (isinstance(ident, bytes) and isinstance(pub, bytes) and len(pub) == 32 and k and s and isinstance(updated, int)):
        raise vv.VerifyError("malformed IssuerEntry")
    issuer_id = ident.decode("utf-8")
    if not issuer_id.startswith("vl:issuer:") or not 10 < len(ident) <= 64:
        raise vv.VerifyError("bad issuer id")
    if tokens[0][0] != hashlib.blake2b(ident, digest_size=28).hexdigest():
        raise vv.VerifyError("token name is not bound to the issuer id")
    if k[0] >= len(KINDS) or s[0] > 1:
        raise vv.VerifyError("unknown kind or status")
    return {"issuerId": issuer_id, "kind": KINDS[k[0]], "pubkey": pub.hex(),
            "status": "active" if s[0] == 0 else "revoked", "updatedAt": updated, "txHash": tx["tx_hash"]}


# ---------------------------------------------------------------------------
# KERI KEL verification (witnessless, non-delegated; icp / ixn / rot)
# ---------------------------------------------------------------------------

def parse_kel(stream: str):
    msgs, o = [], 0
    raw_all = stream.encode()
    while o < len(stream):
        if not stream.startswith('{"v":"KERI10JSON', o):
            raise vv.VerifyError("unsupported or malformed event")
        size = int(stream[o + 16:o + 22], 16)
        raw = raw_all[o:o + size]
        event = json.loads(raw)
        o += size
        sigs, end = [], len(stream)
        while o < end and stream[o] == "-":
            code, count = stream[o:o + 2], _b64int(stream[o + 2:o + 4])
            o += 4
            if code == "-V":
                end = o + count * 4
            elif code == "-A":
                for _ in range(count):
                    sig = stream[o:o + 88]
                    if sig[0] not in "AB":
                        raise vv.VerifyError("unsupported signature code")
                    sigs.append((_B64.index(sig[1]), _b64d(sig)[2:]))
                    o += 88
            elif code == "-E":
                o += count * 60
            elif code == "-B":
                o += count * 88
            elif code == "-C":
                o += count * 132
            else:
                raise vv.VerifyError(f"unsupported attachment {code}")
        msgs.append((raw, event, sigs))
    return msgs


def _threshold(t, n):
    if not isinstance(t, str) or not t.isdigit() or t.startswith("0") or int(t) > n:
        raise vv.VerifyError("only numeric thresholds are supported")
    return int(t)


def verify_kel(stream: str, aid: str) -> list:
    events, keys, kt, nxt, nt = [], [], 0, [], 0
    for sn, (raw, e, sigs) in enumerate(parse_kel(stream)):
        if e.get("i") != aid or e.get("s") != format(sn, "x"):
            raise vv.VerifyError(f"event {sn}: wrong identifier or sequence number")
        if e["t"] not in (("icp",) if sn == 0 else ("ixn", "rot")):
            raise vv.VerifyError(f"event {sn}: unsupported type {e['t']}")
        if json.dumps(e, separators=(",", ":"), ensure_ascii=False).encode() != raw:
            raise vv.VerifyError(f"event {sn} is not compact JSON")
        blank = dict(e, d="#" * 44, **({"i": "#" * 44} if e["t"] == "icp" else {}))
        if blake3_qb64(json.dumps(blank, separators=(",", ":"), ensure_ascii=False).encode()) != e["d"]:
            raise vv.VerifyError(f"event {sn}: SAID does not match")
        if sn and e.get("p") != events[-1]["d"]:
            raise vv.VerifyError(f"event {sn} does not chain")
        if e["t"] in ("icp", "rot"):
            if e.get("bt") != "0" or e.get("b") or e.get("ba") or e.get("br"):
                raise vv.VerifyError("witnessed identifiers are not supported")
            if e["t"] == "rot":
                committed = sum(1 for k in e["k"] if blake3_qb64(k.encode()) in nxt)
                if committed < nt:
                    raise vv.VerifyError(f"rotation {sn} uses keys that were not pre-committed")
            keys, kt = e["k"], _threshold(e.get("kt"), len(e["k"]))
            nxt = e.get("n") or []
            if not nxt:
                raise vv.VerifyError("non-transferable identifiers are not supported")
            nt = _threshold(e.get("nt"), len(nxt))
        good = {i for i, sig in sigs if i < len(keys) and ed25519_verify(_raw1(keys[i], "D"), raw, sig)}
        if len(good) < kt:
            raise vv.VerifyError(f"event {sn}: {len(good)} valid signatures, needs {kt}")
        if e["t"] == "icp" and e["i"] != e["d"]:
            raise vv.VerifyError("identifier is not self-addressing")
        events.append(e)
    if not events:
        raise vv.VerifyError("empty KEL")
    return events


def verify_attest(tx_bytes: bytes, kel: str, expected_aid: str | None = None) -> dict:
    """CIP-0170 ATTEST at label 170 next to the label-22092 anchor (SPEC §9)."""
    tx = vv.parse_tx(tx_bytes)
    md = vv.metadata_from_aux(tx["aux"])
    attest = md.get(170) if isinstance(md, vv.CMap) else None
    if attest is None:
        return {"status": "absent"}
    try:
        if not isinstance(attest, vv.CMap) or attest.get("t") != "ATTEST":
            raise vv.VerifyError("label 170 is not an ATTEST")
        i, d, s = attest.get("i"), attest.get("d"), attest.get("s")
        if not all(isinstance(x, str) for x in (i, d, s)) or d[:1] != "E":
            raise vv.VerifyError("malformed ATTEST")
        data = metadatum_bytes(tx_bytes, vv.DEFAULT_LABEL)
        if data is None:
            raise vv.VerifyError("no label 22092 metadatum to attest")
        if blake3_qb64(data) != d:
            raise vv.VerifyError("ATTEST digest does not match the label 22092 bytes")
        if expected_aid and i != expected_aid:
            raise vv.VerifyError("signed by an identifier other than the expected one")
        events = verify_kel(kel, i)
        sn = int(s, 16)
        if sn >= len(events) or not any(isinstance(a, dict) and a.get("d") == d for a in events[sn].get("a", [])):
            raise vv.VerifyError(f"KEL event {s} does not anchor this digest")
        return {"status": "valid", "aid": i, "sn": sn, "digest": d}
    except (vv.VerifyError, ValueError, KeyError) as e:
        return {"status": "invalid", "reason": str(e)}


def main(argv=None) -> int:
    import argparse
    import urllib.request
    ap = argparse.ArgumentParser(description="VitaLedger spec 1.2 extension checks (Python).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("attest", help="check a CIP-0170 ATTEST in an anchor transaction")
    a.add_argument("tx_hash")
    a.add_argument("--kel", required=True, help="KEL file, or an OOBI URL")
    a.add_argument("--aid", help="expected operator AID")
    a.add_argument("--network", default="preprod")
    c = sub.add_parser("cip8", help="check an issuer signature (raw Ed25519 or CIP-8)")
    c.add_argument("public_key")
    c.add_argument("message")
    c.add_argument("signature")
    args = ap.parse_args(argv)
    if args.cmd == "cip8":
        ok = verify_message_signature(args.public_key, args.message.encode(), args.signature)
        print("VALID signature" if ok else "INVALID signature")
        return 0 if ok else 1
    kel = (urllib.request.urlopen(args.kel, timeout=30).read().decode() if args.kel.startswith("http")
           else open(args.kel, encoding="utf-8").read())
    tx = vv.fetch_tx_cbor(vv.KOIOS_BY_NETWORK[args.network], args.tx_hash)
    res = verify_attest(tx, kel, args.aid)
    print(json.dumps(res))
    return 0 if res["status"] == "valid" else 2 if res["status"] == "absent" else 1


if __name__ == "__main__":
    sys.exit(main())
