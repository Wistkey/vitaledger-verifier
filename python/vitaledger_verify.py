#!/usr/bin/env python3
"""Clean-room Python verifier for VitaLedger record anchoring (SPEC.md v1).

Standard library only. Implemented from SPEC.md, the JSON schema and the
test vectors, without reference to the TypeScript implementation.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from decimal import Decimal

SCHEMA_V1 = "vitaledger.record.v1"
DEFAULT_LABEL = 22092
KOIOS_BY_NETWORK = {
    "preprod": "https://preprod.koios.rest/api/v1",
    "preview": "https://preview.koios.rest/api/v1",
    "mainnet": "https://api.koios.rest/api/v1",
}


class VerifyError(Exception):
    """Operational error (exit code 2): not a judgement on the record."""


# ---------------------------------------------------------------------------
# JSON loading (reject duplicate member names, as I-JSON / RFC 8785 require)
# ---------------------------------------------------------------------------

def _no_dupes(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate member name {k!r}")
        obj[k] = v
    return obj


def load_json(text: str):
    return json.loads(text, object_pairs_hook=_no_dupes)


# ---------------------------------------------------------------------------
# §4.1 JCS (RFC 8785)
# ---------------------------------------------------------------------------

def es_number(x) -> str:
    """ECMAScript Number::toString for a finite double."""
    x = float(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite number cannot be canonicalised")
    if x == 0:
        return "0"  # also covers -0
    sign = "-" if x < 0 else ""
    x = abs(x)
    # repr() gives the shortest round-trip digits (same choice as ECMAScript).
    t = Decimal(repr(x)).as_tuple()
    digits = "".join(map(str, t.digits)).lstrip("0")
    exp = t.exponent
    stripped = digits.rstrip("0")
    exp += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = k + exp  # value = 0.digits * 10^n
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + s


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise ValueError("lone surrogate in string")
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return es_number(v)
    if isinstance(v, str):
        return jcs_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(jcs(e) for e in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise ValueError("object member names must be strings")
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(jcs_string(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise ValueError(f"cannot canonicalise {type(v).__name__}")


def canonical_bytes(record) -> bytes:
    return jcs(record).encode("utf-8")


def record_digest(record) -> str:
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


# ---------------------------------------------------------------------------
# §3 Record validation
# ---------------------------------------------------------------------------

HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
ISSUER_RE = re.compile(r"^vl:issuer:[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\Z")
GTIN_RE = re.compile(r"^(\d{8}|\d{12,14})\Z")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
ISSUED_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ\Z")
EVENT_TYPES = {"attestation_created", "record_updated", "revoked"}
CLAIM_TYPES = {"allergen_declaration", "certification", "lab_result", "label_snapshot", "recall_notice"}
def _is_calendar_date(iso):
    import datetime
    try:
        datetime.date(int(iso[0:4]), int(iso[5:7]), int(iso[8:10]))
        return True
    except ValueError:
        return False


RECORD_KEYS = {"schema", "eventType", "subject", "issuer", "claim", "sourceDigest", "issuedAt", "prev"}
REQUIRED_KEYS = {"schema", "eventType", "subject", "issuer", "claim", "issuedAt"}


def gtin_ok(s: str) -> bool:
    if not GTIN_RE.match(s):
        return False
    body, check = s[:-1], int(s[-1])
    total = 0
    for i, ch in enumerate(reversed(body)):
        total += int(ch) * (3 if i % 2 == 0 else 1)
    return (10 - total % 10) % 10 == check


def validate_record(r) -> list[str]:
    errs: list[str] = []
    if not isinstance(r, dict):
        return ["record is not an object"]
    extra = set(r) - RECORD_KEYS
    if extra:
        errs.append(f"unknown members: {sorted(extra)}")
    missing = REQUIRED_KEYS - set(r)
    if missing:
        errs.append(f"missing members: {sorted(missing)}")
    if "schema" in r and r["schema"] != SCHEMA_V1:
        errs.append("schema must be vitaledger.record.v1")
    et = r.get("eventType")
    if "eventType" in r and et not in EVENT_TYPES:
        errs.append("bad eventType")
    subj = r.get("subject")
    if "subject" in r:
        if not isinstance(subj, dict) or set(subj) != {"kind", "value"} or not isinstance(subj.get("value"), str):
            errs.append("subject must be {kind, value} with string value")
        elif subj["kind"] == "gtin":
            if not gtin_ok(subj["value"]):
                errs.append("subject.value is not a GTIN-8/12/13/14 with a valid check digit")
        elif subj["kind"] == "vl_product":
            if not UUID_RE.match(subj["value"]):
                errs.append("subject.value is not a lowercase UUID")
        else:
            errs.append("subject.kind must be gtin or vl_product")
    if "issuer" in r and not (isinstance(r["issuer"], str) and ISSUER_RE.match(r["issuer"])):
        errs.append("bad issuer")
    if "claim" in r:
        c = r["claim"]
        if not isinstance(c, dict) or c.get("type") not in CLAIM_TYPES:
            errs.append("claim must be an object with a known type")
    if "sourceDigest" in r and not (isinstance(r["sourceDigest"], str) and HEX64.match(r["sourceDigest"])):
        errs.append("bad sourceDigest")
    if "issuedAt" in r and not (isinstance(r["issuedAt"], str) and ISSUED_RE.match(r["issuedAt"]) and _is_calendar_date(r["issuedAt"])):
        errs.append("bad issuedAt")
    if "prev" in r and not (isinstance(r["prev"], str) and HEX64.match(r["prev"])):
        errs.append("bad prev")
    if et == "attestation_created" and "prev" in r:
        errs.append("attestation_created must not have prev")
    if et in ("record_updated", "revoked") and "prev" not in r:
        errs.append(f"{et} requires prev")
    if not errs:
        try:
            canonical_bytes(r)
        except ValueError as e:
            errs.append(f"not canonicalisable: {e}")
    return errs


# ---------------------------------------------------------------------------
# §4.3 / §4.4 Merkle tree (RFC 9162)
# ---------------------------------------------------------------------------

def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(digest_hex: str) -> bytes:
    return _sha(b"\x00" + bytes.fromhex(digest_hex))


def _mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return _sha(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:]))


def merkle_root(digests: list[str]) -> str:
    if not digests:
        raise ValueError("empty batch")
    return _mth([leaf_hash(d) for d in digests]).hex()


def _expected_path_len(index: int, size: int) -> int:
    # Length of the RFC 9162 audit path for leaf `index` in a tree of `size`.
    length = 0
    while size > 1:
        k = 1
        while k * 2 < size:
            k *= 2
        if index < k:
            size = k
        else:
            index -= k
            size -= k
        length += 1
    return length


def root_from_proof(digest_hex: str, proof) -> str:
    """RFC 9162 §2.1.3.2 with the leaf hash as the starting hash. Returns hex root."""
    if not isinstance(proof, dict):
        raise ValueError("proof is not an object")
    idx, size, path = proof.get("leafIndex"), proof.get("treeSize"), proof.get("path")
    for name, v in (("leafIndex", idx), ("treeSize", size)):
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{name} must be an integer")
    if size < 1 or idx < 0 or idx >= size:
        raise ValueError("leafIndex out of range for treeSize")
    if not isinstance(path, list) or not all(isinstance(p, str) and HEX64.match(p) for p in path):
        raise ValueError("path must be a list of 64-char lowercase hex strings")
    if len(path) != _expected_path_len(idx, size):
        raise ValueError(f"path has {len(path)} elements; tree size implies {_expected_path_len(idx, size)}")
    fn, sn = idx, size - 1
    r = leaf_hash(digest_hex)
    for p_hex in path:
        p = bytes.fromhex(p_hex)
        if sn == 0:
            raise ValueError("path too long")
        if fn & 1 or fn == sn:
            r = _sha(b"\x01" + p + r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _sha(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("path too short")
    return r.hex()


# ---------------------------------------------------------------------------
# Minimal CBOR reader with byte spans
# ---------------------------------------------------------------------------

class CMap(list):
    """CBOR map as an ordered list of (key, value) pairs (keys may be unhashable)."""

    def get(self, key, default=None):
        hits = [v for k, v in self if type(k) is type(key) and k == key]
        if len(hits) > 1:
            raise ValueError(f"duplicate map key {key!r}")
        return hits[0] if hits else default

    def has(self, key) -> bool:
        return any(type(k) is type(key) and k == key for k, _ in self)


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value

    def __repr__(self):
        return f"Tag({self.tag}, {self.value!r})"


class Simple:
    def __init__(self, v):
        self.v = v


BREAK = object()


class CBORReader:
    def __init__(self, data: bytes):
        self.d = data
        self.pos = 0

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.d):
            raise ValueError("CBOR: unexpected end of input")
        b = self.d[self.pos:self.pos + n]
        self.pos += n
        return b

    def _arg(self, ai: int):
        if ai < 24:
            return ai
        if ai == 24:
            return self._take(1)[0]
        if ai == 25:
            return int.from_bytes(self._take(2), "big")
        if ai == 26:
            return int.from_bytes(self._take(4), "big")
        if ai == 27:
            return int.from_bytes(self._take(8), "big")
        if ai == 31:
            return None  # indefinite
        raise ValueError(f"CBOR: reserved additional info {ai}")

    def read(self):
        """Return (value, start, end)."""
        start = self.pos
        v = self._item()
        if v is BREAK:
            raise ValueError("CBOR: unexpected break")
        return v, start, self.pos

    def _item(self):
        ib = self._take(1)[0]
        mt, ai = ib >> 5, ib & 0x1F
        if mt == 7:
            if ai == 31:
                return BREAK
            if ai == 25:
                import struct
                return struct.unpack(">e", self._take(2))[0]
            if ai == 26:
                import struct
                return struct.unpack(">f", self._take(4))[0]
            if ai == 27:
                import struct
                return struct.unpack(">d", self._take(8))[0]
            val = self._arg(ai)
            return {20: False, 21: True, 22: None}.get(val, Simple(val))
        arg = self._arg(ai)
        if mt == 0:
            return arg
        if mt == 1:
            return -1 - arg
        if mt in (2, 3):
            if arg is None:
                chunks = []
                while True:
                    c = self._item()
                    if c is BREAK:
                        break
                    if type(c) is not (bytes if mt == 2 else str):
                        raise ValueError("CBOR: bad chunk in indefinite string")
                    chunks.append(c)
                return b"".join(chunks) if mt == 2 else "".join(chunks)
            raw = self._take(arg)
            return raw if mt == 2 else raw.decode("utf-8")
        if mt == 4:
            out = []
            if arg is None:
                while (x := self._item()) is not BREAK:
                    out.append(x)
            else:
                for _ in range(arg):
                    out.append(self._nobreak())
            return out
        if mt == 5:
            out = CMap()
            if arg is None:
                while (k := self._item()) is not BREAK:
                    out.append((k, self._nobreak()))
            else:
                for _ in range(arg):
                    k = self._nobreak()
                    out.append((k, self._nobreak()))
            return out
        if mt == 6:
            if arg is None:
                raise ValueError("CBOR: indefinite tag")
            return Tag(arg, self._nobreak())
        raise ValueError("CBOR: bad major type")

    def _nobreak(self):
        v = self._item()
        if v is BREAK:
            raise ValueError("CBOR: unexpected break")
        return v


def blake2b256(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=32).digest()


def parse_tx(tx_bytes: bytes) -> dict:
    """Split a transaction into its parts, keeping the exact body and aux bytes."""
    rd = CBORReader(tx_bytes)
    ib = rd._take(1)[0]
    if ib >> 5 != 4:
        raise ValueError("transaction is not a CBOR array")
    n = rd._arg(ib & 0x1F)
    if n not in (3, 4):
        raise ValueError(f"transaction array has {n} elements; expected 3 or 4")
    body, b0, b1 = rd.read()
    _wits, _, _ = rd.read()
    is_valid = True
    if n == 4:
        is_valid, _, _ = rd.read()
        if not isinstance(is_valid, bool):
            raise ValueError("is_valid is not a boolean")
    aux, a0, a1 = rd.read()
    if rd.pos != len(tx_bytes):
        raise ValueError("trailing bytes after transaction")
    if not isinstance(body, CMap):
        raise ValueError("transaction body is not a map")
    return {
        "body": body,
        "body_bytes": tx_bytes[b0:b1],
        "is_valid": is_valid,
        "aux": aux,
        "aux_bytes": None if aux is None else tx_bytes[a0:a1],
        "tx_hash": blake2b256(tx_bytes[b0:b1]).hex(),
    }


def metadata_from_aux(aux):
    """Return the metadata map from any auxiliary-data era encoding."""
    if aux is None:
        return None
    if isinstance(aux, CMap) and all(isinstance(k, int) for k, _ in aux):
        # Shelley: plain metadata map
        return aux
    if isinstance(aux, list) and len(aux) >= 1:
        # Allegra/Mary: [metadata, native_scripts]
        return aux[0]
    if isinstance(aux, Tag) and aux.tag == 259 and isinstance(aux.value, CMap):
        # Alonzo+: #6.259({? 0: metadata, ...})
        return aux.value.get(0)
    raise ValueError("unrecognised auxiliary data encoding")


# ---------------------------------------------------------------------------
# §5.2 Anchor parsing
# ---------------------------------------------------------------------------

def parse_anchor(md) -> dict:
    """Decode an anchor v1 metadatum (CMap, or a plain dict for JSON vectors)."""
    if isinstance(md, dict):
        md = CMap(md.items())
    if not isinstance(md, CMap):
        raise ValueError("anchor value is not a map")
    for k, _ in md:
        if not isinstance(k, str):
            raise ValueError("anchor map has a non-text key")
    keys = [k for k, _ in md]
    if len(keys) != len(set(keys)):
        raise ValueError("anchor map has duplicate keys")
    out = {}

    def need(key, typ):
        if not md.has(key):
            raise ValueError(f"anchor missing '{key}'")
        v = md.get(key)
        if isinstance(v, bool) or not isinstance(v, typ):
            raise ValueError(f"anchor '{key}' has wrong type")
        return v

    v = need("v", int)
    if v != 1:
        raise ValueError(f"unsupported anchor version v={v}")
    s = need("s", str)
    if s != SCHEMA_V1:
        raise ValueError(f"unsupported schema s={s!r}")
    r = need("r", str)
    if not HEX64.match(r):
        raise ValueError("anchor 'r' is not 64 lowercase hex")
    n = need("n", int)
    if n < 1:
        raise ValueError("anchor 'n' < 1")
    i = need("i", str)
    if not i.startswith("vl:registry:") or len(i) == len("vl:registry:"):
        raise ValueError("anchor 'i' is not vl:registry:<name>")
    out.update(v=v, s=s, r=r, n=n, i=i)
    if md.has("p"):
        p = md.get("p")
        if not isinstance(p, str) or not HEX64.match(p):
            raise ValueError("anchor 'p' is not 64 lowercase hex")
        out["p"] = p
    for key, val in out.items():
        if isinstance(val, str) and len(val.encode("utf-8")) > 64:
            raise ValueError(f"anchor '{key}' exceeds 64 bytes")
    return out


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch_tx_cbor(koios: str, tx_hash: str) -> bytes:
    url = koios.rstrip("/") + "/tx_cbor"
    req = urllib.request.Request(
        url,
        data=json.dumps({"_tx_hashes": [tx_hash]}).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": "vitaledger-verify-py/1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        raise VerifyError(f"fetch failed: {e}") from e
    if not isinstance(data, list):
        raise VerifyError("unexpected Koios response")
    for row in data:
        if isinstance(row, dict) and str(row.get("tx_hash", "")).lower() == tx_hash:
            try:
                return bytes.fromhex(row["cbor"])
            except (KeyError, TypeError, ValueError) as e:
                raise VerifyError("Koios row has no valid cbor") from e
    raise VerifyError(f"transaction {tx_hash} not found")


# ---------------------------------------------------------------------------
# §6 Verification
# ---------------------------------------------------------------------------

def verify_bundle(bundle, tx_bytes_source, out=print) -> bool:
    """tx_bytes_source(tx_hash) -> bytes. Raises VerifyError for operational errors."""
    ok = True

    def check(name, passed, detail=""):
        nonlocal ok
        out(f"[{'PASS' if passed else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
        ok = ok and passed
        return passed

    if not isinstance(bundle, dict):
        raise VerifyError("bundle is not a JSON object")
    record, proof, anchor = bundle.get("record"), bundle.get("proof"), bundle.get("anchor")
    if not isinstance(anchor, dict):
        raise VerifyError("bundle.anchor missing")
    tx_hash = anchor.get("txHash")
    # SPEC §4.4: hex is lowercase everywhere; reject rather than normalise.
    if not isinstance(tx_hash, str) or not re.match(r"^[0-9a-f]{64}\Z", tx_hash):
        raise VerifyError("anchor.txHash is not 64 lowercase hex characters")
    label = anchor.get("label", DEFAULT_LABEL)
    if isinstance(label, bool) or not isinstance(label, int) or label < 0:
        raise VerifyError("anchor.label is not a non-negative integer")

    # 1. Record format
    errs = validate_record(record)
    check("1 record format (§3)", not errs, "; ".join(errs))
    # 2. Digest
    digest = None
    try:
        digest = record_digest(record)
        check("2 digest (§4.2)", True, digest)
    except ValueError as e:
        check("2 digest (§4.2)", False, str(e))
    # 3. Proof
    root = None
    if digest is not None:
        try:
            root = root_from_proof(digest, proof)
            check("3 proof (§4.4)", True, f"root {root}")
        except ValueError as e:
            check("3 proof (§4.4)", False, str(e))
    else:
        check("3 proof (§4.4)", False, "no digest")

    # 4. Transaction bytes
    tx_bytes = tx_bytes_source(tx_hash)
    try:
        tx = parse_tx(tx_bytes)
    except (ValueError, UnicodeDecodeError) as e:
        raise VerifyError(f"cannot decode transaction CBOR: {e}") from e
    check("4a blake2b-256(body) == txHash", tx["tx_hash"] == tx_hash, tx["tx_hash"])
    adh = tx["body"].get(7)
    if tx["aux_bytes"] is None or adh is None:
        check("4b aux data hash", False, "transaction has no auxiliary data")
        aux_ok = False
    else:
        calc = blake2b256(tx["aux_bytes"])
        aux_ok = check("4b aux data hash", isinstance(adh, bytes) and adh == calc,
                       f"body[7]={adh.hex() if isinstance(adh, bytes) else repr(adh)} computed={calc.hex()}")
    # 5. Validity
    check("5 is_valid", tx["is_valid"] is not False)
    # 6. Anchor
    anchor_v = None
    if aux_ok:
        try:
            md = metadata_from_aux(tx["aux"])
            if not isinstance(md, CMap) or not md.has(label):
                raise ValueError(f"no metadatum at label {label}")
            anchor_v = parse_anchor(md.get(label))
            check(f"6 anchor at label {label} (§5.2)", True, json.dumps(anchor_v))
        except ValueError as e:
            check(f"6 anchor at label {label} (§5.2)", False, str(e))
    else:
        check(f"6 anchor at label {label} (§5.2)", False, "aux data not authenticated")
    # 7. Root
    check("7 anchored r == computed root", anchor_v is not None and root is not None and anchor_v["r"] == root,
          f"anchored {anchor_v['r'] if anchor_v else None}")
    # 8. Size
    ts = proof.get("treeSize") if isinstance(proof, dict) else None
    check("8 anchored n == proof.treeSize", anchor_v is not None and anchor_v["n"] == ts,
          f"anchored {anchor_v['n'] if anchor_v else None}, proof {ts}")
    out("RESULT: " + ("VALID" if ok else "INVALID"))
    return ok


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Verify a VitaLedger proof bundle (SPEC.md v1).")
    ap.add_argument("bundle")
    ap.add_argument("--koios", help="Koios base URL (default by anchor.network; preprod)")
    a = ap.parse_args(argv)
    try:
        with open(a.bundle, encoding="utf-8") as f:
            bundle = load_json(f.read())
        network = (bundle.get("anchor") or {}).get("network", "preprod") if isinstance(bundle, dict) else "preprod"
        koios = a.koios or KOIOS_BY_NETWORK.get(network)
        if koios is None:
            raise VerifyError(f"unknown network {network!r}; pass --koios")
        return 0 if verify_bundle(bundle, lambda h: fetch_tx_cbor(koios, h)) else 1
    except (VerifyError, OSError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
