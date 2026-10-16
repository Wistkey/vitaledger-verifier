/**
 * Issuer signatures made with a Cardano wallet: CIP-30 `signData`, which
 * returns a CIP-8 (COSE_Sign1, RFC 9052) signature and a COSE_Key. The
 * wallet's payment key is an ordinary Ed25519 key, so an issuer registered
 * with it keeps the same 32-byte public key as SPEC §8; only the signature
 * encoding differs. A signature is either 128 hex characters (raw Ed25519) or
 * a longer hex COSE_Sign1.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { type CborValue, decode, Tagged } from "./cbor.js";

export class Cip8Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Cip8Error";
  }
}

const EDDSA = -8;

function encodeHead(major: number, length: number): number[] {
  if (length < 24) return [(major << 5) | length];
  if (length < 0x100) return [(major << 5) | 24, length];
  if (length < 0x10000) return [(major << 5) | 25, length >> 8, length & 0xff];
  return [(major << 5) | 26, (length >>> 24) & 0xff, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff];
}

function bstr(b: Uint8Array): number[] {
  return [...encodeHead(2, b.length), ...b];
}

/** RFC 9052 §4.4 Sig_structure for COSE_Sign1 with empty external_aad. */
export function sigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  const context = new TextEncoder().encode("Signature1");
  return new Uint8Array([0x84, ...encodeHead(3, context.length), ...context, ...bstr(protectedBytes), 0x40, ...bstr(payload)]);
}

function get(m: Map<CborValue, CborValue>, key: string | number): CborValue {
  return m.get(key);
}

export interface ParsedCoseSign1 {
  protectedBytes: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
  /** The `address` protected header (raw address bytes), when present. */
  address?: Uint8Array;
}

export function parseCoseSign1(hex: string): ParsedCoseSign1 {
  let v: CborValue;
  try {
    v = decode(hexToBytes(hex));
  } catch {
    throw new Cip8Error("not CBOR");
  }
  // Some encoders tag COSE_Sign1 (18); CIP-30 wallets send it untagged.
  if (v instanceof Tagged && v.tag === 18) v = v.value;
  if (!Array.isArray(v) || v.length !== 4) throw new Cip8Error("not a COSE_Sign1");
  const [protectedBytes, unprotected, payload, signature] = v;
  if (!(protectedBytes instanceof Uint8Array) || !(unprotected instanceof Map)) throw new Cip8Error("bad COSE_Sign1 headers");
  if (!(payload instanceof Uint8Array)) throw new Cip8Error("detached payloads are not accepted");
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new Cip8Error("bad signature length");
  const headers = decode(protectedBytes);
  if (!(headers instanceof Map) || get(headers, 1) !== EDDSA) throw new Cip8Error("algorithm is not EdDSA");
  // CIP-8 "hashed": the payload would be blake2b-224 of the message; not accepted.
  if (get(unprotected, "hashed") === true) throw new Cip8Error("hashed payloads are not accepted");
  const address = get(headers, "address");
  return { protectedBytes, payload, signature, address: address instanceof Uint8Array ? address : undefined };
}

/** The raw Ed25519 public key in a CIP-30 COSE_Key (OKP, Ed25519). */
export function publicKeyFromCoseKey(hex: string): string {
  let key: CborValue;
  try {
    key = decode(hexToBytes(hex));
  } catch {
    throw new Cip8Error("COSE_Key is not CBOR");
  }
  if (!(key instanceof Map) || get(key, 1) !== 1 || get(key, -1) !== 6) throw new Cip8Error("COSE_Key is not an Ed25519 OKP key");
  const alg = get(key, 3);
  if (alg !== undefined && alg !== EDDSA) throw new Cip8Error("COSE_Key algorithm is not EdDSA");
  const x = get(key, -2);
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Cip8Error("COSE_Key has no 32-byte public key");
  return bytesToHex(x);
}

/**
 * Verifies a CIP-8 COSE_Sign1 over exactly `message` under `publicKeyHex`.
 * When the signature names an address, its payment credential must be that
 * key (blake2b-224 of it), so a wallet can't present someone else's address.
 */
export function verifyCip8(coseSign1Hex: string, message: Uint8Array, publicKeyHex: string): boolean {
  let s: ParsedCoseSign1;
  try {
    s = parseCoseSign1(coseSign1Hex);
  } catch {
    return false;
  }
  if (bytesToHex(s.payload) !== bytesToHex(message)) return false;
  const pub = hexToBytes(publicKeyHex);
  if (s.address) {
    // CIP-19 header types 0, 2, 4, 6 have a key-hash payment credential.
    if (s.address.length < 29 || ((s.address[0] >> 4) & 1) !== 0 || (s.address[0] >> 4) > 7) return false;
    if (bytesToHex(s.address.subarray(1, 29)) !== bytesToHex(blake2b(pub, { dkLen: 28 }))) return false;
  }
  try {
    return ed25519.verify(s.signature, sigStructure(s.protectedBytes, s.payload), pub);
  } catch {
    return false;
  }
}

/**
 * Any issuer signature (SPEC §8): 128 lowercase hex = raw Ed25519 over the
 * message; longer hex = CIP-8 COSE_Sign1 whose payload is the message.
 */
export function verifyMessageSignature(publicKeyHex: string, message: Uint8Array, signatureHex: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex) || !/^[0-9a-f]+$/.test(signatureHex)) return false;
  if (signatureHex.length === 128) {
    try {
      return ed25519.verify(hexToBytes(signatureHex), message, hexToBytes(publicKeyHex));
    } catch {
      return false;
    }
  }
  return signatureHex.length > 128 && signatureHex.length <= 4096 && verifyCip8(signatureHex, message, publicKeyHex);
}
