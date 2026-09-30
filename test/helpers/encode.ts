/** Test-only CBOR encoder for building synthetic transactions. */
import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { Tagged } from "../../src/cbor.js";

type V = number | string | boolean | null | Uint8Array | V[] | Map<V, V> | Tagged | { [k: string]: V };

function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 0x100) return [(major << 5) | 24, n];
  if (n < 0x10000) return [(major << 5) | 25, n >> 8, n & 0xff];
  return [(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}

export function encode(v: V): Uint8Array {
  const out: number[] = [];
  const w = (x: V): void => {
    if (x === null) out.push(0xf6);
    else if (x === true) out.push(0xf5);
    else if (x === false) out.push(0xf4);
    else if (typeof x === "number") out.push(...(x >= 0 ? head(0, x) : head(1, -1 - x)));
    else if (typeof x === "string") {
      const b = new TextEncoder().encode(x);
      out.push(...head(3, b.length), ...b);
    } else if (x instanceof Uint8Array) out.push(...head(2, x.length), ...x);
    else if (Array.isArray(x)) {
      out.push(...head(4, x.length));
      x.forEach(w);
    } else if (x instanceof Map) {
      out.push(...head(5, x.size));
      for (const [k, val] of x) {
        w(k);
        w(val);
      }
    } else if (x instanceof Tagged) {
      out.push(...head(6, x.tag));
      w(x.value as V);
    } else {
      const entries = Object.entries(x);
      out.push(...head(5, entries.length));
      for (const [k, val] of entries) {
        w(k);
        w(val);
      }
    }
  };
  w(v);
  return Uint8Array.from(out);
}

const concat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => [...p]));

/** A minimal Conway-shaped transaction carrying `metadata` (label → value). */
export function fakeTransaction(metadata: Map<V, V>, opts: { tamperAux?: boolean; isValid?: boolean } = {}) {
  const aux = encode(new Tagged(259, new Map<V, V>([[0, metadata]]) as never));
  const auxHash = blake2b(aux, { dkLen: 32 });
  const body = encode(new Map<V, V>([[0, []], [1, []], [2, 170000], [7, auxHash]]));
  const auxBytes = opts.tamperAux ? encode(new Tagged(259, new Map<V, V>([[0, new Map<V, V>([[1, "x"]])]]) as never)) : aux;
  const tx = concat(Uint8Array.of(0x84), body, encode(new Map()), encode(opts.isValid ?? true), auxBytes);
  return { cborHex: bytesToHex(tx), txHash: bytesToHex(blake2b(body, { dkLen: 32 })) };
}
