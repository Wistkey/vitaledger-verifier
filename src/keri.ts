/**
 * Minimal KERI key event log (KEL) verification, enough for CIP-0170 ATTEST
 * checks on a VitaLedger operator identifier: self-addressing, transferable
 * AIDs with Ed25519 keys, numeric thresholds, no witnesses and no
 * delegation. Events: icp, ixn, rot. Checked against KELs made by keripy
 * (test/fixtures/keri-kel.json). Anything outside this subset is rejected,
 * never silently accepted.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";

export class KeriError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeriError";
  }
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function b64Decode(s: string): Uint8Array {
  const out: number[] = [];
  let bits = 0;
  let acc = 0;
  for (const ch of s) {
    const v = B64.indexOf(ch);
    if (v < 0) throw new KeriError(`bad base64url character ${ch}`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function b64Encode(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let acc = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += B64[(acc >> bits) & 0x3f];
    }
  }
  if (bits > 0) out += B64[(acc << (6 - bits)) & 0x3f];
  return out;
}

const b64Int = (s: string) => [...s].reduce((n, ch) => n * 64 + B64.indexOf(ch), 0);

/** Raw bytes of a qb64 primitive with a 1-character code (44 chars: 32 bytes). */
function raw1(qb64: string, code: string): Uint8Array {
  if (qb64.length !== 44 || qb64[0] !== code) throw new KeriError(`expected a ${code} primitive, got ${qb64.slice(0, 4)}…`);
  return b64Decode(qb64).subarray(1);
}

/** CESR qb64 of a Blake3-256 digest (code E). */
export function blake3Qb64(data: Uint8Array): string {
  return "E" + b64Encode(new Uint8Array([0, ...blake3(data)])).slice(1);
}

export interface KeyEvent {
  t: "icp" | "ixn" | "rot";
  d: string;
  i: string;
  s: string;
  p?: string;
  kt?: string;
  k?: string[];
  nt?: string;
  n?: string[];
  bt?: string;
  b?: string[];
  a: unknown[];
  [field: string]: unknown;
}

interface Message {
  raw: Uint8Array;
  event: KeyEvent;
  /** Controller signatures: [key index, 64-byte signature]. */
  sigs: Array<[number, Uint8Array]>;
}

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

/** Splits a CESR text stream (qb64) into events and their controller signatures. */
export function parseKelStream(stream: string): Message[] {
  const bytes = enc.encode(stream);
  const out: Message[] = [];
  let o = 0;
  while (o < stream.length) {
    if (stream[o] !== "{") throw new KeriError(`expected an event at offset ${o}`);
    const m = /^\{"v":"KERI10JSON([0-9a-f]{6})_"/.exec(stream.slice(o, o + 32));
    if (!m) throw new KeriError("unsupported event version (need KERI10JSON)");
    const size = parseInt(m[1], 16);
    const raw = bytes.slice(o, o + size);
    const event = JSON.parse(dec.decode(raw)) as KeyEvent;
    o += size;
    const sigs: Array<[number, Uint8Array]> = [];
    // Attachments: optional -V group wrapper, then counted groups.
    let end = stream.length;
    while (o < end && stream[o] === "-") {
      const code = stream.slice(o, o + 2);
      const count = b64Int(stream.slice(o + 2, o + 4));
      o += 4;
      if (code === "-V") {
        end = o + count * 4; // attachment group: its size in quadlets
      } else if (code === "-A") {
        for (let j = 0; j < count; j++, o += 88) {
          const sig = stream.slice(o, o + 88);
          if (sig[0] !== "A" && sig[0] !== "B") throw new KeriError(`unsupported signature code ${sig[0]}`);
          sigs.push([B64.indexOf(sig[1]), b64Decode(sig).subarray(2)]);
        }
      } else if (code === "-E") {
        o += count * (24 + 36); // first-seen replay couples (sn, datetime): not needed
      } else if (code === "-B") {
        o += count * 88; // witness indexed signatures: no witnesses in this subset
      } else if (code === "-C") {
        o += count * (44 + 88); // non-transferable receipt couples
      } else {
        throw new KeriError(`unsupported attachment ${code}`);
      }
    }
    if (end !== stream.length && o !== end) throw new KeriError("attachment group size mismatch");
    out.push({ raw, event, sigs });
  }
  return out;
}

/** SAID check: Blake3 over the event with `d` (and, for icp, `i`) replaced by 44 '#'. */
function checkSaid(msg: Message): void {
  const placeholder = "#".repeat(44);
  const e = msg.event;
  if (JSON.stringify(e) !== dec.decode(msg.raw)) throw new KeriError(`event ${e.s} is not in compact JSON form`);
  const blanked = { ...e, d: placeholder, ...(e.t === "icp" ? { i: placeholder } : {}) };
  if (blake3Qb64(enc.encode(JSON.stringify(blanked))) !== e.d) throw new KeriError(`event ${e.s} SAID does not match`);
}

function threshold(t: string | undefined, n: number): number {
  if (!t || !/^[1-9][0-9]*$/.test(t)) throw new KeriError("only numeric signing thresholds are supported");
  const m = Number(t);
  if (m > n) throw new KeriError("threshold exceeds the number of keys");
  return m;
}

function checkSigs(msg: Message, keys: string[], kt: number): void {
  const signed = new Set<number>();
  for (const [index, sig] of msg.sigs) {
    const key = keys[index];
    if (key && ed25519.verify(sig, msg.raw, raw1(key, "D"))) signed.add(index);
  }
  if (signed.size < kt) throw new KeriError(`event ${msg.event.s} has ${signed.size} valid signatures, needs ${kt}`);
}

export interface KelState {
  aid: string;
  /** Event SAIDs in order. */
  events: KeyEvent[];
  keys: string[];
}

/** Verifies a whole KEL for `aid` and returns its events. Throws KeriError if anything is off. */
export function verifyKel(stream: string, aid: string): KelState {
  const msgs = parseKelStream(stream);
  if (!msgs.length) throw new KeriError("empty KEL");
  let keys: string[] = [];
  let kt = 0;
  let next: string[] = [];
  let nt = 0;
  const events: KeyEvent[] = [];
  msgs.forEach((msg, sn) => {
    const e = msg.event;
    if (e.i !== aid) throw new KeriError(`event ${sn} is for another identifier`);
    if (e.s !== sn.toString(16)) throw new KeriError(`event ${sn} has sequence number ${e.s}`);
    if (sn === 0 ? e.t !== "icp" : e.t !== "ixn" && e.t !== "rot") throw new KeriError(`unsupported or misplaced event ${e.t}`);
    checkSaid(msg);
    if (sn > 0 && e.p !== events[sn - 1].d) throw new KeriError(`event ${sn} does not chain to the previous one`);
    if (e.t === "icp" || e.t === "rot") {
      if (e.bt !== "0" || (e.b?.length ?? 0) > 0 || (Array.isArray(e.ba) && e.ba.length) || (Array.isArray(e.br) && e.br.length)) {
        throw new KeriError("witnessed identifiers are not supported");
      }
      if (!Array.isArray(e.k) || !e.k.length || !Array.isArray(e.n)) throw new KeriError(`event ${sn} has no keys`);
      if (e.t === "rot") {
        // Pre-rotation: every new key must have been committed to as a next-key digest.
        const committed = e.k.filter((k) => next.includes(blake3Qb64(enc.encode(k)))).length;
        if (committed < nt) throw new KeriError(`rotation ${sn} uses keys that were not pre-committed`);
      }
      keys = e.k;
      kt = threshold(e.kt, keys.length);
      next = e.n;
      nt = next.length ? threshold(e.nt, next.length) : 0;
      if (!next.length) throw new KeriError("non-transferable identifiers are not supported");
    }
    checkSigs(msg, keys, kt);
    if (e.t === "icp" && e.i !== e.d) throw new KeriError("identifier is not self-addressing");
    events.push(e);
  });
  return { aid, events, keys };
}

/** The `{d}` seals anchored in an event. */
export function sealsOf(event: KeyEvent): string[] {
  return (event.a ?? []).flatMap((x) => (x && typeof x === "object" && typeof (x as { d?: unknown }).d === "string" ? [(x as { d: string }).d] : []));
}
