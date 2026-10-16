/**
 * CIP-0170 ATTEST next to a VitaLedger anchor (SPEC §9): the anchoring
 * operator's KERI identifier anchors the Blake3-256 digest of the exact CBOR
 * bytes of the label-22092 metadatum in its key event log, and the same
 * transaction carries, at label 170:
 *   { t: "ATTEST", i: <AID>, d: <digest qb64>, s: <hex sn>, v: { v: "1.0" } }
 * Optional: v1 verification (§§4–6) does not depend on it.
 */
import type { CborValue } from "./cbor.js";
import { blake3Qb64, KeriError, sealsOf, verifyKel } from "./keri.js";
import { VITALEDGER_LABEL } from "./metadata.js";
import { metadatumBytes, parseTransaction } from "./tx.js";

export const CIP170_LABEL = 170;

/** Pinned operator identifiers, by network: who VitaLedger's KERI AID is, and where its KEL is served. */
export const KERI_OPERATOR: Partial<Record<"preprod" | "preview" | "mainnet", { aid: string; oobi: string }>> = {};

export interface Attest {
  i: string;
  d: string;
  s: string;
}

export function parseAttest(value: CborValue): Attest {
  if (!(value instanceof Map)) throw new KeriError("label 170 is not a map");
  const t = value.get("t");
  const i = value.get("i");
  const d = value.get("d");
  const s = value.get("s");
  if (t !== "ATTEST") throw new KeriError(`label 170 is ${String(t)}, not ATTEST`);
  if (typeof i !== "string" || typeof d !== "string" || typeof s !== "string" || !/^[0-9a-f]+$/.test(s)) {
    throw new KeriError("malformed ATTEST");
  }
  if (d[0] !== "E") throw new KeriError("ATTEST digest is not Blake3-256 (code E)");
  return { i, d, s };
}

/** The transaction's label-170 ATTEST, or null if it carries none (throws if malformed). */
export function attestOf(txCborHex: string): Attest | null {
  const entry = parseTransaction(txCborHex).metadata.get(CIP170_LABEL);
  return entry === undefined ? null : parseAttest(entry);
}

/** Digest of the label's metadatum bytes as CIP-0170 defines it (Blake3-256, CESR qb64). */
export function attestedDigest(txCborHex: string, label = VITALEDGER_LABEL): string | undefined {
  const bytes = metadatumBytes(txCborHex, label);
  return bytes ? blake3Qb64(bytes) : undefined;
}

export type AttestResult =
  | { status: "absent" }
  | { status: "valid"; aid: string; sn: number; digest: string; operator: boolean }
  | { status: "invalid"; reason: string; aid?: string };

/**
 * Checks the ATTEST in a transaction against the signer's KEL: the digest is
 * recomputed from the on-chain bytes at label 22092, the KEL is verified from
 * inception, and the event at `s` must carry that digest as a seal. With
 * `expectedAid`, the signer must also be that identifier.
 */
export function verifyAttest(txCborHex: string, kel: string, expectedAid?: string): AttestResult {
  const entry = parseTransaction(txCborHex).metadata.get(CIP170_LABEL);
  if (entry === undefined) return { status: "absent" };
  let attest: Attest | undefined;
  try {
    attest = parseAttest(entry);
    const digest = attestedDigest(txCborHex);
    if (!digest) return { status: "invalid", reason: "no label 22092 metadatum to attest", aid: attest.i };
    if (digest !== attest.d) return { status: "invalid", reason: "ATTEST digest does not match the label 22092 bytes", aid: attest.i };
    if (expectedAid && attest.i !== expectedAid) return { status: "invalid", reason: "signed by an identifier other than VitaLedger's", aid: attest.i };
    const state = verifyKel(kel, attest.i);
    const sn = parseInt(attest.s, 16);
    const event = state.events[sn];
    if (!event) return { status: "invalid", reason: `the KEL has no event ${attest.s}`, aid: attest.i };
    if (!sealsOf(event).includes(digest)) return { status: "invalid", reason: `KEL event ${attest.s} does not anchor this digest`, aid: attest.i };
    return { status: "valid", aid: attest.i, sn, digest, operator: expectedAid === attest.i };
  } catch (e) {
    return { status: "invalid", reason: (e as Error).message, aid: attest?.i };
  }
}

/** Fetches a KEL (CESR text) from an OOBI URL. */
export async function fetchKel(oobiUrl: string): Promise<string> {
  const res = await fetch(oobiUrl, { headers: { accept: "application/cesr, application/json+cesr, text/plain" } });
  if (!res.ok) throw new Error(`KEL endpoint responded ${res.status}`);
  return res.text();
}
