/**
 * Batch anchor at the VitaLedger metadata label — see SPEC.md §5.
 */
import type { CborValue } from "./cbor.js";
import { isHex32 } from "./digest.js";
import { RECORD_SCHEMA_V1 } from "./record.js";

/** Provisional label, "VL" in ASCII; unregistered in CIP-10 as of 2026-09-30. */
export const VITALEDGER_LABEL = 22092;
export const ANCHOR_FORMAT_V1 = 1;
export const METADATA_STRING_LIMIT = 64;
const REGISTRY_ID = /^vl:registry:[a-z0-9-]{1,52}$/;

export interface BatchAnchor {
  /** Anchor format version. */
  v: number;
  /** Schema of every record in the batch. */
  s: string;
  /** Merkle root of the batch, lowercase hex. */
  r: string;
  /** Number of records in the batch. */
  n: number;
  /** Issuer registry that resolves the issuer ids used in the batch. */
  i: string;
  /** Transaction hash of the previous batch from the same registry. */
  p?: string;
}

export class AnchorFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnchorFormatError";
  }
}

export function buildBatchAnchor(fields: Omit<BatchAnchor, "v" | "s"> & { s?: string }): BatchAnchor {
  const anchor: BatchAnchor = { v: ANCHOR_FORMAT_V1, s: fields.s ?? RECORD_SCHEMA_V1, r: fields.r, n: fields.n, i: fields.i };
  if (fields.p !== undefined) anchor.p = fields.p;
  assertAnchor(anchor);
  return anchor;
}

function assertAnchor(a: BatchAnchor): void {
  if (a.v !== ANCHOR_FORMAT_V1) throw new AnchorFormatError(`unsupported anchor version ${a.v}`);
  if (a.s !== RECORD_SCHEMA_V1) throw new AnchorFormatError(`unsupported record schema ${a.s}`);
  if (!isHex32(a.r)) throw new AnchorFormatError("r must be a 64-character lowercase hex Merkle root");
  if (!Number.isSafeInteger(a.n) || a.n < 1) throw new AnchorFormatError("n must be a positive integer");
  if (!REGISTRY_ID.test(a.i)) throw new AnchorFormatError("i must match vl:registry:<name>");
  if (a.p !== undefined && !isHex32(a.p)) throw new AnchorFormatError("p must be a 64-character lowercase hex transaction hash");
  for (const [k, v] of Object.entries(a)) {
    if (typeof v === "string" && new TextEncoder().encode(v).length > METADATA_STRING_LIMIT) {
      throw new AnchorFormatError(`${k} exceeds the ${METADATA_STRING_LIMIT}-byte metadata string limit`);
    }
  }
}

/** Reads a batch anchor from a decoded metadatum. Unknown keys are ignored (forward compatibility). */
export function parseBatchAnchor(metadatum: CborValue): BatchAnchor {
  if (!(metadatum instanceof Map)) throw new AnchorFormatError("anchor metadatum is not a map");
  const get = (k: string) => metadatum.get(k);
  const anchor: BatchAnchor = {
    v: get("v") as number,
    s: get("s") as string,
    r: get("r") as string,
    n: get("n") as number,
    i: get("i") as string,
  };
  const p = get("p");
  if (p !== undefined) anchor.p = p as string;
  assertAnchor(anchor);
  return anchor;
}
