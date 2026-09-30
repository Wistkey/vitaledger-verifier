/**
 * Reads the metadata of a Cardano transaction from its CBOR, and proves the
 * bytes belong to the requested transaction: the transaction id is
 * blake2b-256 of the body, and the body commits to the auxiliary data with
 * blake2b-256 (body field 7).
 */
import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { type CborValue, readArrayItems, readItem, Tagged } from "./cbor.js";

export class TransactionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransactionError";
  }
}

export interface ParsedTransaction {
  txHash: string;
  isValid: boolean;
  /** Label → metadatum, or empty when the transaction has no metadata. */
  metadata: Map<number, CborValue>;
}

const hash256 = (bytes: Uint8Array) => bytesToHex(blake2b(bytes, { dkLen: 32 }));

export function parseTransaction(txCborHex: string): ParsedTransaction {
  const bytes = hexToBytes(txCborHex);
  const items = readArrayItems(bytes);
  if (items.length !== 3 && items.length !== 4) throw new TransactionError("not a Cardano transaction");
  const [body, , third, fourth] = items;
  const isValid = items.length === 4 ? third.value !== false : true;
  const aux = items.length === 4 ? fourth : third;

  const txHash = hash256(bytes.subarray(body.start, body.end));
  if (!(body.value instanceof Map)) throw new TransactionError("transaction body is not a map");

  const metadata = new Map<number, CborValue>();
  if (aux.value === null) {
    if (body.value.has(7)) throw new TransactionError("body commits to auxiliary data that is missing");
    return { txHash, isValid, metadata };
  }

  const committed = body.value.get(7);
  if (!(committed instanceof Uint8Array)) throw new TransactionError("body has no auxiliary data hash");
  if (bytesToHex(committed) !== hash256(bytes.subarray(aux.start, aux.end))) {
    throw new TransactionError("auxiliary data does not match the hash in the transaction body");
  }

  const raw = auxiliaryMetadata(aux.value);
  if (raw) {
    for (const [label, value] of raw) {
      if (typeof label !== "number") throw new TransactionError("metadata label is not an integer");
      metadata.set(label, value);
    }
  }
  return { txHash, isValid, metadata };
}

/** Shelley map, Allegra/Mary [metadata, scripts], or Alonzo+ tag 259 {0: metadata}. */
function auxiliaryMetadata(aux: CborValue): Map<CborValue, CborValue> | undefined {
  if (aux instanceof Map) return aux;
  if (Array.isArray(aux) && aux[0] instanceof Map) return aux[0];
  if (aux instanceof Tagged && aux.tag === 259 && aux.value instanceof Map) {
    const m = aux.value.get(0);
    return m instanceof Map ? m : undefined;
  }
  throw new TransactionError("unrecognised auxiliary data format");
}

/** Re-reads a metadatum by label from raw CBOR — used by builders for a pre-submit check. */
export function metadatumAt(txCborHex: string, label: number): CborValue | undefined {
  return parseTransaction(txCborHex).metadata.get(label);
}

export { readItem };
