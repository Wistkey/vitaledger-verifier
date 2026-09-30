import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { canonicalise } from "./canonical.js";

export { bytesToHex, hexToBytes };

const encoder = new TextEncoder();

/** Canonical UTF-8 bytes of a record: the exact input to the record digest. */
export function canonicalBytes(record: unknown): Uint8Array {
  return encoder.encode(canonicalise(record));
}

/**
 * Record digest: lowercase hex SHA-256 of the canonical bytes. Identical to
 * `sha256sum` over a file containing the canonical JSON with no trailing newline.
 */
export function recordDigest(record: unknown): string {
  return bytesToHex(sha256(canonicalBytes(record)));
}

export function isHex32(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
