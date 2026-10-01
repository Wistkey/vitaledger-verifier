/**
 * Issuer-side helpers (Node only): Ed25519 keys and record signatures, as in
 * SPEC.md §8. Not part of the browser bundle.
 */
import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { recordDigest } from "./digest.js";
import { validateRecord } from "./record.js";

/** The exact bytes an issuer signs: UTF-8 of `vitaledger.record.v1:<recordDigest>`. */
export function signedMessage(digest: string): Uint8Array {
  return new TextEncoder().encode(`vitaledger.record.v1:${digest}`);
}

export interface IssuerKey {
  /** Raw 32-byte Ed25519 public key, lowercase hex: give this to VitaLedger. */
  publicKey: string;
  /** PKCS#8 PEM. Keep secret. */
  privateKeyPem: string;
}

export function generateIssuerKey(): IssuerKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: Buffer.from(publicKey.export({ format: "der", type: "spki" }).subarray(-32)).toString("hex"),
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
}

export class InvalidRecordError extends Error {
  constructor(readonly problems: string[]) {
    super(`record is invalid: ${problems.join("; ")}`);
    this.name = "InvalidRecordError";
  }
}

/** Validates and signs a record; the result is the body of POST /api/v1/attestation-records. */
export function signRecord(record: unknown, privateKeyPem: string): { record: unknown; signature: string; recordDigest: string } {
  const problems = validateRecord(record);
  if (problems.length) throw new InvalidRecordError(problems);
  const digest = recordDigest(record);
  const signature = Buffer.from(sign(null, signedMessage(digest), createPrivateKey(privateKeyPem))).toString("hex");
  return { record, signature, recordDigest: digest };
}
