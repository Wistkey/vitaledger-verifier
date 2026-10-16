/** The exact bytes an issuer signs: UTF-8 of `vitaledger.record.v1:<recordDigest>` (SPEC §8). */
export function signedMessage(digest: string): Uint8Array {
  return new TextEncoder().encode(`vitaledger.record.v1:${digest}`);
}
