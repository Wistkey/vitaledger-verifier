import { describe, expect, it } from "vitest";
import vectors from "../test-vectors/v1.json" with { type: "json" };
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalise } from "../src/canonical.js";
import { recordDigest } from "../src/digest.js";
import { leafHash, merkleRoot, rootFromProof } from "../src/merkle.js";

describe("published test vectors", () => {
  it.each(vectors.records.map((v, i) => [i, v] as const))("record %i reproduces", (_, v) => {
    expect(canonicalise(v.record)).toBe(v.canonical);
    expect(recordDigest(v.record)).toBe(v.recordDigest);
    expect(bytesToHex(leafHash(v.recordDigest))).toBe(v.leafHash);
    expect(rootFromProof(v.recordDigest, v.proof)).toBe(vectors.batch.merkleRoot);
  });

  it("batch roots reproduce", () => {
    expect(merkleRoot(vectors.records.map((v) => v.recordDigest))).toBe(vectors.batch.merkleRoot);
    for (const s of vectors.merkleSizes) expect(merkleRoot(s.recordDigests)).toBe(s.merkleRoot);
  });
});
