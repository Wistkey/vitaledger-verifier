import { describe, expect, it } from "vitest";
import vectors from "../test-vectors/v1.json" with { type: "json" };
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalise } from "../src/canonical.js";
import { recordDigest } from "../src/digest.js";
import { leafHash, merkleRoot, rootFromProof } from "../src/merkle.js";
import { parseBatchAnchor } from "../src/metadata.js";
import { validateRecord } from "../src/record.js";

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

  it.each(vectors.edgeRecords.map((v, i) => [i, v] as const))("edge record %i reproduces", (_, v) => {
    expect(validateRecord(v.record)).toEqual([]);
    expect(canonicalise(v.record)).toBe(v.canonical);
    expect(recordDigest(v.record)).toBe(v.recordDigest);
    expect(rootFromProof(v.recordDigest, v.proof)).toBe(vectors.chainedBatch.merkleRoot);
  });

  it("chained batch carries p", () => {
    const anchor = parseBatchAnchor(new Map(Object.entries(vectors.chainedBatch.metadata["22092"])) as never);
    expect(anchor.p).toBe("7111eecc3510eb132bc4ec1794514a58f9ca812b2995a23a02bc7bcc7a6a50ff");
  });

  it.each((vectors.extensionRecords ?? []).map((v: { record: unknown; canonical: string; recordDigest: string }) => [v.recordDigest, v] as const))(
    "accepts spec 1.1 extension record %s",
    (_, v) => {
      expect(validateRecord(v.record)).toEqual([]);
      expect(canonicalise(v.record)).toBe(v.canonical);
      expect(recordDigest(v.record)).toBe(v.recordDigest);
    },
  );

  it.each(vectors.invalidRecords.map((v) => [v.why, v.record] as const))("rejects: %s", (_, record) => {
    expect(validateRecord(record)).not.toEqual([]);
  });
});
