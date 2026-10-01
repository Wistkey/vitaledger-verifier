import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { allInclusionProofs, inclusionProof, leafHash, merkleRoot, rootFromProof } from "../src/merkle.js";

const digests = (n: number) => Array.from({ length: n }, (_, i) => bytesToHex(sha256(new TextEncoder().encode(`record-${i}`))));

/** Independent bottom-up construction: pair left to right, carry an odd last node up unchanged. */
function referenceRoot(ds: string[]): string {
  let level = ds.map(leafHash);
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? sha256(Uint8Array.from([0x01, ...level[i], ...level[i + 1]])) : level[i]);
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

describe("merkle", () => {
  it("a single record's root is its leaf hash", () => {
    const [d] = digests(1);
    expect(merkleRoot([d])).toBe(bytesToHex(sha256(Uint8Array.from([0x00, ...hexToBytes(d)]))));
    expect(inclusionProof([d], 0).path).toEqual([]);
  });

  it("matches an independent construction for sizes 1–70", () => {
    for (let n = 1; n <= 70; n++) expect(merkleRoot(digests(n)), `n=${n}`).toBe(referenceRoot(digests(n)));
  });

  it("every proof in every batch up to 40 leads back to the root", () => {
    for (let n = 1; n <= 40; n++) {
      const ds = digests(n);
      const root = merkleRoot(ds);
      for (let i = 0; i < n; i++) expect(rootFromProof(ds[i], inclusionProof(ds, i)), `n=${n} i=${i}`).toBe(root);
    }
  });

  it("any change to the digest, path, index or size breaks the proof", () => {
    const ds = digests(13);
    const root = merkleRoot(ds);
    const proof = inclusionProof(ds, 6);
    expect(rootFromProof(ds[7], proof)).not.toBe(root);
    proof.path.forEach((_, j) => {
      const path = [...proof.path];
      path[j] = ds[0];
      expect(rootFromProof(ds[6], { ...proof, path })).not.toBe(root);
    });
    expect(rootFromProof(ds[6], { ...proof, leafIndex: 5 })).not.toBe(root);
    expect(() => rootFromProof(ds[6], { ...proof, path: proof.path.slice(1) })).toThrow(/shorter/);
    expect(() => rootFromProof(ds[6], { ...proof, path: [...proof.path, ds[0]] })).toThrow(/longer/);
    expect(() => rootFromProof(ds[6], { ...proof, leafIndex: 13 })).toThrow(/outside/);
  });

  it("rejects malformed digests", () => {
    expect(() => merkleRoot(["ABC"])).toThrow(/64 lowercase hex/);
    expect(() => merkleRoot([])).toThrow(/at least one/);
  });

  it("allInclusionProofs equals inclusionProof for every leaf, sizes 1–70", () => {
    for (let n = 1; n <= 70; n++) {
      const ds = digests(n);
      expect(allInclusionProofs(ds), `n=${n}`).toEqual(ds.map((_, i) => inclusionProof(ds, i)));
    }
  });

  it("allInclusionProofs scales to large batches", () => {
    const ds = digests(20_000);
    const t = performance.now();
    const proofs = allInclusionProofs(ds);
    expect(performance.now() - t).toBeLessThan(5_000);
    const root = merkleRoot(ds);
    for (const i of [0, 1, 9_999, 16_383, 16_384, 19_999]) expect(rootFromProof(ds[i], proofs[i])).toBe(root);
  });
});
