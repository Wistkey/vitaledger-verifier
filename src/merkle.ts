/**
 * Merkle tree over record digests, following RFC 9162 §2.1 (Certificate
 * Transparency v2): leaf = SHA-256(0x00 ‖ d), node = SHA-256(0x01 ‖ l ‖ r),
 * and a tree of n leaves splits at the largest power of two below n.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { isHex32 } from "./digest.js";

export interface InclusionProof {
  /** Zero-based position of the record in the batch. */
  leafIndex: number;
  /** Number of records in the batch. */
  treeSize: number;
  /** Sibling hashes from the leaf upwards, lowercase hex. */
  path: string[];
}

export class MerkleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MerkleError";
  }
}

export function leafHash(recordDigestHex: string): Uint8Array {
  if (!isHex32(recordDigestHex)) throw new MerkleError("record digest must be 64 lowercase hex characters");
  return sha256(concat(Uint8Array.of(0x00), hexToBytes(recordDigestHex)));
}

function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(Uint8Array.of(0x01), left, right));
}

/** Largest power of two strictly less than n (n ≥ 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function subtreeRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return nodeHash(subtreeRoot(leaves.slice(0, k)), subtreeRoot(leaves.slice(k)));
}

/** Merkle root of a batch of record digests, lowercase hex. */
export function merkleRoot(recordDigests: string[]): string {
  if (recordDigests.length === 0) throw new MerkleError("a batch needs at least one record");
  return bytesToHex(subtreeRoot(recordDigests.map(leafHash)));
}

/** Inclusion proof for the record at `leafIndex`. */
export function inclusionProof(recordDigests: string[], leafIndex: number): InclusionProof {
  const n = recordDigests.length;
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= n) {
    throw new MerkleError(`leaf index ${leafIndex} outside batch of ${n}`);
  }
  const path: Uint8Array[] = [];
  const walk = (leaves: Uint8Array[], m: number): void => {
    if (leaves.length === 1) return;
    const k = split(leaves.length);
    if (m < k) {
      walk(leaves.slice(0, k), m);
      path.push(subtreeRoot(leaves.slice(k)));
    } else {
      walk(leaves.slice(k), m - k);
      path.push(subtreeRoot(leaves.slice(0, k)));
    }
  };
  walk(recordDigests.map(leafHash), leafIndex);
  return { leafIndex, treeSize: n, path: path.map(bytesToHex) };
}

/**
 * Every leaf's inclusion proof in one O(n log n) pass. Calling
 * inclusionProof() per leaf rebuilds sibling subtrees each time (O(n²)
 * overall), which takes minutes for a few thousand records.
 */
export function allInclusionProofs(recordDigests: string[]): InclusionProof[] {
  const n = recordDigests.length;
  if (n === 0) throw new MerkleError("a batch needs at least one record");
  // Returns the subtree root and, per leaf, its path upward within the subtree.
  const walk = (leaves: Uint8Array[]): { root: Uint8Array; paths: Uint8Array[][] } => {
    if (leaves.length === 1) return { root: leaves[0], paths: [[]] };
    const k = split(leaves.length);
    const left = walk(leaves.slice(0, k));
    const right = walk(leaves.slice(k));
    for (const p of left.paths) p.push(right.root);
    for (const p of right.paths) p.push(left.root);
    return { root: nodeHash(left.root, right.root), paths: [...left.paths, ...right.paths] };
  };
  const { paths } = walk(recordDigests.map(leafHash));
  return paths.map((path, leafIndex) => ({ leafIndex, treeSize: n, path: path.map(bytesToHex) }));
}

/**
 * Root implied by a record digest and its proof (RFC 9162 §2.1.3.2).
 * Throws if the proof is structurally impossible for its tree size.
 */
export function rootFromProof(recordDigestHex: string, proof: InclusionProof): string {
  const { leafIndex, treeSize, path } = proof;
  if (!Number.isInteger(treeSize) || treeSize < 1) throw new MerkleError("tree size must be a positive integer");
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
    throw new MerkleError(`leaf index ${leafIndex} outside batch of ${treeSize}`);
  }
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash(recordDigestHex);
  for (const p of path) {
    if (!isHex32(p)) throw new MerkleError("proof hashes must be 64 lowercase hex characters");
    if (sn === 0) throw new MerkleError("proof is longer than the tree allows");
    const sibling = hexToBytes(p);
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(sibling, r);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = nodeHash(r, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  if (sn !== 0) throw new MerkleError("proof is shorter than the tree requires");
  return bytesToHex(r);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
