/**
 * Verifies a VitaLedger proof bundle — see SPEC.md §6.
 */
import type { Network, ChainProvider, ChainTransaction } from "./chain.js";
import { koios } from "./chain.js";
import { isHex32, recordDigest } from "./digest.js";
import { type InclusionProof, rootFromProof } from "./merkle.js";
import { parseBatchAnchor, VITALEDGER_LABEL } from "./metadata.js";
import { UNSUPPORTED, validateRecord } from "./record.js";
import { parseTransaction } from "./tx.js";

export interface ProofBundle {
  record: unknown;
  proof: InclusionProof;
  anchor: { network: Network; txHash: string; label?: number };
}

export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface VerificationResult {
  valid: boolean;
  /** First failing check, in words. */
  reason?: string;
  /** The record uses a subject kind or claim type newer than this verifier (SPEC §9): upgrade, not tampering. */
  unsupported?: boolean;
  recordDigest?: string;
  merkleRoot?: string;
  txHash?: string;
  network?: Network;
  /** ISO time of the block that anchored the batch. */
  anchoredAt?: string;
  checks: Check[];
}

class Checks {
  readonly list: Check[] = [];
  isUnsupported = false;
  unsupported() {
    this.isUnsupported = true;
  }
  pass(name: string, detail?: string) {
    this.list.push({ name, ok: true, detail });
  }
  fail(name: string, detail: string): false {
    this.list.push({ name, ok: false, detail });
    return false;
  }
}

/**
 * Checks that need no network: the record is well-formed and the proof
 * leads to a root. Returns the root, or undefined after recording a failure.
 */
function offline(bundle: ProofBundle, c: Checks): { digest: string; root: string } | undefined {
  const problems = validateRecord(bundle.record);
  if (problems.length) {
    c.fail("record format", problems.join("; "));
    if (problems.every((p) => p.startsWith(UNSUPPORTED))) c.unsupported();
    return undefined;
  }
  c.pass("record format", "vitaledger.record.v1");
  const digest = recordDigest(bundle.record);
  c.pass("record digest", digest);
  try {
    const root = rootFromProof(digest, bundle.proof);
    c.pass("inclusion proof", `leaf ${bundle.proof.leafIndex} of ${bundle.proof.treeSize}`);
    return { digest, root };
  } catch (e) {
    c.fail("inclusion proof", (e as Error).message);
    return undefined;
  }
}

/** Verifies a bundle against transaction bytes already in hand (browser or test use). */
export function verifyAgainstTransaction(bundle: ProofBundle, tx: ChainTransaction): VerificationResult {
  const c = new Checks();
  const result = (extra: Partial<VerificationResult> = {}): VerificationResult => {
    const failed = c.list.find((x) => !x.ok);
    return {
      valid: !failed,
      reason: failed ? `${failed.name}: ${failed.detail}` : undefined,
      ...(c.isUnsupported ? { unsupported: true } : {}),
      checks: c.list,
      ...extra,
    };
  };
  const txHash = bundle.anchor?.txHash;
  const network = bundle.anchor?.network;
  if (!isHex32(txHash)) {
    c.fail("anchor", "txHash must be 64 lowercase hex characters");
    return result();
  }
  const base = { txHash, network };
  const off = offline(bundle, c);
  if (!off) return result(base);
  const withDigests = { ...base, recordDigest: off.digest, merkleRoot: off.root };

  let parsed;
  try {
    parsed = parseTransaction(tx.cborHex);
  } catch (e) {
    c.fail("transaction bytes", (e as Error).message);
    return result(withDigests);
  }
  if (parsed.txHash !== txHash) {
    c.fail("transaction bytes", `bytes hash to ${parsed.txHash}, not the requested ${txHash}`);
    return result(withDigests);
  }
  c.pass("transaction bytes", "body and metadata hashes match the transaction id");
  if (!parsed.isValid) {
    c.fail("transaction validity", "transaction failed script validation; its metadata is not in effect");
    return result(withDigests);
  }

  const label = bundle.anchor.label ?? VITALEDGER_LABEL;
  const metadatum = parsed.metadata.get(label);
  if (metadatum === undefined) {
    c.fail("anchor metadata", `no metadata at label ${label}`);
    return result(withDigests);
  }
  let anchor;
  try {
    anchor = parseBatchAnchor(metadatum);
  } catch (e) {
    c.fail("anchor metadata", (e as Error).message);
    return result(withDigests);
  }
  c.pass("anchor metadata", `label ${label}, format v${anchor.v}`);

  if (anchor.r !== off.root) c.fail("merkle root", `chain has ${anchor.r}, proof gives ${off.root}`);
  else c.pass("merkle root", "matches the root anchored on chain");
  if (anchor.n !== bundle.proof.treeSize) c.fail("batch size", `chain says ${anchor.n} records, proof says ${bundle.proof.treeSize}`);
  else c.pass("batch size", `${anchor.n} ${anchor.n === 1 ? "record" : "records"}`);

  return result({ ...withDigests, anchoredAt: new Date(tx.blockTime * 1000).toISOString() });
}

/** Fetches the anchoring transaction and verifies the bundle against it. */
export async function verifyBundle(bundle: ProofBundle, provider?: ChainProvider): Promise<VerificationResult> {
  const network = bundle.anchor?.network ?? "preprod";
  const p = provider ?? koios(network);
  if (!isHex32(bundle.anchor?.txHash)) return verifyAgainstTransaction(bundle, { cborHex: "", blockTime: 0, blockHeight: null });
  const tx = await p.fetchTransaction(bundle.anchor.txHash);
  const result = verifyAgainstTransaction(bundle, tx);
  result.checks.push({ name: "chain source", ok: true, detail: p.name });
  return result;
}
