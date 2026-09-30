import { describe, expect, it } from "vitest";
import { buildBatchAnchor, VITALEDGER_LABEL } from "../src/metadata.js";
import { inclusionProof, merkleRoot } from "../src/merkle.js";
import { recordDigest } from "../src/digest.js";
import { type ProofBundle, verifyAgainstTransaction, verifyBundle } from "../src/verify.js";
import { fakeTransaction } from "./helpers/encode.js";
import { allergenRecord, labRecord, recallRecord } from "./fixtures/records.js";

const records = [allergenRecord, labRecord, recallRecord];
const ds = records.map(recordDigest);
const anchor = buildBatchAnchor({ r: merkleRoot(ds), n: ds.length, i: "vl:registry:vitaledger" });

function setup(anchorValue: Record<string, unknown> = { ...anchor }, opts = {}) {
  const tx = fakeTransaction(new Map([[VITALEDGER_LABEL, new Map(Object.entries(anchorValue)) as never]]), opts);
  const bundle: ProofBundle = {
    record: labRecord,
    proof: inclusionProof(ds, 1),
    anchor: { network: "preprod", txHash: tx.txHash },
  };
  return { bundle, chainTx: { cborHex: tx.cborHex, blockTime: 1793000000, blockHeight: 1 } };
}

describe("verifyAgainstTransaction", () => {
  it("accepts an unchanged record", () => {
    const { bundle, chainTx } = setup();
    const r = verifyAgainstTransaction(bundle, chainTx);
    expect(r.reason).toBeUndefined();
    expect(r.valid).toBe(true);
    expect(r.anchoredAt).toBe("2026-10-26T07:33:20.000Z");
    expect(r.recordDigest).toBe(ds[1]);
  });

  it("rejects a record with one changed value", () => {
    const { bundle, chainTx } = setup();
    bundle.record = { ...labRecord, claim: { ...labRecord.claim, valueMgPerKg: 0.001 } };
    expect(verifyAgainstTransaction(bundle, chainTx).reason).toMatch(/^merkle root/);
  });

  it("rejects bytes from a different transaction", () => {
    const { bundle } = setup();
    const other = setup({ ...anchor, n: 4 });
    expect(verifyAgainstTransaction(bundle, other.chainTx).reason).toMatch(/^transaction bytes/);
  });

  it("rejects a batch-size mismatch", () => {
    const { bundle, chainTx } = setup({ ...anchor, n: 4 });
    expect(verifyAgainstTransaction(bundle, chainTx).reason).toMatch(/^batch size/);
  });

  it("rejects a phase-2 invalid transaction", () => {
    const { bundle, chainTx } = setup(undefined, { isValid: false });
    expect(verifyAgainstTransaction(bundle, chainTx).reason).toMatch(/^transaction validity/);
  });

  it("rejects an invalid record before touching the chain", () => {
    const { bundle, chainTx } = setup();
    bundle.record = { ...labRecord, issuer: "Someone" };
    expect(verifyAgainstTransaction(bundle, chainTx).reason).toMatch(/^record format/);
  });

  it("fetches through the provider", async () => {
    const { bundle, chainTx } = setup();
    const r = await verifyBundle(bundle, { name: "stub", fetchTransaction: async () => chainTx });
    expect(r.valid).toBe(true);
    expect(r.checks.at(-1)).toEqual({ name: "chain source", ok: true, detail: "stub" });
  });
});
