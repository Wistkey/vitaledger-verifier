import { describe, expect, it } from "vitest";
import { buildBatchAnchor, VITALEDGER_LABEL } from "../src/metadata.js";
import { inclusionProof, merkleRoot } from "../src/merkle.js";
import { recordDigest } from "../src/digest.js";
import { verifyAll } from "../src/verify-all.js";
import { fakeTransaction } from "./helpers/encode.js";
import { allergenRecord, labRecord, recallRecord } from "./fixtures/records.js";

const records = [allergenRecord, labRecord, recallRecord];
const ds = records.map(recordDigest);
const anchor = buildBatchAnchor({ r: merkleRoot(ds), n: ds.length, i: "vl:registry:vitaledger" });
const tx = fakeTransaction(new Map([[VITALEDGER_LABEL, new Map(Object.entries({ ...anchor })) as never]]));
const chainTx = { cborHex: tx.cborHex, blockTime: 1793000000, blockHeight: 1 };

/** A fake API: lists the three digests over two pages and serves their bundles. */
function fakeApi(tamper?: (i: number, record: unknown) => unknown) {
  const sorted = ds.map((d, i) => ({ d, i })).sort((a, b) => (a.d < b.d ? -1 : 1));
  return async (url: string) => {
    const u = new URL(url);
    if (u.pathname === "/api/v1/proofs") {
      const after = u.searchParams.get("after");
      const rest = sorted.filter((x) => !after || x.d > after);
      const page = rest.slice(0, 2);
      return { data: { records: page.map((x) => ({ recordDigest: x.d })), next: rest.length > 2 ? page[1].d : null } };
    }
    const d = u.pathname.split("/").pop()!;
    const i = ds.indexOf(d);
    const record = tamper ? tamper(i, records[i]) : records[i];
    return { data: { record, bundle: { record, proof: inclusionProof(ds, i), anchor: { network: "preprod", txHash: tx.txHash } } } };
  };
}

describe("verifyAll", () => {
  it("re-verifies every listed record across pages, fetching each transaction once", async () => {
    let fetches = 0;
    const seen: string[] = [];
    const report = await verifyAll({
      apiBase: "https://api.example.test/",
      fetchJson: fakeApi(),
      pageSize: 2,
      providerFor: () => ({ name: "stub", fetchTransaction: async () => (fetches++, chainTx) }),
      onRecord: (o) => seen.push(o.recordDigest),
    });
    expect(report).toMatchObject({ valid: 3, invalid: 0, transactions: 1, errors: [] });
    expect(seen.sort()).toEqual([...ds].sort());
    expect(fetches).toBe(1);
  });

  it("does not trust the API: a swapped or changed record is invalid", async () => {
    const report = await verifyAll({
      apiBase: "https://api.example.test",
      fetchJson: fakeApi((i, r) => (i === 1 ? { ...(r as object), claim: { ...labRecord.claim, valueMgPerKg: 0.001 } } : r)),
      providerFor: () => ({ name: "stub", fetchTransaction: async () => chainTx }),
    });
    expect(report.valid).toBe(2);
    expect(report.invalid).toBe(1);
    expect(report.records.find((r) => r.recordDigest === ds[1])?.reason).toMatch(/different record/);
  });

  it("checks Mithril once per transaction and treats not-yet-certified as pending, not invalid", async () => {
    let calls = 0;
    const report = await verifyAll({
      apiBase: "https://api.example.test",
      fetchJson: fakeApi(),
      providerFor: () => ({ name: "stub", fetchTransaction: async () => chainTx }),
      mithril: async () => (calls++, { certified: false, reason: "not certified by Mithril yet" }),
    });
    expect(calls).toBe(1);
    expect(report.valid).toBe(3);
    expect(report.records.every((r) => r.mithril === "pending")).toBe(true);
  });

  it("reports an unreachable record as an error, not as invalid", async () => {
    const api = fakeApi();
    const report = await verifyAll({
      apiBase: "https://api.example.test",
      fetchJson: async (url) => (url.includes(`/proofs/${ds[0]}`) ? Promise.reject(new Error("timeout")) : api(url)),
      providerFor: () => ({ name: "stub", fetchTransaction: async () => chainTx }),
    });
    expect(report).toMatchObject({ valid: 2, invalid: 0 });
    expect(report.errors).toHaveLength(1);
  });
});
