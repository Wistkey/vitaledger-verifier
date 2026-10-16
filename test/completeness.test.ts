import { describe, expect, it } from "vitest";
import { type ChainAnchor, checkCompleteness } from "../src/completeness.js";

const h = (c: string) => c.repeat(64).slice(0, 64);
const anchor = (tx: string, t: number, n: number, p?: string): ChainAnchor => ({
  txHash: h(tx),
  blockTime: t,
  anchor: { v: 1, s: "vitaledger.record.v1", r: h("f"), n, i: "vl:registry:vitaledger", ...(p ? { p: h(p) } : {}) },
});
// a ← b ← c (newest), plus a pre-launch test anchor t.
const chain = [anchor("a", 100, 2), anchor("b", 200, 1, "a"), anchor("c", 300, 3, "b"), anchor("t", 50, 1)];
const all = new Map([[h("a"), 2], [h("b"), 1], [h("c"), 3]]);
const NOW = { now: 100_000 };

describe("checkCompleteness", () => {
  it("is complete when every batch on the p chain is listed in full", () => {
    const r = checkCompleteness(chain, all, NOW);
    expect(r.complete).toBe(true);
    expect(r.history.map((a) => a.txHash)).toEqual([h("c"), h("b"), h("a")]);
    expect(r.outside.map((a) => a.txHash)).toEqual([h("t")]);
  });

  it("fails when the API leaves a batch out", () => {
    const listed = new Map(all);
    listed.delete(h("b"));
    const r = checkCompleteness(chain, listed, NOW);
    expect(r.complete).toBe(false);
    expect(r.missing).toEqual([{ txHash: h("b"), blockTime: 200, n: 1, recent: false }]);
  });

  it("fails when the API lists fewer records than a batch anchors", () => {
    const r = checkCompleteness(chain, new Map([...all, [h("c"), 2]]), NOW);
    expect(r.complete).toBe(false);
    expect(r.short).toEqual([{ txHash: h("c"), n: 3, listed: 2 }]);
  });

  it("tolerates a newest batch the API hasn't confirmed yet", () => {
    const listed = new Map(all);
    listed.delete(h("c"));
    const r = checkCompleteness(chain, listed, { now: 400, graceSeconds: 3600 });
    expect(r.complete).toBe(true);
    expect(r.missing[0]).toMatchObject({ txHash: h("c"), recent: true });
  });

  it("reports a fork and a previous link that leads nowhere", () => {
    const fork = checkCompleteness([...chain, anchor("x", 250, 1, "a")], all, NOW);
    expect(fork.problems.join()).toMatch(/fork/);
    expect(fork.complete).toBe(false);
    const broken = checkCompleteness([anchor("c", 300, 3, "z")], new Map([[h("c"), 3]]), NOW);
    expect(broken.problems.join()).toMatch(/not one of the operator's anchors/);
  });
});
