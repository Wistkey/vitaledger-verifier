import { describe, expect, it } from "vitest";
import { bytesToHex } from "@noble/hashes/utils.js";
import fx from "./fixtures/keri-kel.json" with { type: "json" };
import cml from "./fixtures/cip170-tx.json" with { type: "json" };
import { attestedDigest, verifyAttest } from "../src/cip170.js";
import { blake3Qb64, KeriError, sealsOf, verifyKel } from "../src/keri.js";
import { metadatumBytes } from "../src/tx.js";
import { encode, fakeTransaction } from "./helpers/encode.js";

const anchor = {
  v: 1,
  s: "vitaledger.record.v1",
  r: "1e459e042a4148859142913ff4b91a62830c8695959a6a467e6564d3d0f30e28",
  n: 1,
  i: "vl:registry:vitaledger",
};
const attest = (over: Record<string, unknown> = {}) => ({ t: "ATTEST", i: fx.aid, d: fx.attested.d, s: fx.attested.s, v: { v: "1.0" }, ...over });
const tx = (a: unknown, value: unknown = anchor) =>
  fakeTransaction(new Map<never, never>([[22092, value], [170, a]] as never)).cborHex;

describe("KERI KEL (keripy fixture)", () => {
  it("verifies a keripy KEL: inception, interactions, rotation", () => {
    const state = verifyKel(fx.kel, fx.aid);
    expect(state.events.map((e) => e.t)).toEqual(["icp", "ixn", "ixn", "rot", "ixn", "ixn"]);
    for (const seal of fx.seals) expect(sealsOf(state.events[parseInt(seal.s, 16)])).toContain(seal.d);
  });

  it("matches the CIP-0170 digest test vector", () => {
    expect(blake3Qb64(Buffer.from(fx.cip170Vector.cborHex, "hex"))).toBe(fx.cip170Vector.d);
  });

  it("rejects a tampered event, a dropped event and another identifier", () => {
    expect(() => verifyKel(fx.kel.replace(fx.seals[0].d, fx.seals[1].d), fx.aid)).toThrow(KeriError);
    const events = fx.kel.split('{"v":');
    expect(() => verifyKel(['', ...events.slice(1, 2), ...events.slice(3)].join('{"v":'), fx.aid)).toThrow(/sequence number|chain/);
    expect(() => verifyKel(fx.kel, "E" + "A".repeat(43))).toThrow(/another identifier/);
  });

  it("rejects a forged signature", () => {
    const i = fx.kel.indexOf("-AAB") + 4;
    const sig = fx.kel.slice(i, i + 88);
    const forged = sig.slice(0, 10) + (sig[10] === "A" ? "B" : "A") + sig.slice(11);
    expect(() => verifyKel(fx.kel.replace(sig, forged), fx.aid)).toThrow(/valid signatures/);
  });
});

describe("CIP-0170 ATTEST", () => {
  it("the fixture's attested bytes are this anchor's CBOR", () => {
    expect(bytesToHex(encode(anchor))).toBe(fx.attested.cborHex);
    expect(bytesToHex(metadatumBytes(tx(attest()), 22092)!)).toBe(fx.attested.cborHex);
    expect(attestedDigest(tx(attest()))).toBe(fx.attested.d);
  });

  it("accepts an ATTEST whose digest is sealed in the signer's KEL", () => {
    expect(verifyAttest(tx(attest()), fx.kel, fx.aid)).toMatchObject({ status: "valid", aid: fx.aid, sn: parseInt(fx.attested.s, 16), operator: true });
  });

  it("rejects a changed anchor, a wrong sequence number and another signer", () => {
    expect(verifyAttest(tx(attest(), { ...anchor, n: 2 }), fx.kel)).toMatchObject({ status: "invalid", reason: /does not match/ });
    expect(verifyAttest(tx(attest({ s: "1" })), fx.kel)).toMatchObject({ status: "invalid", reason: /does not anchor/ });
    expect(verifyAttest(tx(attest()), fx.kel, "E" + "A".repeat(43))).toMatchObject({ status: "invalid", reason: /other than VitaLedger/ });
  });

  it("accepts an ATTEST on a real CML-built transaction (Lucid Evolution)", () => {
    expect(bytesToHex(metadatumBytes(cml.cborHex, 22092)!)).toBe(fx.attested.cborHex);
    expect(verifyAttest(cml.cborHex, fx.kel, fx.aid)).toMatchObject({ status: "valid", operator: true });
  });

  it("reports a transaction without label 170 as absent", () => {
    expect(verifyAttest(fakeTransaction(new Map([[22092, anchor]] as never)).cborHex, fx.kel)).toEqual({ status: "absent" });
  });
});

describe("pinned operator", () => {
  it("pins VitaLedger's Preprod operator AID and its OOBI URL", async () => {
    const { KERI_OPERATOR } = await import("../src/cip170.js");
    expect(KERI_OPERATOR.preprod?.aid).toMatch(/^E[A-Za-z0-9_-]{43}$/);
    expect(KERI_OPERATOR.preprod?.oobi).toBe(`https://api.vitababy.ai/oobi/${KERI_OPERATOR.preprod?.aid}`);
  });
});
