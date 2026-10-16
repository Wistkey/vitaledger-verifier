import { describe, expect, it } from "vitest";
import type { RegistryEntry } from "../src/registry.js";
import { issuerReports, type RecordOutcome } from "../src/verify-all.js";

const KEY = "11".repeat(32);
const entry = (over: Partial<RegistryEntry> = {}): RegistryEntry => ({
  issuerId: "vl:issuer:acme", kind: "brand", pubkey: KEY, status: "active", updatedAt: 1n, txHash: "f".repeat(64), outputIndex: 0, ...over,
});
const rec = (sig: RecordOutcome["issuerSignature"]): RecordOutcome => ({ recordDigest: "a".repeat(64), valid: true, issuer: "vl:issuer:acme", issuerSignature: sig });
const api = (publicKey: string, status = "active") => async () => ({ data: { publicKey, status } });

async function report(e: RegistryEntry | null | undefined, apiKey = KEY, apiStatus = "active", sigs: RecordOutcome["issuerSignature"][] = ["valid"]) {
  const [r] = await issuerReports("https://api.example.test", api(apiKey, apiStatus), sigs.map(rec), new Map([["vl:issuer:acme", Promise.resolve(e)]]));
  return r;
}

describe("issuer drift (API against the on-chain registry)", () => {
  it("is clean when key and status agree and signatures verify", async () => {
    const r = await report(entry());
    expect(r).toMatchObject({ registry: "active", drift: [], warnings: [], signatures: { valid: 1, invalid: 0, absent: 0 } });
  });
  it("flags a key that differs between the API and the registry", async () => {
    expect((await report(entry(), "22".repeat(32))).drift).toEqual(["the API and the on-chain registry have different keys"]);
  });
  it("flags a status conflict either way", async () => {
    expect((await report(entry({ status: "revoked" }))).drift).toEqual(["revoked on chain but active in the API"]);
    expect((await report(entry(), KEY, "suspended")).drift).toEqual(["active on chain but suspended in the API"]);
  });
  it("only warns for an unregistered issuer or signatures under another key", async () => {
    const unregistered = await report(null);
    expect(unregistered.drift).toEqual([]);
    expect(unregistered.warnings).toEqual(["not registered in the on-chain registry"]);
    const rotated = await report(entry(), KEY, "active", ["valid", "invalid"]);
    expect(rotated.drift).toEqual([]);
    expect(rotated.warnings[0]).toMatch(/1 signature\(s\) don't verify under the current registry key/);
  });
});
