import { describe, expect, it } from "vitest";
import fx from "./fixtures/registry-emulator.json" with { type: "json" };
import type { ChainProvider } from "../src/chain.js";
import {
  checkIssuer,
  lookupIssuer,
  readRegistryEntry,
  registryTokenName,
  type RegistryLocator,
} from "../src/registry.js";

const read = (t: { cborHex: string; outputIndex: number }) => readRegistryEntry(t.cborHex, t.outputIndex, fx.policyId);

describe("readRegistryEntry (emulator transactions)", () => {
  it("decodes a genuine entry from raw transaction bytes", () => {
    const e = read(fx.register);
    expect(e).toMatchObject({
      issuerId: fx.entry.issuerId,
      kind: "brand",
      pubkey: fx.entry.pubkey,
      status: "active",
      updatedAt: BigInt(fx.entry.updatedAt),
      txHash: fx.register.txHash,
      outputIndex: 0,
    });
  });

  it("reads a revoked entry", () => {
    expect(read(fx.revoke).status).toBe("revoked");
  });

  it("rejects an entry-shaped datum without a registry token", () => {
    expect(() => read(fx.fakeDatumNoToken)).toThrow(/exactly one registry token/);
  });

  it("rejects the reference-script output", () => {
    expect(() => read(fx.referenceScript)).toThrow(/registry token|inline datum/);
  });

  it("rejects the entry under another policy", () => {
    expect(() => readRegistryEntry(fx.register.cborHex, 0, "00".repeat(28))).toThrow(/registry script address/);
  });

  it("rejects an output index that doesn't exist", () => {
    expect(() => readRegistryEntry(fx.register.cborHex, 9, fx.policyId)).toThrow(/no output/);
  });
});

describe("checkIssuer", () => {
  const entry = read(fx.register);
  it("accepts the issuer's signature under the registered key", () => {
    expect(checkIssuer(entry, fx.recordDigest, fx.signature)).toMatchObject({ status: "active", signature: "valid" });
  });
  it("rejects a signature over another digest", () => {
    expect(checkIssuer(entry, "00".repeat(32), fx.signature)).toMatchObject({ signature: "invalid" });
  });
  it("rejects a malformed signature", () => {
    expect(checkIssuer(entry, fx.recordDigest, "zz")).toMatchObject({ signature: "invalid" });
  });
  it("reports a missing signature, a revoked issuer and an unregistered one", () => {
    expect(checkIssuer(entry, fx.recordDigest)).toMatchObject({ signature: "absent" });
    expect(checkIssuer(read(fx.revoke), fx.recordDigest, fx.signature).status).toBe("revoked");
    expect(checkIssuer(null, fx.recordDigest).status).toBe("not_registered");
  });
});

describe("lookupIssuer", () => {
  const provider = (txs: Record<string, string>): ChainProvider => ({
    name: "fake",
    async fetchTransaction(h) {
      return { cborHex: txs[h], blockTime: 0, blockHeight: null };
    },
  });
  const locator = (at: { txHash: string; outputIndex: number } | null): RegistryLocator => ({
    name: "fake",
    async locate(policyId, assetName) {
      expect(policyId).toBe(fx.policyId);
      expect(assetName).toBe(registryTokenName(fx.entry.issuerId));
      return at;
    },
  });

  it("follows the locator to the current entry", async () => {
    const e = await lookupIssuer(fx.entry.issuerId, {
      policyId: fx.policyId,
      locator: locator({ txHash: fx.revoke.txHash, outputIndex: 0 }),
      provider: provider({ [fx.revoke.txHash]: fx.revoke.cborHex }),
    });
    expect(e?.status).toBe("revoked");
  });

  it("returns null for an unregistered issuer", async () => {
    expect(
      await lookupIssuer(fx.entry.issuerId, { policyId: fx.policyId, locator: locator(null), provider: provider({}) }),
    ).toBeNull();
  });

  it("does not trust an indexer that serves another transaction's bytes", async () => {
    await expect(
      lookupIssuer(fx.entry.issuerId, {
        policyId: fx.policyId,
        locator: locator({ txHash: fx.revoke.txHash, outputIndex: 0 }),
        provider: provider({ [fx.revoke.txHash]: fx.register.cborHex }),
      }),
    ).rejects.toThrow(/different transaction/);
  });
});
