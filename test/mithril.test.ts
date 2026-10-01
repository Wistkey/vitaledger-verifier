import { describe, expect, it } from "vitest";
import { MITHRIL, type MithrilClientLike, verifyInclusionWithMithril } from "../src/mithril.js";

const TX = "7111eecc3510eb132bc4ec1794514a58f9ca812b2995a23a02bc7bcc7a6a50ff";

function fakeClient(opts: { certified: boolean; matches?: boolean }): MithrilClientLike {
  return {
    get_cardano_transaction_proofs: async (hashes) => ({
      certificate_hash: "03c253e98cd167563488168aae1d07ed4b5f63fd162d47c8ca250cce9cd699ee",
      transactions_hashes: opts.certified ? hashes : [],
      non_certified_transactions: opts.certified ? [] : hashes,
    }),
    verify_certificate_chain: async () => ({ epoch: 316, signed_entity_type: { CardanoTransactions: [316, 5241539] } }),
    verify_cardano_transaction_proof_then_compute_message: async () => ({ message: "m" }),
    verify_message_match_certificate: async () => opts.matches ?? true,
  };
}

describe("verifyInclusionWithMithril", () => {
  it("reports a certified transaction with its certificate and epoch", async () => {
    expect(await verifyInclusionWithMithril(TX, fakeClient({ certified: true }))).toEqual({
      certified: true,
      certificateHash: "03c253e98cd167563488168aae1d07ed4b5f63fd162d47c8ca250cce9cd699ee",
      epoch: 316,
      certifiedUpToBlock: 5241539,
    });
  });

  it("says 'not certified yet' for a recent transaction", async () => {
    const r = await verifyInclusionWithMithril(TX, fakeClient({ certified: false }));
    expect(r).toMatchObject({ certified: false, reason: expect.stringMatching(/^not certified/) });
  });

  it("rejects a proof that does not match its certificate", async () => {
    const r = await verifyInclusionWithMithril(TX, fakeClient({ certified: true, matches: false }));
    expect(r).toEqual({ certified: false, reason: "Mithril proof does not match its certificate" });
  });

  it("pins a genesis key and aggregator for every network", () => {
    for (const net of ["preprod", "preview", "mainnet"] as const) {
      expect(MITHRIL[net].aggregator).toMatch(/^https:\/\/aggregator\..+\.api\.mithril\.network\/aggregator$/);
      expect(MITHRIL[net].genesisVkey).toMatch(/^[0-9a-f]{200,}$/);
    }
    expect(MITHRIL.mainnet.genesisVkey).not.toBe(MITHRIL.preprod.genesisVkey);
  });
});
