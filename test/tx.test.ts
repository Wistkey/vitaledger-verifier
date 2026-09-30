import { describe, expect, it } from "vitest";
import fixture from "./fixtures/preprod-046c0ce9.json" with { type: "json" };
import { parseTransaction } from "../src/tx.js";
import { fakeTransaction } from "./helpers/encode.js";

describe("parseTransaction", () => {
  it("reads a real Preprod transaction and recomputes its id", () => {
    const tx = parseTransaction(fixture[0].cbor);
    expect(tx.txHash).toBe(fixture[0].tx_hash);
    expect(tx.isValid).toBe(true);
    expect([...tx.metadata.keys()].sort()).toEqual([170, 170170]);
  });

  it("detects auxiliary data that the body does not commit to", () => {
    const { cborHex } = fakeTransaction(new Map([[22092, "x"]]), { tamperAux: true });
    expect(() => parseTransaction(cborHex)).toThrow(/does not match/);
  });

  it("detects a tampered body via the transaction id", () => {
    const { cborHex, txHash } = fakeTransaction(new Map([[22092, "x"]]));
    const tampered = cborHex.replace("1a00029810", "1a00029811"); // fee 170000 → 170001
    expect(tampered).not.toBe(cborHex);
    expect(parseTransaction(tampered).txHash).not.toBe(txHash);
  });
});
