import { describe, expect, it } from "vitest";
import { isValidGtin, validateRecord } from "../src/record.js";
import { recordDigest } from "../src/digest.js";
import { allergenRecord } from "./fixtures/records.js";

describe("record v1", () => {
  it("accepts a well-formed record", () => {
    expect(validateRecord(allergenRecord)).toEqual([]);
  });

  it("checks GTIN check digits", () => {
    expect(["4006381333931", "96385074", "036000291452", "00012345600012"].map(isValidGtin)).toEqual([true, true, true, true]);
    expect(isValidGtin("4006381333932")).toBe(false);
    expect(validateRecord({ ...allergenRecord, subject: { kind: "gtin", value: "4006381333932" } })).toEqual([
      "subject.value must be a GTIN with a valid check digit",
    ]);
  });

  it("rejects unknown fields, so personal data cannot ride along at the top level", () => {
    expect(validateRecord({ ...allergenRecord, childName: "x" })).toContain('unknown field "childName"');
  });

  it("requires prev on updates and revocations, and forbids it on creation", () => {
    const prev = recordDigest(allergenRecord);
    expect(validateRecord({ ...allergenRecord, eventType: "revoked" })[0]).toMatch(/prev .* revoked/);
    expect(validateRecord({ ...allergenRecord, eventType: "revoked", prev })).toEqual([]);
    expect(validateRecord({ ...allergenRecord, prev })).toEqual(["prev is not allowed on attestation_created"]);
  });

  it("requires second-precision UTC timestamps", () => {
    expect(validateRecord({ ...allergenRecord, issuedAt: "2026-11-03T09:30:00.000Z" })).toHaveLength(1);
    expect(validateRecord({ ...allergenRecord, issuedAt: "2026-11-03T17:30:00+08:00" })).toHaveLength(1);
    expect(validateRecord({ ...allergenRecord, issuedAt: "2026-02-30T09:30:00Z" })).toHaveLength(1);
    expect(validateRecord({ ...allergenRecord, issuedAt: "2028-02-29T09:30:00Z" })).toEqual([]);
  });

  it("digest does not depend on key order", () => {
    const shuffled = Object.fromEntries(Object.entries(allergenRecord).reverse());
    expect(recordDigest(shuffled)).toBe(recordDigest(allergenRecord));
  });
});
