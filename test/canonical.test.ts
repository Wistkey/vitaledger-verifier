import { describe, expect, it } from "vitest";
import { canonicalise, CanonicalisationError } from "../src/canonical.js";

describe("canonicalise (RFC 8785)", () => {
  it("sorts keys by UTF-16 code units and strips whitespace", () => {
    expect(canonicalise({ b: 1, a: { d: [3, 2], c: "x" } })).toBe('{"a":{"c":"x","d":[3,2]},"b":1}');
    // RFC 8785 §3.2.3 ordering example: "\r" < "1" < "\u0080" < "ö" < "€" < "😀" < "ﬂ"
    const keys = ["€", "\r", "דּ", "1", "😀", "\u0080", "ö"];
    const obj = Object.fromEntries(keys.map((k) => [k, 0]));
    const order = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\ud83d\ude00", "\ufb33"];
    expect(canonicalise(obj)).toBe(`{${order.map((k) => `${JSON.stringify(k)}:0`).join(",")}}`);
  });

  it("uses ECMAScript number formatting", () => {
    expect(canonicalise([1e21, 1e-7, 0.1, -0, 100, 4.5])).toBe("[1e+21,1e-7,0.1,0,100,4.5]");
  });

  it("rejects values JSON cannot represent", () => {
    expect(() => canonicalise({ a: NaN })).toThrow(CanonicalisationError);
    expect(() => canonicalise({ a: new Date() })).toThrow(/plain objects/);
    expect(() => canonicalise({ a: 1n })).toThrow(/bigint/);
  });

  it("drops undefined members, like JSON.stringify", () => {
    expect(canonicalise({ a: undefined, b: 1 })).toBe('{"b":1}');
  });
});
