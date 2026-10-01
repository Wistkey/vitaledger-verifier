import { createPublicKey, verify } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { recordDigest } from "../src/digest.js";
import { generateIssuerKey, InvalidRecordError, signedMessage, signRecord } from "../src/issuer.js";
import { validateRecord } from "../src/record.js";
import { allergenRecord } from "./fixtures/records.js";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const publicKeyFromHex = (hex: string) =>
  createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex, "hex")]), format: "der", type: "spki" });

describe("issuer signing (SPEC §8)", () => {
  it("signs vitaledger.record.v1:<digest> with a fresh Ed25519 key", () => {
    const key = generateIssuerKey();
    expect(key.publicKey).toMatch(/^[0-9a-f]{64}$/);
    const signed = signRecord(allergenRecord, key.privateKeyPem);
    expect(signed.recordDigest).toBe(recordDigest(allergenRecord));
    expect(signed.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(new TextDecoder().decode(signedMessage(signed.recordDigest))).toBe(`vitaledger.record.v1:${signed.recordDigest}`);
    const ok = verify(null, signedMessage(signed.recordDigest), publicKeyFromHex(key.publicKey), Buffer.from(signed.signature, "hex"));
    expect(ok).toBe(true);
  });

  it("refuses to sign an invalid record", () => {
    expect(() => signRecord({ ...allergenRecord, childName: "x" }, generateIssuerKey().privateKeyPem)).toThrow(InvalidRecordError);
  });
});

describe("issuer-pack templates", () => {
  const dir = "issuer-pack/templates";
  it.each(readdirSync(dir).filter((f) => f.endsWith(".json")))("%s is a valid record once placeholders are filled", (file) => {
    const raw = JSON.parse(readFileSync(`${dir}/${file}`, "utf8"));
    const filled = JSON.parse(
      JSON.stringify(raw).replace(/"replace-with-[^"]*"/g, `"${recordDigest(allergenRecord)}"`).replace("vl:issuer:your-slug", "vl:issuer:example-brand"),
    );
    expect(validateRecord(filled)).toEqual([]);
  });
});
