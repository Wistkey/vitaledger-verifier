import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import fx from "./fixtures/cip8-lucid.json" with { type: "json" };
import { parseCoseSign1, publicKeyFromCoseKey, sigStructure, verifyCip8, verifyMessageSignature } from "../src/cip8.js";
import { signedMessage } from "../src/signed-message.js";

const pubkey = publicKeyFromCoseKey(fx.key);
const message = signedMessage(fx.recordDigest);

describe("CIP-8 wallet signatures (Lucid signMessage fixture)", () => {
  it("reads the Ed25519 key from the COSE_Key", () => {
    expect(pubkey).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifies a wallet signature over the record message", () => {
    const parsed = parseCoseSign1(fx.signature);
    expect(new TextDecoder().decode(parsed.payload)).toBe(fx.message);
    expect(bytesToHex(parsed.address!)).toBe(fx.addressHex);
    expect(verifyCip8(fx.signature, message, pubkey)).toBe(true);
    expect(verifyMessageSignature(pubkey, message, fx.signature)).toBe(true);
  });

  it("rejects a wallet signature over another message", () => {
    expect(verifyMessageSignature(pubkey, message, fx.signatureOverOtherDigest)).toBe(false);
  });

  it("rejects it under another key", () => {
    expect(verifyMessageSignature("11".repeat(32), message, fx.signature)).toBe(false);
  });

  it("rejects a tampered signature byte", () => {
    const last = fx.signature.slice(-2) === "00" ? "01" : "00";
    expect(verifyMessageSignature(pubkey, message, fx.signature.slice(0, -2) + last)).toBe(false);
  });

  it("rejects an address that isn't the signing key's", () => {
    // A valid signature by key B, but under protected headers naming wallet A's address.
    const sk = ed25519.utils.randomSecretKey();
    const other = bytesToHex(ed25519.getPublicKey(sk));
    const parsed = parseCoseSign1(fx.signature);
    const sig = ed25519.sign(sigStructure(parsed.protectedBytes, parsed.payload), sk);
    const forged = fx.signature.slice(0, -128) + bytesToHex(sig);
    expect(verifyCip8(forged, message, other)).toBe(false);
  });

  it("still verifies raw Ed25519 signatures", () => {
    const sk = ed25519.utils.randomSecretKey();
    const raw = bytesToHex(ed25519.sign(message, sk));
    expect(verifyMessageSignature(bytesToHex(ed25519.getPublicKey(sk)), message, raw)).toBe(true);
  });
});
