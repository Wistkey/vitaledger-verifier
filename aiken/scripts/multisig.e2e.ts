// The M-of-N signing flow end to end in Lucid's Emulator (real Plutus V3
// evaluation): admin 1 exports a signing request, admin 3 checks and
// co-signs it on "their machine", admin 1 submits. Plus the refusals.
//   npm run e2e:multisig
import assert from "node:assert/strict";
import { Emulator, Lucid, generateEmulatorAccount } from "@lucid-evolution/lucid";
import { adminKeyHashOf, deployReferenceScriptTx, findReferenceScript, genuineEntries, registerTx, registryFor, signAll } from "./lib.js";
import { cosignRequest, describeRequest, exportRequest, REQUEST_TTL_MS, submitRequest } from "./multisig.js";

const [a1, a2, a3] = Array.from({ length: 3 }, () => generateEmulatorAccount({ lovelace: 100_000_000n }));
const emulator = new Emulator([a1, a2, a3]);
const lucid = await Lucid(emulator, "Preprod");
const kh = (a: typeof a1) => adminKeyHashOf(a.address);
const reg = registryFor("Preprod", { keys: [kh(a1), kh(a2), kh(a3)], required: 2 });

lucid.selectWallet.fromSeed(a1.seedPhrase);
await (await signAll(await deployReferenceScriptTx(lucid, reg), [], "Preprod")).submit();
emulator.awaitBlock(1);
const ref = await findReferenceScript(lucid, reg);
assert.ok(ref);

const entry = { issuerId: "vl:issuer:acme-foods", kind: "brand" as const, pubkey: "11".repeat(32), status: "active" as const, updatedAt: 1n };

// 1. Admin 1 builds and exports, asking admin 3 to co-sign.
const tx = await registerTx(lucid, reg, entry, { signers: [kh(a1), kh(a3)], ref, validTo: emulator.now() + REQUEST_TTL_MS });
let req = await exportRequest(tx, "preprod", reg, kh(a1), "register vl:issuer:acme-foods");
assert.deepEqual(Object.keys(req.witnesses), [kh(a1)]);
assert.doesNotMatch(JSON.stringify(req), new RegExp(a1.seedPhrase.split(" ")[0] + " " + a1.seedPhrase.split(" ")[1]));
console.log("  ok  admin 1 exports a signing request with only its own signature (no secrets)");

// 2. Admin 3 reviews what the tx itself does.
const desc = await describeRequest(lucid, reg, req, "Preprod");
assert.deepEqual(desc.problems, []);
assert.ok(desc.lines.some((l) => l.includes("writes entry vl:issuer:acme-foods: kind brand, status active")), desc.lines.join("\n"));
assert.ok(desc.lines.some((l) => l.includes("mints registry token")));
assert.ok(desc.lines.some((l) => l.includes("needs signatures from: admin 1, admin 3")), desc.lines.join("\n"));
console.log("  ok  the co-signer sees the change decoded from the tx bytes:\n" + desc.lines.join("\n"));

// Refusals.
await assert.rejects(submitRequest(lucid, reg, req, "Preprod"), /1 of 2 admin signatures/);
console.log("  ok  submit refuses with one signature");
await assert.rejects(cosignRequest(lucid, req, a2.seedPhrase, "Preprod", desc), /doesn't ask for your signature/);
console.log("  ok  an admin the tx doesn't name can't co-sign it");
const forged = { ...req, policyId: "00".repeat(28) };
const forgedDesc = await describeRequest(lucid, reg, forged, "Preprod");
assert.match(forgedDesc.problems.join(), /not our registry/);
await assert.rejects(cosignRequest(lucid, forged, a3.seedPhrase, "Preprod", forgedDesc), /refusing to sign/);
const swapped = { ...req, txHash: "ff".repeat(32) };
assert.match((await describeRequest(lucid, reg, swapped, "Preprod")).problems.join(), /don't match/);
console.log("  ok  co-signing refuses a request for another registry, or with mismatched bytes");

// 3. Admin 3 co-signs; admin 1 submits.
req = await cosignRequest(lucid, req, a3.seedPhrase, "Preprod", desc);
assert.deepEqual(Object.keys(req.witnesses).sort(), [kh(a1), kh(a3)].sort());
const hash = await submitRequest(lucid, reg, req, "Preprod");
emulator.awaitBlock(1);
assert.equal(hash, req.txHash);
assert.deepEqual((await genuineEntries(reg, await lucid.utxosAt(reg.address))).map((e) => e.entry.issuerId), [entry.issuerId]);
console.log(`  ok  admin 3 co-signs, admin 1 submits: ${hash.slice(0, 16)}… registers acme-foods`);
console.log("multisig e2e passed");
