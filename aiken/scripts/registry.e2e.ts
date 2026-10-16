// End-to-end run of the compiled validator in Lucid Evolution's Emulator
// (real Plutus V3 evaluation, no network):  npm run e2e
// 2-of-3 admins; the script is read from a CIP-33 reference script.
import assert from "node:assert/strict";
import { Emulator, Lucid, generateEmulatorAccount, type TxSignBuilder } from "@lucid-evolution/lucid";
import {
  adminKeyHashOf,
  deployReferenceScriptTx,
  encodeEntry,
  findEntry,
  findReferenceScript,
  genuineEntries,
  registerTx,
  registryFor,
  retireTx,
  signAll,
  updateTx,
  type IssuerEntry,
  type Signing,
} from "./lib.js";

const [a1, a2, a3, attacker] = Array.from({ length: 4 }, () => generateEmulatorAccount({ lovelace: 100_000_000n }));
const emulator = new Emulator([a1, a2, a3, attacker]);
const lucid = await Lucid(emulator, "Preprod");
const kh = (acct: typeof a1) => adminKeyHashOf(acct.address);
const reg = registryFor("Preprod", { keys: [kh(a1), kh(a2), kh(a3)], required: 2 });

/** `payer` pays the fee and signs; `cosigners` add their signatures. */
async function submit(payer: typeof a1, cosigners: (typeof a1)[], build: () => Promise<TxSignBuilder>) {
  lucid.selectWallet.fromSeed(payer.seedPhrase);
  const tx = await build();
  const hash = await (await signAll(tx, cosigners.map((c) => c.seedPhrase), "Preprod")).submit();
  emulator.awaitBlock(1);
  return hash;
}

async function rejects(what: string, fn: () => Promise<unknown>) {
  const err = await fn().then(
    () => null,
    (e: unknown) => String((e as Error)?.message ?? e),
  );
  assert.ok(err, `${what} should be rejected`);
  // Must be the validator failing, not some unrelated error. (`aiken build`
  // strips traces, so which check failed is covered by the aiken tests.)
  assert.match(err, /failed script execution (Mint|Spend)/, `${what}: unexpected error ${err}`);
  console.log(`  ok  rejected by the validator: ${what}`);
}

const entries = async () => genuineEntries(reg, await lucid.utxosAt(reg.address));
const acme: IssuerEntry = {
  issuerId: "vl:issuer:acme-foods",
  kind: "brand",
  pubkey: "11".repeat(32),
  status: "active",
  updatedAt: 1n,
};

console.log(`registry ${reg.address}\npolicy   ${reg.policyId} (2-of-3 admins)`);

// CIP-33: publish the script once.
await submit(a1, [], () => deployReferenceScriptTx(lucid, reg));
const ref = await findReferenceScript(lucid, reg);
assert.ok(ref, "reference script UTxO");
const quorum: Signing = { signers: [kh(a1), kh(a3)], ref };
console.log(`  ok  reference script at ${ref.txHash}#${ref.outputIndex}`);

lucid.selectWallet.fromSeed(a1.seedPhrase);
const attachedSize = (await registerTx(lucid, reg, acme, { signers: quorum.signers })).toCBOR().length / 2;
const refSize = (await registerTx(lucid, reg, acme, quorum)).toCBOR().length / 2;
assert.ok(refSize < attachedSize - 1000, `reference script should shrink the tx (${refSize} vs ${attachedSize} bytes)`);
console.log(`  ok  register tx ${refSize} bytes with the reference script vs ${attachedSize} carrying it`);

await rejects("one admin alone registers", () =>
  submit(a1, [], () => registerTx(lucid, reg, acme, { signers: [kh(a1)], ref })),
);
await rejects("one admin plus an outsider registers", () =>
  submit(a1, [attacker], () => registerTx(lucid, reg, acme, { signers: [kh(a1), kh(attacker)], ref })),
);

await submit(a1, [a3], () => registerTx(lucid, reg, acme, quorum));
assert.deepEqual((await entries()).map((e) => e.entry), [acme]);
console.log("  ok  admins 1+3 register acme-foods");

await rejects("outsider rotates acme's key", () =>
  submit(attacker, [], async () =>
    updateTx(lucid, reg, await findEntry(lucid, reg, acme.issuerId), { ...acme, pubkey: "ee".repeat(32) }, {
      signers: [kh(attacker)],
      ref,
    }),
  ),
);

// Anyone can pay to the script address; a fake entry without a token is ignored.
await submit(attacker, [], () =>
  lucid
    .newTx()
    .pay.ToContract(
      reg.address,
      { kind: "inline", value: encodeEntry({ ...acme, issuerId: "vl:issuer:fake", pubkey: "ee".repeat(32) }) },
      { lovelace: 2_000_000n },
    )
    .complete(),
);
assert.equal((await lucid.utxosAt(reg.address)).length, 3); // entry + reference script + fake
assert.deepEqual((await entries()).map((e) => e.entry.issuerId), [acme.issuerId]);
console.log("  ok  fake datum and the reference-script output are not entries");

const rotated = { ...acme, pubkey: "22".repeat(32), updatedAt: 2n };
await submit(a2, [a3], async () =>
  updateTx(lucid, reg, await findEntry(lucid, reg, acme.issuerId), rotated, { signers: [kh(a2), kh(a3)], ref }),
);
assert.deepEqual((await entries()).map((e) => e.entry), [rotated]);
console.log("  ok  admins 2+3 rotate acme's key");

const revoked = { ...rotated, status: "revoked" as const, updatedAt: 3n };
await submit(a1, [a2], async () =>
  updateTx(lucid, reg, await findEntry(lucid, reg, acme.issuerId), revoked, { signers: [kh(a1), kh(a2)], ref }),
);
assert.deepEqual((await entries()).map((e) => e.entry), [revoked]);
console.log("  ok  admins 1+2 revoke acme (entry kept, status revoked)");

await submit(a1, [a3], async () => retireTx(lucid, reg, await findEntry(lucid, reg, acme.issuerId), quorum));
assert.deepEqual(await entries(), []);
console.log("  ok  admins 1+3 retire acme (token burned)");

console.log("e2e passed");
