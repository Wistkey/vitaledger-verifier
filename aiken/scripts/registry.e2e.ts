// End-to-end run of the compiled validator in Lucid Evolution's Emulator
// (real Plutus V3 evaluation, no network):  npm run e2e
import assert from "node:assert/strict";
import { Emulator, Lucid, generateEmulatorAccount, type LucidEvolution } from "@lucid-evolution/lucid";
import {
  adminKeyHashOf,
  encodeEntry,
  findEntry,
  genuineEntries,
  registerTx,
  registryFor,
  retireTx,
  updateTx,
  type IssuerEntry,
} from "./lib.js";

const admin = generateEmulatorAccount({ lovelace: 100_000_000n });
const attacker = generateEmulatorAccount({ lovelace: 100_000_000n });
const emulator = new Emulator([admin, attacker]);
const lucid = await Lucid(emulator, "Preprod");
const reg = registryFor("Preprod", adminKeyHashOf(admin.address));

async function submit(as: typeof admin, build: (l: LucidEvolution) => Promise<{ sign: { withWallet(): { complete(): Promise<{ submit(): Promise<string> }> } } }>) {
  lucid.selectWallet.fromSeed(as.seedPhrase);
  const tx = await build(lucid);
  const hash = await (await tx.sign.withWallet().complete()).submit();
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

console.log(`registry ${reg.address}\npolicy   ${reg.policyId}`);

await submit(admin, (l) => registerTx(l, reg, acme));
assert.deepEqual((await entries()).map((e) => e.entry), [acme]);
console.log("  ok  admin registers acme-foods");

await rejects("attacker registers an issuer", () =>
  submit(attacker, (l) =>
    registerTx(l, { ...reg, adminKeyHash: adminKeyHashOf(attacker.address) }, { ...acme, issuerId: "vl:issuer:evil" }),
  ),
);

await rejects("attacker rotates acme's key", () =>
  submit(attacker, async (l) =>
    updateTx(l, { ...reg, adminKeyHash: adminKeyHashOf(attacker.address) }, await findEntry(l, reg, acme.issuerId), {
      ...acme,
      pubkey: "ee".repeat(32),
    }),
  ),
);

// Anyone can pay to the script address; a fake entry without a token is ignored.
await submit(attacker, async (l) =>
  l
    .newTx()
    .pay.ToContract(reg.address, { kind: "inline", value: encodeEntry({ ...acme, issuerId: "vl:issuer:fake", pubkey: "ee".repeat(32) }) }, { lovelace: 2_000_000n })
    .complete(),
);
assert.equal((await lucid.utxosAt(reg.address)).length, 2);
assert.deepEqual((await entries()).map((e) => e.entry.issuerId), [acme.issuerId]);
console.log("  ok  fake datum at the script address is not a genuine entry");

const rotated = { ...acme, pubkey: "22".repeat(32), updatedAt: 2n };
await submit(admin, async (l) => updateTx(l, reg, await findEntry(l, reg, acme.issuerId), rotated));
assert.deepEqual((await entries()).map((e) => e.entry), [rotated]);
console.log("  ok  admin rotates acme's key");

const revoked = { ...rotated, status: "revoked" as const, updatedAt: 3n };
await submit(admin, async (l) => updateTx(l, reg, await findEntry(l, reg, acme.issuerId), revoked));
assert.deepEqual((await entries()).map((e) => e.entry), [revoked]);
console.log("  ok  admin revokes acme (entry kept, status revoked)");

await submit(admin, async (l) => retireTx(l, reg, await findEntry(l, reg, acme.issuerId)));
assert.deepEqual(await entries(), []);
console.log("  ok  admin retires acme (token burned)");

console.log("e2e passed");
