import assert from "node:assert/strict";
import {
  Blockfrost,
  Lucid,
  SLOT_CONFIG_NETWORK,
  walletFromSeed,
  type Network,
  type TxSignBuilder,
} from "@lucid-evolution/lucid";
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

const storeUrl = (process.env.YACI_STORE_URL ?? "http://127.0.0.1:8080/api/v1").replace(/\/$/, "");
const adminUrl = (process.env.YACI_ADMIN_URL ?? "http://127.0.0.1:10000/local-cluster/api/admin").replace(/\/$/, "");
for (const url of [storeUrl, adminUrl]) {
  const parsed = new URL(url);
  assert.ok(parsed.protocol === "http:" && ["127.0.0.1", "localhost"].includes(parsed.hostname), "Yaci endpoints must be local");
}
const seed = `${Array(23).fill("test").join(" ")} sauce`;
const network: Network = "Custom";
const accounts = [0, 1, 2, 3];
const [a1, a2, a3, attacker] = accounts;

const adminAddress = (accountIndex: number) => walletFromSeed(seed, { network, accountIndex }).address;
const kh = (accountIndex: number) => adminKeyHashOf(adminAddress(accountIndex));

const ready = async () => {
  for (let attempt = 0; attempt < 240; attempt++) {
    try {
      if ((await fetch(`${storeUrl}/network`)).ok) return;
    } catch {
      // Yaci Store starts after the node and admin API.
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("Yaci Store is not ready; run npm run yaci:up first");
};
await ready();
const shelley = await fetch(`${adminUrl}/devnet/genesis/shelley`).then(async (res) => {
  assert.ok(res.ok, `Yaci admin responded ${res.status}`);
  return res.json();
});
SLOT_CONFIG_NETWORK.Custom = {
  zeroTime: new Date(shelley.systemStart).getTime(),
  slotLength: shelley.slotLength * 1000,
  zeroSlot: 0,
};
const plainFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const response = await plainFetch(input, init);
  const path = input instanceof Request ? input.url : String(input);
  if (!response.ok || !path.endsWith("/cbor") || !response.headers.get("content-type")?.includes("application/octet-stream")) {
    return response;
  }
  const cbor = Buffer.from(await response.arrayBuffer()).toString("hex");
  return Response.json({ cbor });
};

const lucid = await Lucid(new Blockfrost(storeUrl, "yaci-devkit"), network);
const reg = registryFor(network, { keys: [kh(a1), kh(a2), kh(a3)], required: 2 });
assert.deepEqual(await lucid.utxosAt(reg.address), [], "run the registry scenario on a fresh Yaci devnet");

async function submit(payer: number, cosigners: number[], build: () => Promise<TxSignBuilder>) {
  lucid.selectWallet.fromSeed(seed, { accountIndex: payer });
  const tx = await build();
  let signed = tx.sign.withWallet();
  for (const accountIndex of cosigners) {
    signed = signed.sign.withPrivateKey(walletFromSeed(seed, { network, accountIndex }).paymentKey);
  }
  const complete = await signed.complete();
  const hash = await complete.submit();
  assert.ok(await lucid.awaitTx(hash), `transaction ${hash} was not indexed`);
  return hash;
}

async function rejects(what: string, fn: () => Promise<unknown>) {
  const err = await fn().then(
    () => null,
    (e: unknown) => String((e as Error)?.message ?? e),
  );
  assert.ok(err, `${what} should be rejected`);
  assert.match(err, /failed script execution (Mint|Spend)|Scripts? (failed|failure)|Redeemer.*failed/i, `${what}: unexpected error ${err}`);
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

console.log(`registry ${reg.address}\npolicy   ${reg.policyId} (2-of-3 admins on Yaci)`);
await submit(a1, [], () => deployReferenceScriptTx(lucid, reg));
const ref = await findReferenceScript(lucid, reg);
assert.ok(ref, "reference script UTxO");
const quorum: Signing = { signers: [kh(a1), kh(a3)], ref };
console.log(`  ok  reference script at ${ref.txHash}#${ref.outputIndex}`);

lucid.selectWallet.fromSeed(seed, { accountIndex: a1 });
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
assert.equal((await lucid.utxosAt(reg.address)).length, 3);
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
console.log("Yaci registry e2e passed");
