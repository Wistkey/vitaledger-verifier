/**
 * Creates one registry admin wallet (a new wallet: not the anchor or spike wallet).
 * Run once per admin; put each key hash in deployments/<network>.json `admins.keys`.
 *   npm run new-admin-wallet -- --out registry-admin.env [--network preprod]
 * Writes `REGISTRY_ADMIN_MNEMONIC=<24 words>` to an owner-only file and prints
 * only the address and the admin key hash. Only the fee-paying admin needs tADA.
 */
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { generateSeedPhrase, walletFromSeed } from "@lucid-evolution/lucid";
import { LUCID_NETWORK, MNEMONIC_VAR, adminKeyHashOf, parseNet } from "./lib.js";

const { values } = parseArgs({ options: { out: { type: "string" }, network: { type: "string", default: "preprod" } } });
if (!values.out) {
  console.error("usage: npm run new-admin-wallet -- --out <registry-admin.env> [--network preprod|preview]");
  process.exit(2);
}
const net = parseNet(values.network);
const seed = generateSeedPhrase();
const { address } = walletFromSeed(seed, { network: LUCID_NETWORK[net] });
// flag "wx": never overwrite an existing wallet file.
writeFileSync(values.out, `${MNEMONIC_VAR}=${seed}\n`, { mode: 0o600, flag: "wx" });
console.log(`Wrote ${values.out} (mode 600). Back it up in your password manager; never commit or email it.`);
console.log(`admin address (${net}): ${address}`);
console.log(`admin key hash: ${adminKeyHashOf(address)}`);
console.log("If this admin pays fees, fund it from the faucet: https://docs.cardano.org/cardano-testnets/tools/faucet");
