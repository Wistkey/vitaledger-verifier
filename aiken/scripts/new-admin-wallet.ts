/**
 * Creates the registry admin wallet (a new wallet: not the anchor or spike wallet).
 *   npm run new-admin-wallet -- --out registry-admin.env [--network preprod]
 * Writes `REGISTRY_ADMIN_MNEMONIC=<24 words>` to an owner-only file and prints
 * only the address to fund and the admin key hash the validator is applied to.
 */
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { generateSeedPhrase, walletFromSeed } from "@lucid-evolution/lucid";
import { LUCID_NETWORK, MNEMONIC_VAR, adminKeyHashOf, parseNet, registryFor } from "./lib.js";

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
const reg = registryFor(LUCID_NETWORK[net], adminKeyHashOf(address));
console.log(`Wrote ${values.out} (mode 600). Back it up in your password manager; never commit or email it.`);
console.log(`admin address (${net}): ${address}`);
console.log(`admin key hash:  ${reg.adminKeyHash}`);
console.log(`registry address: ${reg.address}`);
console.log(`registry policy:  ${reg.policyId}`);
console.log("Fund the admin address from the faucet: https://docs.cardano.org/cardano-testnets/tools/faucet");
