/**
 * Lists the genuine registry entries. Read-only, no wallet needed.
 *   npm run list -- [--network preprod] [--admin <key hash>]
 * The admin key hash defaults to the one in ../deployments/<network>.json.
 */
import { existsSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { Koios, Lucid } from "@lucid-evolution/lucid";
import { KOIOS, LUCID_NETWORK, genuineEntries, parseNet, registryFor } from "./lib.js";

const { values: v } = parseArgs({ options: { network: { type: "string", default: "preprod" }, admin: { type: "string" } } });
const net = parseNet(v.network);
const deployment = new URL(`../deployments/${net}.json`, import.meta.url);
const admin = v.admin ?? (existsSync(deployment) ? JSON.parse(readFileSync(deployment, "utf8")).adminKeyHash : undefined);
if (!admin) {
  console.error(`no --admin given and no deployments/${net}.json`);
  process.exit(2);
}
const reg = registryFor(LUCID_NETWORK[net], admin);
const lucid = await Lucid(new Koios(KOIOS[net]), LUCID_NETWORK[net]);
const utxos = await lucid.utxosAt(reg.address);
const entries = genuineEntries(reg, utxos);
console.log(`registry ${reg.address} (policy ${reg.policyId})`);
console.log(`${entries.length} genuine entr${entries.length === 1 ? "y" : "ies"}; ${utxos.length - entries.length} other UTxO(s) at the address ignored`);
for (const { entry, utxo } of entries) {
  console.log(`- ${entry.issuerId}  ${entry.kind}  ${entry.status}  key ${entry.pubkey}  (${utxo.txHash}#${utxo.outputIndex})`);
}
