/**
 * Lists the genuine registry entries. Read-only, no wallet needed.
 *   npm run list -- [--network preprod]
 * Admin keys and threshold come from ../deployments/<network>.json.
 */
import { parseArgs } from "node:util";
import { Koios, Lucid } from "@lucid-evolution/lucid";
import { KOIOS, LUCID_NETWORK, findReferenceScript, genuineEntries, parseNet, readDeployment, registryFor } from "./lib.js";

const { values: v } = parseArgs({ options: { network: { type: "string", default: "preprod" } } });
const net = parseNet(v.network);
const reg = registryFor(LUCID_NETWORK[net], readDeployment(net).admins);
const lucid = await Lucid(new Koios(KOIOS[net]), LUCID_NETWORK[net]);
const utxos = await lucid.utxosAt(reg.address);
const entries = genuineEntries(reg, utxos);
const ref = await findReferenceScript(lucid, reg);
console.log(`registry ${reg.address} (policy ${reg.policyId}, ${reg.admins.required}-of-${reg.admins.keys.length} admins)`);
console.log(`reference script: ${ref ? `${ref.txHash}#${ref.outputIndex}` : "not deployed"}`);
console.log(`${entries.length} genuine entr${entries.length === 1 ? "y" : "ies"}; ${utxos.length - entries.length} other UTxO(s) at the address are not entries`);
for (const { entry, utxo } of entries) {
  console.log(`- ${entry.issuerId}  ${entry.kind}  ${entry.status}  key ${entry.pubkey}  (${utxo.txHash}#${utxo.outputIndex})`);
}
