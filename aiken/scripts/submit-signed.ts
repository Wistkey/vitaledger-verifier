/**
 * Submit a registry signing request once enough admins have co-signed it.
 *   npm run submit-signed -- --request req.json [--network preprod]
 * Checks the transaction again, that at least `required` distinct admins
 * signed, then assembles and submits. Needs no recovery phrase.
 */
import { parseArgs } from "node:util";
import { Koios, Lucid } from "@lucid-evolution/lucid";
import { KOIOS, LUCID_NETWORK, explorer, parseNet, readDeployment, registryFor } from "./lib.js";
import { koiosResolver, readRequest, submitRequest } from "./multisig.js";

const { values: v } = parseArgs({ options: { request: { type: "string" }, network: { type: "string", default: "preprod" } } });
if (!v.request) {
  console.error("usage: npm run submit-signed -- --request <req.json>");
  process.exit(2);
}
const net = parseNet(v.network);
const req = readRequest(v.request);
const reg = registryFor(LUCID_NETWORK[net], readDeployment(net).admins);
const lucid = await Lucid(new Koios(KOIOS[net]), LUCID_NETWORK[net]);
const hash = await submitRequest(lucid, reg, req, LUCID_NETWORK[net], koiosResolver(KOIOS[net]));
console.log(`submitted: ${req.action}\ntx ${hash}\n${explorer(net, hash)}`);
console.log(`Record it in deployments/${net}.json ("transactions").`);
