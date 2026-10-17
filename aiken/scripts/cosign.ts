/**
 * Co-sign a registry signing request on your own machine.
 *   npm run cosign -- --env <your admin env> --request req.json [--network preprod] [--yes]
 * Decodes the transaction itself (not the request's description), shows what
 * it changes, refuses anything that isn't a change to our registry, and asks
 * you to confirm before adding your signature to the file. Your recovery
 * phrase never leaves this machine; send the file back to the fee payer.
 */
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { Koios, Lucid } from "@lucid-evolution/lucid";
import { KOIOS, LUCID_NETWORK, parseNet, readDeployment, readMnemonic, registryFor } from "./lib.js";
import { cosignRequest, describeRequest, koiosResolver, readRequest, writeRequest } from "./multisig.js";

const { values: v } = parseArgs({
  options: { env: { type: "string" }, request: { type: "string" }, network: { type: "string", default: "preprod" }, yes: { type: "boolean", default: false } },
});
if (!v.env || !v.request) {
  console.error("usage: npm run cosign -- --env <your admin env> --request <req.json> [--yes]");
  process.exit(2);
}
const net = parseNet(v.network);
const req = readRequest(v.request);
if (req.network !== net) throw new Error(`the request is for ${req.network}, not ${net}`);
const reg = registryFor(LUCID_NETWORK[net], readDeployment(net).admins);
const lucid = await Lucid(new Koios(KOIOS[net]), LUCID_NETWORK[net]);
const desc = await describeRequest(lucid, reg, req, LUCID_NETWORK[net], koiosResolver(KOIOS[net]));
console.log(`Request: "${req.action}" (tx ${req.txHash.slice(0, 16)}…, created ${req.createdAt})`);
console.log("What the transaction itself does:");
for (const l of desc.lines) console.log(l);
if (desc.problems.length) {
  console.error("\nREFUSED, not signing:");
  for (const p of desc.problems) console.error(`  ✗ ${p}`);
  process.exit(1);
}
if (!v.yes) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question("\nSign this? Type yes to sign: ");
  rl.close();
  if (answer.trim().toLowerCase() !== "yes") {
    console.log("Not signed.");
    process.exit(1);
  }
}
writeRequest(v.request, await cosignRequest(lucid, req, readMnemonic(v.env), LUCID_NETWORK[net], desc));
console.log(`Signed. Send ${v.request} back to the fee payer (it contains signatures only, no secrets).`);
