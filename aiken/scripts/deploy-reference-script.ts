/**
 * Publishes the registry script once as a CIP-33 reference script, so later
 * registry transactions read it from chain instead of carrying ~1.6 kB each.
 *   npm run deploy-ref -- --env registry-admin.env [--network preprod]
 */
import { parseArgs } from "node:util";
import { adminLucid, deployReferenceScriptTx, explorer, findReferenceScript, parseNet } from "./lib.js";

const { values: v } = parseArgs({ options: { env: { type: "string" }, network: { type: "string", default: "preprod" } } });
if (!v.env) {
  console.error("usage: npm run deploy-ref -- --env <file> [--network preprod|preview]");
  process.exit(2);
}
const net = parseNet(v.network);
// Publishing the script needs no admin quorum: it is a plain payment.
const { lucid, reg } = await adminLucid(net, v.env, [], { quorum: false });
const existing = await findReferenceScript(lucid, reg);
if (existing) {
  console.log(`already deployed: ${existing.txHash}#${existing.outputIndex}`);
  process.exit(0);
}
const tx = await deployReferenceScriptTx(lucid, reg);
const hash = await (await tx.sign.withWallet().complete()).submit();
console.log(`reference script tx ${hash} (output #0)\n${explorer(net, hash)}`);
console.log(`record "referenceScript": "${hash}#0" in deployments/${net}.json`);
