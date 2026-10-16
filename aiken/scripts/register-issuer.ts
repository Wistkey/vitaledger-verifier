/**
 * Adds an issuer to the on-chain registry.
 *   npm run register -- --env registry-admin.env --id vl:issuer:<slug> --kind brand --pubkey <64 hex> [--network preprod]
 */
import { parseArgs } from "node:util";
import { KINDS, adminLucid, explorer, parseNet, registerTx, type IssuerKind } from "./lib.js";

const { values: v } = parseArgs({
  options: {
    env: { type: "string" },
    id: { type: "string" },
    kind: { type: "string" },
    pubkey: { type: "string" },
    network: { type: "string", default: "preprod" },
  },
});
if (!v.env || !v.id || !v.kind || !v.pubkey || !KINDS.includes(v.kind as IssuerKind)) {
  console.error(`usage: npm run register -- --env <file> --id vl:issuer:<slug> --kind ${KINDS.join("|")} --pubkey <hex>`);
  process.exit(2);
}
const net = parseNet(v.network);
const { lucid, reg } = await adminLucid(net, v.env);
const tx = await registerTx(lucid, reg, {
  issuerId: v.id,
  kind: v.kind as IssuerKind,
  pubkey: v.pubkey,
  status: "active",
  updatedAt: BigInt(Date.now()),
});
const hash = await (await tx.sign.withWallet().complete()).submit();
console.log(`registered ${v.id}\ntx ${hash}\n${explorer(net, hash)}`);
