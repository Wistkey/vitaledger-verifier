/**
 * Adds an issuer to the on-chain registry.
 *   npm run register -- --env registry-admin.env --cosign admin-2.env --id vl:issuer:<slug> --kind brand --pubkey <64 hex> [--network preprod]
 */
import { parseArgs } from "node:util";
import { KINDS, adminLucid, explorer, parseNet, registerTx, signAll, type IssuerKind } from "./lib.js";

const { values: v } = parseArgs({
  options: {
    env: { type: "string" },
    id: { type: "string" },
    kind: { type: "string" },
    pubkey: { type: "string" },
    cosign: { type: "string", multiple: true },
    network: { type: "string", default: "preprod" },
  },
});
if (!v.env || !v.id || !v.kind || !v.pubkey || !KINDS.includes(v.kind as IssuerKind)) {
  console.error(`usage: npm run register -- --env <file> [--cosign <file> ...] --id vl:issuer:<slug> --kind ${KINDS.join("|")} --pubkey <hex>`);
  process.exit(2);
}
const net = parseNet(v.network);
const { lucid, reg, signing, cosignerSeeds, network } = await adminLucid(net, v.env, v.cosign ?? []);
const tx = await registerTx(lucid, reg, {
  issuerId: v.id,
  kind: v.kind as IssuerKind,
  pubkey: v.pubkey,
  status: "active",
  updatedAt: BigInt(Date.now()),
}, signing);
const hash = await (await signAll(tx, cosignerSeeds, network)).submit();
console.log(`registered ${v.id}\ntx ${hash}\n${explorer(net, hash)}`);
