/**
 * Adds an issuer to the on-chain registry.
 *   Admins on different machines (the normal case):
 *     npm run register -- --env admin-1.env --export req.json --cosigner 2 --id vl:issuer:<slug> --kind brand --pubkey <64 hex>
 *     then the co-signer runs `npm run cosign`, and you run `npm run submit-signed` (multisig.ts).
 *   All keys on one machine (tests, rehearsal):
 *     npm run register -- --env admin-1.env --cosign admin-2.env --id … --kind … --pubkey …
 */
import { parseArgs } from "node:util";
import { KINDS, adminLucid, parseNet, registerTx, type IssuerKind } from "./lib.js";
import { finishOrExport } from "./multisig.js";

const { values: v } = parseArgs({
  options: {
    env: { type: "string" },
    id: { type: "string" },
    kind: { type: "string" },
    pubkey: { type: "string" },
    cosign: { type: "string", multiple: true },
    export: { type: "string" },
    cosigner: { type: "string" },
    network: { type: "string", default: "preprod" },
  },
});
if (!v.env || !v.id || !v.kind || !v.pubkey || !KINDS.includes(v.kind as IssuerKind)) {
  console.error(`usage: npm run register -- --env <file> (--export <req.json> --cosigner <admin #> | --cosign <file> ...) --id vl:issuer:<slug> --kind ${KINDS.join("|")} --pubkey <hex>`);
  process.exit(2);
}
const net = parseNet(v.network);
const ctx = await adminLucid(net, v.env, v.cosign ?? [], { quorum: !v.export });
const entry = { issuerId: v.id, kind: v.kind as IssuerKind, pubkey: v.pubkey, status: "active" as const, updatedAt: BigInt(Date.now()) };
await finishOrExport({
  ctx,
  net,
  exportPath: v.export,
  cosigner: v.cosigner,
  action: `register ${v.id} (${v.kind}, key ${v.pubkey})`,
  build: (signing) => registerTx(ctx.lucid, ctx.reg, entry, signing),
});
