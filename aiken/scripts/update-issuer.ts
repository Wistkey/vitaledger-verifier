/**
 * Rotates an issuer's key, changes its kind, revokes it, or retires (removes) it.
 *   npm run update -- --env registry-admin.env --cosign admin-2.env --id vl:issuer:<slug> [--pubkey <hex>] [--kind <k>] [--revoke | --reactivate | --retire]
 */
import { parseArgs } from "node:util";
import { KINDS, adminLucid, findEntry, parseNet, retireTx, updateTx, type IssuerKind } from "./lib.js";
import { finishOrExport } from "./multisig.js";

const { values: v } = parseArgs({
  options: {
    env: { type: "string" },
    id: { type: "string" },
    pubkey: { type: "string" },
    kind: { type: "string" },
    revoke: { type: "boolean" },
    reactivate: { type: "boolean" },
    retire: { type: "boolean" },
    cosign: { type: "string", multiple: true },
    export: { type: "string" },
    cosigner: { type: "string" },
    network: { type: "string", default: "preprod" },
  },
});
if (!v.env || !v.id || (v.kind && !KINDS.includes(v.kind as IssuerKind))) {
  console.error("usage: npm run update -- --env <file> (--export <req.json> --cosigner <admin #> | --cosign <file> ...) --id vl:issuer:<slug> [--pubkey <hex>] [--kind <k>] [--revoke|--reactivate|--retire]");
  process.exit(2);
}
const net = parseNet(v.network);
const ctx = await adminLucid(net, v.env, v.cosign ?? [], { quorum: !v.export });
const current = await findEntry(ctx.lucid, ctx.reg, v.id);
const next = {
  ...current.entry,
  pubkey: v.pubkey ?? current.entry.pubkey,
  kind: (v.kind as IssuerKind | undefined) ?? current.entry.kind,
  status: v.revoke ? ("revoked" as const) : v.reactivate ? ("active" as const) : current.entry.status,
  updatedAt: BigInt(Date.now()),
};
await finishOrExport({
  ctx,
  net,
  exportPath: v.export,
  cosigner: v.cosigner,
  action: v.retire ? `retire ${v.id}` : `update ${v.id} (${next.kind}, ${next.status}, key ${next.pubkey})`,
  build: (signing) => (v.retire ? retireTx(ctx.lucid, ctx.reg, current, signing) : updateTx(ctx.lucid, ctx.reg, current, next, signing)),
});
