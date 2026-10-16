/**
 * Rotates an issuer's key, changes its kind, revokes it, or retires (removes) it.
 *   npm run update -- --env registry-admin.env --cosign admin-2.env --id vl:issuer:<slug> [--pubkey <hex>] [--kind <k>] [--revoke | --reactivate | --retire]
 */
import { parseArgs } from "node:util";
import { KINDS, adminLucid, explorer, findEntry, parseNet, retireTx, signAll, updateTx, type IssuerKind } from "./lib.js";

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
    network: { type: "string", default: "preprod" },
  },
});
if (!v.env || !v.id || (v.kind && !KINDS.includes(v.kind as IssuerKind))) {
  console.error("usage: npm run update -- --env <file> [--cosign <file> ...] --id vl:issuer:<slug> [--pubkey <hex>] [--kind <k>] [--revoke|--reactivate|--retire]");
  process.exit(2);
}
const net = parseNet(v.network);
const { lucid, reg, signing, cosignerSeeds, network } = await adminLucid(net, v.env, v.cosign ?? []);
const current = await findEntry(lucid, reg, v.id);
const tx = v.retire
  ? await retireTx(lucid, reg, current, signing)
  : await updateTx(lucid, reg, current, {
      ...current.entry,
      pubkey: v.pubkey ?? current.entry.pubkey,
      kind: (v.kind as IssuerKind | undefined) ?? current.entry.kind,
      status: v.revoke ? "revoked" : v.reactivate ? "active" : current.entry.status,
      updatedAt: BigInt(Date.now()),
    }, signing);
const hash = await (await signAll(tx, cosignerSeeds, network)).submit();
console.log(`${v.retire ? "retired" : "updated"} ${v.id}\ntx ${hash}\n${explorer(net, hash)}`);
