// Registry changes signed by M of N admins on their own machines.
//
// 1. The fee-paying admin builds the transaction, signs it, and writes a
//    signing request file (`--export`). No secret is in it.
// 2. Each co-signer runs `cosign` on their own machine. It decodes the
//    transaction with vitaledger-verifier's own CBOR code (independent of
//    the Lucid builder), shows exactly what it changes, refuses anything that
//    isn't a change to our registry, and only then adds their signature.
// 3. The fee payer runs `submit-signed`: it checks the threshold, assembles
//    the signatures and submits.
import { readFileSync, writeFileSync } from "node:fs";
import { CML, getAddressDetails, walletFromSeed, type LucidEvolution, type Network, type TxSignBuilder } from "@lucid-evolution/lucid";
import { readRegistryEntry, parseTransaction, Tagged } from "vitaledger-verifier";
import { adminKeyHashOf, type Net, type Registry } from "./lib.js";

export const REQUEST_FORMAT = "vitaledger-registry-signing-request/1";

export interface SigningRequest {
  format: typeof REQUEST_FORMAT;
  network: Net;
  policyId: string;
  /** What the builder says it does; informational only, the tx itself is what gets checked. */
  action: string;
  txCbor: string;
  txHash: string;
  /** Admin payment-key hash → that admin's witness set (CBOR hex). */
  witnesses: Record<string, string>;
  createdAt: string;
}

/** How long a request stays submittable. */
export const REQUEST_TTL_MS = 24 * 60 * 60 * 1000;

export async function exportRequest(tx: TxSignBuilder, net: Net, reg: Registry, payerKeyHash: string, action: string) {
  const witness = await tx.partialSign.withWallet();
  const req: SigningRequest = {
    format: REQUEST_FORMAT,
    network: net,
    policyId: reg.policyId,
    action,
    txCbor: tx.toCBOR(),
    txHash: tx.toHash(),
    witnesses: { [payerKeyHash]: witness },
    createdAt: new Date().toISOString(),
  };
  return req;
}

export function readRequest(path: string): SigningRequest {
  const req = JSON.parse(readFileSync(path, "utf8")) as SigningRequest;
  if (req.format !== REQUEST_FORMAT) throw new Error(`${path} is not a registry signing request`);
  return req;
}

export function writeRequest(path: string, req: SigningRequest) {
  writeFileSync(path, JSON.stringify(req, null, 2) + "\n");
}

const hex = (v: unknown) => (v instanceof Uint8Array ? Buffer.from(v).toString("hex") : "");
/** Conway encodes sets as tag 258 arrays; older eras as plain arrays. */
const items = (v: unknown): unknown[] => (v instanceof Tagged ? (v.value as unknown[]) : Array.isArray(v) ? v : []);

export interface Description {
  lines: string[];
  /** Reasons to refuse signing; empty when the request is a well-formed registry change. */
  problems: string[];
  requiredSigners: string[];
}

/**
 * What the transaction does, read from its own bytes with vitaledger-verifier
 * (not from the request's `action` text), plus the current registry entries
 * it spends, resolved from the chain.
 */
/** Resolves inputs: address, assets and whether already spent. */
export type InputResolver = (refs: Array<{ txHash: string; outputIndex: number }>) => Promise<
  Array<{ txHash: string; outputIndex: number; address: string; assets: Record<string, bigint>; spent?: boolean }>
>;

/** Inputs via Lucid's provider (used with the Emulator). */
export const lucidResolver = (lucid: LucidEvolution): InputResolver => (refs) => lucid.utxosByOutRef(refs);

/** Inputs via Koios `utxo_info` (Lucid 0.6's Koios provider can't parse current tx_info responses). */
export const koiosResolver = (baseUrl: string): InputResolver => async (refs) => {
  const res = await fetch(`${baseUrl}/utxo_info`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ _utxo_refs: refs.map((r) => `${r.txHash}#${r.outputIndex}`), _extended: true }),
  });
  if (!res.ok) throw new Error(`Koios utxo_info responded ${res.status}`);
  const rows = (await res.json()) as Array<{ tx_hash: string; tx_index: number; address: string; value: string; is_spent: boolean; asset_list: Array<{ policy_id: string; asset_name: string | null; quantity: string }> }>;
  return rows.map((r) => ({
    txHash: r.tx_hash,
    outputIndex: r.tx_index,
    address: r.address,
    spent: r.is_spent,
    assets: Object.fromEntries([["lovelace", BigInt(r.value)], ...r.asset_list.map((a) => [a.policy_id + (a.asset_name ?? ""), BigInt(a.quantity)])]),
  }));
};

export async function describeRequest(lucid: LucidEvolution, reg: Registry, req: SigningRequest, network: Network, resolve: InputResolver = lucidResolver(lucid)): Promise<Description> {
  const lines: string[] = [];
  const problems: string[] = [];
  const tx = parseTransaction(req.txCbor);
  if (tx.txHash !== req.txHash) problems.push("the transaction bytes don't match the request's tx hash");
  if (req.policyId !== reg.policyId) problems.push(`the request is for policy ${req.policyId}, not our registry ${reg.policyId}`);
  const body = tx.body;

  // Registry outputs: each must be a genuine entry (token, address, datum), decoded independently.
  const outputs = items(body.get(1));
  outputs.forEach((out, i) => {
    // Legacy outputs are [address, value, …]; Babbage+ outputs are maps {0: address, 1: value, …}.
    const addr = out instanceof Map ? out.get(0) : Array.isArray(out) ? out[0] : undefined;
    const atRegistry = addr instanceof Uint8Array && ((addr[0] >> 4) & 1) === 1 && hex(addr.subarray(1, 29)) === reg.policyId;
    if (!atRegistry) {
      const value = out instanceof Map ? out.get(1) : Array.isArray(out) ? out[1] : 0;
      const coin = Array.isArray(value) ? value[0] : value;
      const payer = addr instanceof Uint8Array && hex(addr.subarray(1, 29)) === payerKeyHashOf(req) ? " (change back to the fee payer)" : "";
      lines.push(`  pays ${Number(coin) / 1e6} tADA to ${hex(addr).slice(0, 18)}…${payer}`);
      return;
    }
    try {
      const e = readRegistryEntry(req.txCbor, i, reg.policyId);
      lines.push(`  writes entry ${e.issuerId}: kind ${e.kind}, status ${e.status}, key ${e.pubkey}`);
    } catch (err) {
      problems.push(`output #${i} at the registry address is not a genuine entry: ${(err as Error).message}`);
    }
  });

  // Registry tokens minted or burned; any other policy is refused.
  const mint = body.get(9);
  if (mint instanceof Map) {
    for (const [policy, assets] of mint) {
      if (hex(policy) !== reg.policyId) problems.push(`mints or burns tokens of another policy (${hex(policy)})`);
      else if (assets instanceof Map) for (const [name, qty] of assets) lines.push(`  ${Number(qty) > 0 ? "mints" : "burns"} registry token ${hex(name).slice(0, 16)}…`);
    }
  }

  // Inputs: show registry entries being changed; resolve every input so nothing unexpected is spent.
  const list = items(body.get(0)) as Array<[Uint8Array, number]>;
  const utxos = await resolve(list.map(([h, i]) => ({ txHash: hex(h), outputIndex: Number(i) })));
  for (const u of utxos) if (u.spent) problems.push(`input ${u.txHash.slice(0, 16)}…#${u.outputIndex} is already spent (request out of date)`);
  for (const u of utxos) {
    const isRegistry = Object.keys(u.assets).some((unit) => unit.startsWith(reg.policyId));
    if (isRegistry) lines.push(`  replaces the current entry at ${u.txHash.slice(0, 16)}…#${u.outputIndex}`);
    else if (u.address === reg.address) lines.push(`  sweeps a non-entry UTxO at the registry address (${Number(u.assets.lovelace) / 1e6} tADA)`);
    else lines.push(`  spends ${Number(u.assets.lovelace) / 1e6} tADA from ${u.address.slice(0, 20)}…`);
  }
  if (utxos.length !== list.length) problems.push("some inputs could not be found on chain (already spent? request too old?)");

  const required = items(body.get(14)).map(hex).sort((x, y) => reg.admins.keys.indexOf(x) - reg.admins.keys.indexOf(y));
  const fee = Number(body.get(2) ?? 0);
  const ttl = body.get(3);
  lines.push(`  fee ${fee / 1e6} tADA` + (ttl !== undefined ? `; valid until ${new Date(lucid.slotToUnixTime(Number(ttl))).toISOString()}` : "; no expiry"));
  lines.push(`  needs signatures from: ${required.map((k) => (reg.admins.keys.includes(k) ? `admin ${reg.admins.keys.indexOf(k) + 1}` : `NOT AN ADMIN ${k}`)).join(", ")}`);
  for (const k of required) if (!reg.admins.keys.includes(k)) problems.push(`requires a signature from a non-admin key ${k}`);
  return { lines, problems, requiredSigners: required };
}

/** The admin whose signature the request already carries (the fee payer who built it). */
const payerKeyHashOf = (req: SigningRequest) => Object.keys(req.witnesses)[0];

/** Adds this admin's signature to the request (after the caller has shown and confirmed the description). */
export async function cosignRequest(lucid: LucidEvolution, req: SigningRequest, seed: string, network: Network, desc: Description) {
  const { address, paymentKey } = walletFromSeed(seed, { network });
  const me = adminKeyHashOf(address);
  if (!desc.requiredSigners.includes(me)) throw new Error("this transaction doesn't ask for your signature");
  if (desc.problems.length) throw new Error(`refusing to sign: ${desc.problems.join("; ")}`);
  const witness = await lucid.fromTx(req.txCbor).partialSign.withPrivateKey(paymentKey);
  return { ...req, witnesses: { ...req.witnesses, [me]: witness } };
}

/** Assembles the collected signatures and submits, once enough distinct admins have signed. */
export async function submitRequest(lucid: LucidEvolution, reg: Registry, req: SigningRequest, network: Network, resolve?: InputResolver) {
  const desc = await describeRequest(lucid, reg, req, network, resolve);
  if (desc.problems.length) throw new Error(`refusing to submit: ${desc.problems.join("; ")}`);
  const signed = Object.keys(req.witnesses).filter((k) => reg.admins.keys.includes(k));
  const missing = desc.requiredSigners.filter((k) => !req.witnesses[k]);
  if (new Set(signed).size < reg.admins.required || missing.length) {
    throw new Error(`${new Set(signed).size} of ${reg.admins.required} admin signatures; still missing: ${missing.join(", ") || "none"}`);
  }
  const assembled = assembleTx(req.txCbor, Object.values(req.witnesses));
  // Adding witnesses must not change the body: the tx id everyone reviewed must be the one submitted.
  if (parseTransaction(assembled).txHash !== req.txHash) throw new Error("assembling changed the transaction id; not submitting");
  return lucid.config().provider!.submitTx(assembled);
}

/** Adds the collected vkey witnesses to the transaction. Needs no wallet or recovery phrase. */
export function assembleTx(txCbor: string, witnessSets: string[]): string {
  const tx = CML.Transaction.from_cbor_hex(txCbor);
  const ws = tx.witness_set();
  const vkeys = ws.vkeywitnesses() ?? CML.VkeywitnessList.new();
  for (const w of witnessSets) {
    const list = CML.TransactionWitnessSet.from_cbor_hex(w).vkeywitnesses();
    if (list) for (let i = 0; i < list.len(); i++) vkeys.add(list.get(i));
  }
  ws.set_vkeywitnesses(vkeys);
  return CML.Transaction.new(tx.body(), ws, tx.is_valid(), tx.auxiliary_data()).to_cbor_hex();
}

/** Admin key hash for `--cosigner`: a 1-based index into the deployment's admins, or a key hash. */
export function cosignerKeyHash(reg: Registry, value: string): string {
  if (/^[1-9]$/.test(value)) {
    const k = reg.admins.keys[Number(value) - 1];
    if (!k) throw new Error(`there is no admin ${value}`);
    return k;
  }
  if (!reg.admins.keys.includes(value)) throw new Error(`${value} is not a registry admin key hash`);
  return value;
}

export const keyHashOfAddress = (addr: string) => getAddressDetails(addr).paymentCredential!.hash;

/**
 * Shared by register / update: with `--export <file>`, build for the fee
 * payer plus one co-signer, sign as the fee payer and write a signing
 * request; otherwise sign with every local key and submit (one machine).
 */
export async function finishOrExport(opts: {
  build: (signing: import("./lib.js").Signing) => Promise<TxSignBuilder>;
  action: string;
  ctx: Awaited<ReturnType<typeof import("./lib.js").adminLucid>>;
  net: Net;
  exportPath?: string;
  cosigner?: string;
}) {
  const { ctx, net } = opts;
  if (!opts.exportPath) {
    const { signAll, explorer } = await import("./lib.js");
    const tx = await opts.build(ctx.signing);
    const hash = await (await signAll(tx, ctx.cosignerSeeds, ctx.network)).submit();
    console.log(`${opts.action}\ntx ${hash}\n${explorer(net, hash)}`);
    return;
  }
  const me = ctx.signing.signers[0];
  const signers = ctx.reg.admins.required > 1 ? [me, cosignerKeyHash(ctx.reg, opts.cosigner ?? "")] : [me];
  if (new Set(signers).size !== signers.length) throw new Error("the co-signer must be a different admin");
  const tx = await opts.build({ signers, ref: ctx.signing.ref, validTo: Date.now() + REQUEST_TTL_MS });
  writeRequest(opts.exportPath, await exportRequest(tx, net, ctx.reg, me, opts.action));
  const who = ctx.reg.admins.keys.indexOf(signers[1]) + 1;
  console.log(`wrote ${opts.exportPath}: ${opts.action}, signed by you, valid for 24 hours.`);
  console.log(`Send it to admin ${who}. They run: npm run cosign -- --env <their env> --request ${opts.exportPath}`);
  console.log(`then send it back, and you run: npm run submit-signed -- --request ${opts.exportPath}`);
}
