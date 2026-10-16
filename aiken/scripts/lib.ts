// Shared off-chain helpers for the Aiken issuer registry (prototype).
// Mirrors the on-chain types in ../lib/vitaledger/registry.ak.
import { readFileSync } from "node:fs";
import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  Constr,
  Data,
  Koios,
  Lucid,
  applyDoubleCborEncoding,
  applyParamsToScript,
  fromText,
  mintingPolicyToId,
  paymentCredentialOf,
  toText,
  validatorToAddress,
  type LucidEvolution,
  type Network,
  type Script,
  type UTxO,
} from "@lucid-evolution/lucid";

const BLUEPRINT = new URL("../plutus.json", import.meta.url);

export const KOIOS = {
  preprod: "https://preprod.koios.rest/api/v1",
  preview: "https://preview.koios.rest/api/v1",
} as const;
export const LUCID_NETWORK = { preprod: "Preprod", preview: "Preview" } as const;
export type Net = keyof typeof KOIOS;

export const KINDS = ["brand", "lab", "certifier", "recall_authority"] as const;
export type IssuerKind = (typeof KINDS)[number];
export const STATUSES = ["active", "revoked"] as const;
export type IssuerStatus = (typeof STATUSES)[number];

export interface IssuerEntry {
  issuerId: string; // "vl:issuer:<slug>"
  kind: IssuerKind;
  pubkey: string; // 64 hex chars, raw Ed25519 public key
  status: IssuerStatus;
  updatedAt: bigint; // POSIX ms
}

// Redeemers: constructor index follows declaration order in registry.ak.
export const Register = Data.to(new Constr(0, []));
export const Remove = Data.to(new Constr(1, []));
export const Update = Data.to(new Constr(0, []));
export const Retire = Data.to(new Constr(1, []));

export function encodeEntry(e: IssuerEntry): string {
  return Data.to(
    new Constr(0, [
      fromText(e.issuerId),
      new Constr(KINDS.indexOf(e.kind), []),
      e.pubkey.toLowerCase(),
      new Constr(STATUSES.indexOf(e.status), []),
      e.updatedAt,
    ]),
  );
}

/** Decodes an inline datum; returns null for anything that is not a well-formed entry. */
export function decodeEntry(datumCbor: string): IssuerEntry | null {
  try {
    const d = Data.from(datumCbor) as Constr<unknown>;
    if (!(d instanceof Constr) || d.index !== 0 || d.fields.length !== 5) return null;
    const [id, kind, pubkey, status, updatedAt] = d.fields as [string, Constr<unknown>, string, Constr<unknown>, bigint];
    const k = KINDS[kind.index];
    const s = STATUSES[status.index];
    if (!k || !s || typeof id !== "string" || typeof pubkey !== "string" || typeof updatedAt !== "bigint") return null;
    return { issuerId: toText(id), kind: k, pubkey, status: s, updatedAt };
  } catch {
    return null;
  }
}

/** Asset name of an issuer's registry token: blake2b-224 of the UTF-8 issuer id. */
export function tokenName(issuerId: string): string {
  return bytesToHex(blake2b(new TextEncoder().encode(issuerId), { dkLen: 28 }));
}

export function checkEntry(e: IssuerEntry): void {
  const len = new TextEncoder().encode(e.issuerId).length;
  if (!e.issuerId.startsWith("vl:issuer:") || len <= 10 || len > 64) {
    throw new Error(`issuer id must be "vl:issuer:<slug>", at most 64 bytes: ${e.issuerId}`);
  }
  if (!/^[0-9a-f]{64}$/i.test(e.pubkey)) throw new Error("pubkey must be 64 hex chars (raw Ed25519 key)");
  if (!KINDS.includes(e.kind)) throw new Error(`kind must be one of ${KINDS.join(", ")}`);
}

export interface Registry {
  script: Script;
  policyId: string;
  address: string;
  adminKeyHash: string;
}

/** The registry validator with the admin key hash applied. */
export function registryFor(network: Network, adminKeyHash: string): Registry {
  const blueprint = JSON.parse(readFileSync(BLUEPRINT, "utf8")) as {
    validators: Array<{ title: string; compiledCode: string }>;
  };
  const v = blueprint.validators.find((x) => x.title === "registry.issuer_registry.spend");
  if (!v) throw new Error("plutus.json has no registry.issuer_registry validator; run `aiken build`");
  const script: Script = {
    type: "PlutusV3",
    script: applyParamsToScript(applyDoubleCborEncoding(v.compiledCode), [adminKeyHash]),
  };
  return { script, policyId: mintingPolicyToId(script), address: validatorToAddress(network, script), adminKeyHash };
}

export function adminKeyHashOf(address: string): string {
  return paymentCredentialOf(address).hash;
}

export interface RegistryUtxo {
  utxo: UTxO;
  entry: IssuerEntry;
}

/**
 * Genuine entries only: UTxOs at the registry address that hold exactly one
 * registry token whose name matches the issuer id in a well-formed datum.
 * Anyone can send outputs to the script address; those without a token are ignored.
 */
export function genuineEntries(reg: Registry, utxos: UTxO[]): RegistryUtxo[] {
  const out: RegistryUtxo[] = [];
  for (const utxo of utxos) {
    const ours = Object.entries(utxo.assets).filter(([unit]) => unit.startsWith(reg.policyId));
    if (ours.length !== 1 || ours[0][1] !== 1n || !utxo.datum) continue;
    const entry = decodeEntry(utxo.datum);
    if (entry && ours[0][0] === reg.policyId + tokenName(entry.issuerId)) out.push({ utxo, entry });
  }
  return out;
}

export async function findEntry(lucid: LucidEvolution, reg: Registry, issuerId: string): Promise<RegistryUtxo> {
  const found = genuineEntries(reg, await lucid.utxosAt(reg.address)).find((e) => e.entry.issuerId === issuerId);
  if (!found) throw new Error(`${issuerId} is not in the registry at ${reg.address}`);
  return found;
}

// ---- Transactions (each needs the admin wallet selected) -------------------

export async function registerTx(lucid: LucidEvolution, reg: Registry, entry: IssuerEntry) {
  checkEntry(entry);
  const unit = reg.policyId + tokenName(entry.issuerId);
  return lucid
    .newTx()
    .mintAssets({ [unit]: 1n }, Register)
    .attach.MintingPolicy(reg.script)
    .pay.ToContract(reg.address, { kind: "inline", value: encodeEntry(entry) }, { [unit]: 1n })
    .addSignerKey(reg.adminKeyHash)
    .complete();
}

export async function updateTx(lucid: LucidEvolution, reg: Registry, current: RegistryUtxo, next: IssuerEntry) {
  checkEntry(next);
  if (next.issuerId !== current.entry.issuerId) throw new Error("issuer id cannot change");
  const unit = reg.policyId + tokenName(next.issuerId);
  return lucid
    .newTx()
    .collectFrom([current.utxo], Update)
    .attach.SpendingValidator(reg.script)
    .pay.ToContract(reg.address, { kind: "inline", value: encodeEntry(next) }, { [unit]: 1n })
    .addSignerKey(reg.adminKeyHash)
    .complete();
}

export async function retireTx(lucid: LucidEvolution, reg: Registry, current: RegistryUtxo) {
  const unit = reg.policyId + tokenName(current.entry.issuerId);
  return lucid
    .newTx()
    .collectFrom([current.utxo], Retire)
    .mintAssets({ [unit]: -1n }, Remove)
    .attach.SpendingValidator(reg.script)
    .addSignerKey(reg.adminKeyHash)
    .complete();
}

// ---- CLI plumbing ----------------------------------------------------------

export const MNEMONIC_VAR = "REGISTRY_ADMIN_MNEMONIC";

export function readMnemonic(envFile: string): string {
  const line = readFileSync(envFile, "utf8")
    .split("\n")
    .find((l) => l.startsWith(`${MNEMONIC_VAR}=`));
  if (!line) throw new Error(`${envFile} has no ${MNEMONIC_VAR} line`);
  return line.slice(MNEMONIC_VAR.length + 1).trim();
}

export async function adminLucid(net: Net, envFile: string) {
  const lucid = await Lucid(new Koios(KOIOS[net]), LUCID_NETWORK[net]);
  lucid.selectWallet.fromSeed(readMnemonic(envFile));
  const reg = registryFor(LUCID_NETWORK[net], adminKeyHashOf(await lucid.wallet().address()));
  return { lucid, reg };
}

export function parseNet(value: string | undefined): Net {
  if (value !== "preprod" && value !== "preview") throw new Error("--network must be preprod or preview");
  return value;
}

export function explorer(net: Net, txHash: string): string {
  return `https://${net}.cardanoscan.io/transaction/${txHash}`;
}
