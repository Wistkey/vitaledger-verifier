/**
 * Reads the on-chain issuer registry (aiken/, prototype) and checks a
 * record's issuer against it. Non-normative: v1 verification (SPEC §§4–6)
 * does not depend on this module.
 *
 * Trust: the entry is decoded from the raw CBOR of the transaction that
 * created it, checked against its transaction id like an anchor (tx.ts), and
 * that transaction can be certified with Mithril. The indexer is trusted only
 * to say which UTxO currently holds the issuer's registry token.
 */
import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { type CborValue, decode, Tagged } from "./cbor.js";
import type { ChainProvider, Network } from "./chain.js";
import { verifyMessageSignature } from "./cip8.js";
import { signedMessage } from "./signed-message.js";
import { parseTransaction } from "./tx.js";

/** Registry deployments: the policy id is the registry validator's script hash. */
export const REGISTRY: Partial<Record<Network, { policyId: string }>> = {
  preprod: { policyId: "b8645dd4274ef31a6ebe2cd0711a5eceeda5b7ba4ad4a2b5ab3d10a0" },
};

// Same order as IssuerKind / IssuerStatus in aiken/lib/vitaledger/registry.ak.
export const REGISTRY_KINDS = ["brand", "lab", "certifier", "recall_authority", "vitaledger"] as const;
export type RegistryKind = (typeof REGISTRY_KINDS)[number];

export interface RegistryEntry {
  issuerId: string;
  kind: RegistryKind;
  /** Raw Ed25519 public key, 64 lowercase hex. */
  pubkey: string;
  status: "active" | "revoked";
  /** POSIX ms, set by the admins. */
  updatedAt: bigint;
  txHash: string;
  outputIndex: number;
}

export class RegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryError";
  }
}

/** Asset name of an issuer's registry token: blake2b-224 of the UTF-8 issuer id. */
export function registryTokenName(issuerId: string): string {
  return bytesToHex(blake2b(new TextEncoder().encode(issuerId), { dkLen: 28 }));
}

const hex = (v: CborValue) => (v instanceof Uint8Array ? bytesToHex(v) : undefined);

/** Plutus data constructor `n` is CBOR tag 121 + n (n < 7). */
function constr(v: CborValue): { index: number; fields: CborValue[] } | undefined {
  if (!(v instanceof Tagged) || v.tag < 121 || v.tag > 127 || !Array.isArray(v.value)) return undefined;
  return { index: v.tag - 121, fields: v.value };
}

/** The registry tokens of `policyId` in a CBOR value (coin, or [coin, multiasset]). */
function tokensOf(value: CborValue, policyId: string): Array<[string, bigint]> {
  if (!Array.isArray(value)) return [];
  const multiasset = value[1];
  if (!(multiasset instanceof Map)) return [];
  for (const [policy, assets] of multiasset) {
    if (hex(policy) !== policyId || !(assets instanceof Map)) continue;
    return [...assets].map(([name, qty]) => [hex(name) ?? "", BigInt(qty as number | bigint)]);
  }
  return [];
}

/**
 * Decodes and validates registry entry `outputIndex` of a transaction, from
 * its raw CBOR. Throws a RegistryError unless it is a genuine entry: at the
 * registry script address, holding exactly one registry token whose name is
 * bound to the issuer id, with a well-formed inline `IssuerEntry` datum.
 */
export function readRegistryEntry(txCborHex: string, outputIndex: number, policyId: string): RegistryEntry {
  const tx = parseTransaction(txCborHex);
  if (!tx.isValid) throw new RegistryError("transaction failed validation");
  const outputs = tx.body.get(1);
  if (!Array.isArray(outputs) || !outputs[outputIndex]) throw new RegistryError(`no output #${outputIndex}`);
  const output = outputs[outputIndex];
  // Babbage+ outputs are maps {0: address, 1: value, 2: datum option}; legacy arrays cannot carry inline datums.
  if (!(output instanceof Map)) throw new RegistryError("output has no inline datum");

  const address = output.get(0);
  if (!(address instanceof Uint8Array) || address.length < 29) throw new RegistryError("bad address");
  // Header types 1, 3, 5, 7 have a script payment credential (CIP-19).
  if (((address[0] >> 4) & 1) !== 1 || bytesToHex(address.subarray(1, 29)) !== policyId) {
    throw new RegistryError("output is not at the registry script address");
  }

  const tokens = tokensOf(output.get(1), policyId);
  if (tokens.length !== 1 || tokens[0][1] !== 1n) throw new RegistryError("output does not hold exactly one registry token");

  const datumOption = output.get(2);
  if (!Array.isArray(datumOption) || datumOption[0] !== 1) throw new RegistryError("output has no inline datum");
  const wrapped = datumOption[1];
  if (!(wrapped instanceof Tagged) || wrapped.tag !== 24 || !(wrapped.value instanceof Uint8Array)) {
    throw new RegistryError("bad inline datum encoding");
  }
  const entry = constr(decode(wrapped.value));
  if (!entry || entry.index !== 0 || entry.fields.length !== 5) throw new RegistryError("datum is not an IssuerEntry");
  const [id, kind, pubkey, status, updatedAt] = entry.fields;
  const k = constr(kind);
  const s = constr(status);
  if (!(id instanceof Uint8Array) || !(pubkey instanceof Uint8Array) || pubkey.length !== 32 || !k || !s) {
    throw new RegistryError("malformed IssuerEntry");
  }
  if (typeof updatedAt !== "number" && typeof updatedAt !== "bigint") throw new RegistryError("malformed IssuerEntry");
  const issuerId = new TextDecoder("utf-8", { fatal: true }).decode(id);
  if (!issuerId.startsWith("vl:issuer:") || id.length <= 10 || id.length > 64) throw new RegistryError("bad issuer id");
  if (tokens[0][0] !== registryTokenName(issuerId)) throw new RegistryError("token name is not bound to the issuer id");
  const kindName = REGISTRY_KINDS[k.index];
  if (!kindName || s.index > 1) throw new RegistryError("unknown kind or status");

  return {
    issuerId,
    kind: kindName,
    pubkey: bytesToHex(pubkey),
    status: s.index === 0 ? "active" : "revoked",
    updatedAt: BigInt(updatedAt),
    txHash: tx.txHash,
    outputIndex,
  };
}

/** Finds the UTxO that currently holds an issuer's registry token. */
export interface RegistryLocator {
  readonly name: string;
  locate(policyId: string, assetName: string): Promise<{ txHash: string; outputIndex: number } | null>;
}

const KOIOS: Record<Network, string> = {
  preprod: "https://preprod.koios.rest/api/v1",
  preview: "https://preview.koios.rest/api/v1",
  mainnet: "https://api.koios.rest/api/v1",
};

export function koiosRegistryLocator(network: Network, baseUrl = KOIOS[network]): RegistryLocator {
  return {
    name: `Koios (${network})`,
    async locate(policyId, assetName) {
      const res = await fetch(`${baseUrl}/asset_utxos`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ _asset_list: [[policyId, assetName]] }),
      });
      if (!res.ok) throw new Error(`Koios responded ${res.status}`);
      const rows = (await res.json()) as Array<{ tx_hash: string; tx_index: number }>;
      if (rows.length > 1) throw new RegistryError("registry token held by more than one UTxO");
      return rows[0] ? { txHash: rows[0].tx_hash, outputIndex: rows[0].tx_index } : null;
    },
  };
}

/** The issuer's current registry entry, or null if it is not registered. */
export async function lookupIssuer(
  issuerId: string,
  opts: { policyId: string; locator: RegistryLocator; provider: ChainProvider },
): Promise<RegistryEntry | null> {
  const at = await opts.locator.locate(opts.policyId, registryTokenName(issuerId));
  if (!at) return null;
  const tx = await opts.provider.fetchTransaction(at.txHash);
  const entry = readRegistryEntry(tx.cborHex, at.outputIndex, opts.policyId);
  if (entry.txHash !== at.txHash) throw new RegistryError("indexer returned bytes of a different transaction");
  if (entry.issuerId !== issuerId) throw new RegistryError("registry entry is for a different issuer");
  return entry;
}

export type IssuerCheck =
  | { status: "not_registered" }
  | { status: "revoked"; entry: RegistryEntry }
  | { status: "active"; entry: RegistryEntry; signature: "valid" | "invalid" | "absent" };

/**
 * Checks a record's issuer against its registry entry and, when the bundle
 * carries the issuer's signature, the signature against the registered key.
 */
export function checkIssuer(entry: RegistryEntry | null, recordDigest: string, signatureHex?: string): IssuerCheck {
  if (!entry) return { status: "not_registered" };
  if (entry.status === "revoked") return { status: "revoked", entry };
  if (!signatureHex) return { status: "active", entry, signature: "absent" };
  // Raw Ed25519 or a CIP-8 wallet signature (cip8.ts).
  const ok = verifyMessageSignature(entry.pubkey, signedMessage(recordDigest), signatureHex);
  return { status: "active", entry, signature: ok ? "valid" : "invalid" };
}
