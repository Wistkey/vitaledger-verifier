/**
 * Optional trustless inclusion check (SPEC §6): proves a transaction is on
 * chain with a Mithril certificate signed by Cardano stake, verified back to
 * the network's pinned genesis key, instead of trusting an indexer.
 *
 * Node only, and only when asked: the Mithril WASM client is an optional
 * dependency (npm i @mithril-dev/mithril-client-wasm), loaded on demand.
 */
import type { Network } from "./chain.js";

/** Pinned Mithril genesis verification keys, from input-output-hk/mithril (mithril-infra/configuration/<network>/genesis.vkey), 2026-10-01. */
const TESTNET_GENESIS_VKEY = "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d";
export const MITHRIL: Record<Network, { aggregator: string; genesisVkey: string }> = {
  preprod: { aggregator: "https://aggregator.release-preprod.api.mithril.network/aggregator", genesisVkey: TESTNET_GENESIS_VKEY },
  preview: { aggregator: "https://aggregator.pre-release-preview.api.mithril.network/aggregator", genesisVkey: TESTNET_GENESIS_VKEY },
  mainnet: { aggregator: "https://aggregator.release-mainnet.api.mithril.network/aggregator", genesisVkey: "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d" },
};

export type MithrilInclusion =
  | { certified: true; certificateHash: string; epoch: number; certifiedUpToBlock: number | null }
  | { certified: false; reason: string };

export class MithrilUnavailableError extends Error {
  constructor() {
    super("Mithril check needs the optional package: npm i @mithril-dev/mithril-client-wasm");
    this.name = "MithrilUnavailableError";
  }
}

/** Minimal surface of the WASM client this module uses; injectable for tests. */
export interface MithrilClientLike {
  get_cardano_transaction_proofs(hashes: string[]): Promise<{ certificate_hash: string; transactions_hashes: string[]; non_certified_transactions: string[] }>;
  verify_certificate_chain(hash: string): Promise<{ epoch: number; signed_entity_type?: unknown }>;
  verify_cardano_transaction_proof_then_compute_message(proof: unknown, certificate: unknown): Promise<unknown>;
  verify_message_match_certificate(message: unknown, certificate: unknown): Promise<boolean>;
}

export async function mithrilClient(network: Network, aggregator?: string): Promise<MithrilClientLike> {
  let mod: { MithrilClient: new (endpoint: string, vkey: string, options: unknown) => MithrilClientLike };
  try {
    mod = await import(/* optional */ "@mithril-dev/mithril-client-wasm" as string);
  } catch {
    throw new MithrilUnavailableError();
  }
  const cfg = MITHRIL[network];
  return new mod.MithrilClient(aggregator ?? cfg.aggregator, cfg.genesisVkey, {});
}

/**
 * Proof of inclusion for one transaction: fetch the Mithril proof, verify
 * the certificate chain to genesis, and check the proof against the
 * certificate's signed message. Recent transactions may not be certified
 * yet (Mithril signs the transaction set every few blocks).
 */
export async function verifyInclusionWithMithril(txHash: string, client: MithrilClientLike): Promise<MithrilInclusion> {
  const proof = await client.get_cardano_transaction_proofs([txHash]);
  if (!proof.transactions_hashes.includes(txHash)) {
    return { certified: false, reason: "not certified by Mithril yet (recent transactions are certified every few blocks)" };
  }
  const certificate = await client.verify_certificate_chain(proof.certificate_hash);
  const message = await client.verify_cardano_transaction_proof_then_compute_message(proof, certificate);
  if (!(await client.verify_message_match_certificate(message, certificate))) {
    return { certified: false, reason: "Mithril proof does not match its certificate" };
  }
  const entity = (certificate.signed_entity_type ?? {}) as { CardanoTransactions?: [number, number] };
  return {
    certified: true,
    certificateHash: proof.certificate_hash,
    epoch: certificate.epoch,
    certifiedUpToBlock: entity.CardanoTransactions?.[1] ?? null,
  };
}
