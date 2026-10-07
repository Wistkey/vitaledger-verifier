/**
 * Re-verify every anchored record a VitaLedger API lists (SPEC §6), from
 * public data: the API supplies each record and proof, the chain provider
 * supplies the transaction bytes, and each bundle is checked exactly as a
 * single proof would be. The API is trusted for nothing: a bundle whose
 * record doesn't hash to the listed digest is reported invalid.
 */
import type { ChainProvider, ChainTransaction, Network } from "./chain.js";
import { recordDigest } from "./digest.js";
import { type MithrilInclusion } from "./mithril.js";
import { type ProofBundle, type VerificationResult, verifyBundle } from "./verify.js";

export interface RecordOutcome {
  recordDigest: string;
  txHash?: string;
  valid: boolean;
  reason?: string;
  anchoredAt?: string;
  claimType?: string;
  issuer?: string;
  /** "certified" | "pending" (Mithril hasn't reached it yet) | "failed" | undefined when not asked. */
  mithril?: "certified" | "pending" | "failed";
}

export interface VerifyAllReport {
  apiBase: string;
  records: RecordOutcome[];
  transactions: number;
  valid: number;
  /** Records checked and found not to match the chain. */
  invalid: number;
  /** Records that couldn't be checked (network, missing bundle). */
  errors: string[];
}

export interface VerifyAllOptions {
  apiBase: string;
  providerFor: (network: Network) => ChainProvider;
  /** Proves inclusion of one transaction with Mithril; omit to skip. */
  mithril?: (txHash: string, network: Network) => Promise<MithrilInclusion>;
  fetchJson?: (url: string) => Promise<unknown>;
  pageSize?: number;
  onRecord?: (outcome: RecordOutcome) => void;
}

const defaultFetchJson = async (url: string) => {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`${url} answered HTTP ${res.status}`);
  return res.json();
};

/** Fetches each transaction once, however many records its batch holds. */
function memoised(provider: ChainProvider): ChainProvider {
  const cache = new Map<string, Promise<ChainTransaction>>();
  return {
    name: provider.name,
    fetchTransaction(txHash) {
      if (!cache.has(txHash)) cache.set(txHash, provider.fetchTransaction(txHash));
      return cache.get(txHash)!;
    },
  };
}

export async function verifyAll(opts: VerifyAllOptions): Promise<VerifyAllReport> {
  const base = opts.apiBase.replace(/\/+$/, "");
  const fetchJson = opts.fetchJson ?? defaultFetchJson;
  const pageSize = opts.pageSize ?? 500;
  const providers = new Map<Network, ChainProvider>();
  const mithrilByTx = new Map<string, Promise<MithrilInclusion>>();
  const report: VerifyAllReport = { apiBase: base, records: [], transactions: 0, valid: 0, invalid: 0, errors: [] };
  const txs = new Set<string>();

  let after: string | null = null;
  do {
    const page = (await fetchJson(`${base}/api/v1/proofs?limit=${pageSize}${after ? `&after=${after}` : ""}`)) as {
      data?: { records?: Array<{ recordDigest: string }>; next?: string | null };
    };
    const listed = page.data?.records ?? [];
    for (const { recordDigest: digest } of listed) {
      const outcome: RecordOutcome = { recordDigest: digest, valid: false };
      let errored = false;
      try {
        const proof = (await fetchJson(`${base}/api/v1/proofs/${digest}`)) as {
          data?: { bundle?: ProofBundle | null; record?: { claim?: { type?: string }; issuer?: string } };
        };
        const bundle = proof.data?.bundle;
        if (!bundle) throw new Error("listed as anchored but no proof bundle was returned");
        const network: Network = bundle.anchor?.network ?? "preprod";
        if (!providers.has(network)) providers.set(network, memoised(opts.providerFor(network)));
        let result: VerificationResult;
        if (recordDigest(bundle.record) !== digest) {
          result = { valid: false, reason: "the API returned a different record than the one it listed", checks: [] } as unknown as VerificationResult;
        } else {
          result = await verifyBundle(bundle, providers.get(network)!);
        }
        Object.assign(outcome, {
          valid: result.valid,
          reason: result.reason,
          txHash: result.txHash ?? bundle.anchor?.txHash,
          anchoredAt: result.anchoredAt,
          claimType: proof.data?.record?.claim?.type,
          issuer: proof.data?.record?.issuer,
        });
        if (result.valid && opts.mithril && outcome.txHash) {
          const tx = outcome.txHash;
          if (!mithrilByTx.has(tx)) mithrilByTx.set(tx, opts.mithril(tx, network));
          const inclusion = await mithrilByTx.get(tx)!;
          if (inclusion.certified) outcome.mithril = "certified";
          else if (inclusion.reason.startsWith("not certified")) outcome.mithril = "pending";
          else {
            outcome.mithril = "failed";
            outcome.valid = false;
            outcome.reason = `block inclusion (Mithril): ${inclusion.reason}`;
          }
        }
      } catch (e) {
        // Couldn't check it (network, missing bundle): an error, not proof of tampering.
        errored = true;
        outcome.reason = `could not check: ${(e as Error).message}`;
        report.errors.push(`${digest}: ${(e as Error).message}`);
      }
      if (outcome.txHash) txs.add(outcome.txHash);
      if (outcome.valid) report.valid++;
      else if (!errored) report.invalid++;
      report.records.push(outcome);
      opts.onRecord?.(outcome);
    }
    after = page.data?.next ?? null;
  } while (after);

  report.transactions = txs.size;
  return report;
}
