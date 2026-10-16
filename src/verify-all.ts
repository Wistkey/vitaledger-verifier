/**
 * Re-verify every anchored record a VitaLedger API lists (SPEC §6), from
 * public data: the API supplies each record and proof, the chain provider
 * supplies the transaction bytes, and each bundle is checked exactly as a
 * single proof would be. The API is trusted for nothing: a bundle whose
 * record doesn't hash to the listed digest is reported invalid.
 */
import type { ChainProvider, ChainTransaction, Network } from "./chain.js";
import { recordDigest } from "./digest.js";
import { type AnchorLister, chainAnchors, checkCompleteness, type CompletenessReport } from "./completeness.js";
import { type MithrilInclusion } from "./mithril.js";
import { type AttestResult, verifyAttest } from "./cip170.js";
import { checkIssuer, lookupIssuer, type RegistryEntry, type RegistryLocator } from "./registry.js";
import { type ProofBundle, type VerificationResult, verifyBundle } from "./verify.js";

export interface RecordOutcome {
  recordDigest: string;
  txHash?: string;
  valid: boolean;
  reason?: string;
  anchoredAt?: string;
  claimType?: string;
  issuer?: string;
  /** Newer format than this verifier (SPEC §9): neither valid nor tampered. */
  unsupported?: boolean;
  /** "certified" | "pending" (Mithril hasn't reached it yet) | "failed" | undefined when not asked. */
  mithril?: "certified" | "pending" | "failed";
  /** With `registry`: the issuer signature against the issuer's current on-chain key. */
  issuerSignature?: "valid" | "invalid" | "absent" | "unregistered" | "revoked";
}

/** One issuer, as the API and the on-chain registry each describe it. */
export interface IssuerReport {
  issuerId: string;
  records: number;
  api?: { publicKey: string; status: string };
  registry: "active" | "revoked" | "not_registered" | "error";
  registryKey?: string;
  signatures: { valid: number; invalid: number; absent: number };
  /** Disagreements between the API and the registry: a failure. */
  drift: string[];
  /** Worth a look, not a failure (e.g. not registered on chain, signatures under an earlier key). */
  warnings: string[];
}

export interface AttestationReport {
  /** Batch transactions carrying a valid CIP-0170 ATTEST by the operator. */
  valid: number;
  /** Batches without label 170 (anchored before CIP-0170 was switched on). */
  unattested: number;
  invalid: Array<{ txHash: string; reason: string }>;
}

export interface VerifyAllReport {
  apiBase: string;
  records: RecordOutcome[];
  transactions: number;
  valid: number;
  /** Records checked and found not to match the chain. */
  invalid: number;
  /** Records in a newer format than this verifier: upgrade, not tampering. */
  unsupported: number;
  /** Records that couldn't be checked (network, missing bundle). */
  errors: string[];
  /** With `completeness`: whether every anchor on chain is listed (completeness.ts). */
  completeness?: CompletenessReport;
  /** With `registry`: each issuer, the API's view against the on-chain registry. */
  issuers?: IssuerReport[];
  /** With `keri`: CIP-0170 ATTESTs on the batch transactions. */
  attestations?: AttestationReport;
}

export interface VerifyAllOptions {
  apiBase: string;
  providerFor: (network: Network) => ChainProvider;
  /** Proves inclusion of one transaction with Mithril; omit to skip. */
  mithril?: (txHash: string, network: Network) => Promise<MithrilInclusion>;
  fetchJson?: (url: string) => Promise<unknown>;
  pageSize?: number;
  onRecord?: (outcome: RecordOutcome) => void;
  /** Also check that the API lists every anchor found on chain from these addresses. */
  completeness?: { network: Network; addresses: string[]; lister: AnchorLister; registryId?: string };
  /** Check each record's issuer signature against the on-chain registry, and the API's issuer keys against it. */
  registry?: { network: Network; policyId: string; locator: RegistryLocator };
  /** Check each batch's CIP-0170 ATTEST against the operator's KEL. */
  keri?: { network: Network; kel: string; aid?: string };
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
  const report: VerifyAllReport = { apiBase: base, records: [], transactions: 0, valid: 0, invalid: 0, unsupported: 0, errors: [] };
  const txs = new Set<string>();
  const entries = new Map<string, Promise<RegistryEntry | null | undefined>>();
  const providerFor = (network: Network) => {
    if (!providers.has(network)) providers.set(network, memoised(opts.providerFor(network)));
    return providers.get(network)!;
  };

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
          unsupported: result.unsupported,
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
        if (opts.registry && outcome.valid && typeof outcome.issuer === "string") {
          const issuerId = outcome.issuer;
          if (!entries.has(issuerId)) {
            entries.set(issuerId, lookupIssuer(issuerId, {
              policyId: opts.registry.policyId,
              locator: opts.registry.locator,
              provider: providerFor(opts.registry.network),
            }).catch(() => undefined));
          }
          const entry = await entries.get(issuerId)!;
          if (entry === undefined) outcome.issuerSignature = undefined;
          else {
            const check = checkIssuer(entry, digest, bundle.issuerSignature);
            outcome.issuerSignature = check.status === "active" ? check.signature : check.status === "revoked" ? "revoked" : "unregistered";
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
      else if (outcome.unsupported) report.unsupported++;
      else if (!errored) report.invalid++;
      report.records.push(outcome);
      opts.onRecord?.(outcome);
    }
    after = page.data?.next ?? null;
  } while (after);

  report.transactions = txs.size;
  if (opts.registry) report.issuers = await issuerReports(base, fetchJson, report.records, entries);
  if (opts.keri) {
    const provider = providerFor(opts.keri.network);
    const att: AttestationReport = { valid: 0, unattested: 0, invalid: [] };
    for (const txHash of txs) {
      let result: AttestResult;
      try {
        result = verifyAttest((await provider.fetchTransaction(txHash)).cborHex, opts.keri.kel, opts.keri.aid);
      } catch (e) {
        result = { status: "invalid", reason: (e as Error).message };
      }
      if (result.status === "valid") att.valid++;
      else if (result.status === "absent") att.unattested++;
      else att.invalid.push({ txHash, reason: result.reason });
    }
    report.attestations = att;
  }
  if (opts.completeness) {
    const { network, addresses, lister, registryId = "vl:registry:vitaledger" } = opts.completeness;
    if (!providers.has(network)) providers.set(network, memoised(opts.providerFor(network)));
    const listedPerTx = new Map<string, number>();
    for (const r of report.records) if (r.txHash) listedPerTx.set(r.txHash, (listedPerTx.get(r.txHash) ?? 0) + 1);
    const anchors = await chainAnchors({ addresses, lister, provider: providers.get(network)!, registryId });
    report.completeness = checkCompleteness(anchors, listedPerTx);
  }
  return report;
}

/** Per issuer: the API's key and status against the on-chain registry entry, plus signature counts. */
export async function issuerReports(
  base: string,
  fetchJson: (url: string) => Promise<unknown>,
  records: RecordOutcome[],
  entries: Map<string, Promise<RegistryEntry | null | undefined>>,
): Promise<IssuerReport[]> {
  const out: IssuerReport[] = [];
  for (const issuerId of [...new Set(records.map((r) => r.issuer).filter((i): i is string => typeof i === "string"))].sort()) {
    const mine = records.filter((r) => r.issuer === issuerId);
    const entry = await (entries.get(issuerId) ?? Promise.resolve(undefined));
    const rep: IssuerReport = {
      issuerId,
      records: mine.length,
      registry: entry === undefined ? "error" : entry === null ? "not_registered" : entry.status,
      registryKey: entry?.pubkey,
      signatures: {
        valid: mine.filter((r) => r.issuerSignature === "valid").length,
        invalid: mine.filter((r) => r.issuerSignature === "invalid").length,
        absent: mine.filter((r) => r.issuerSignature === "absent").length,
      },
      drift: [],
      warnings: [],
    };
    try {
      const api = (await fetchJson(`${base}/api/v1/issuers/${issuerId.replace(/^vl:issuer:/, "")}`)) as { data?: { publicKey?: string; status?: string } };
      if (api.data?.publicKey) rep.api = { publicKey: api.data.publicKey, status: api.data.status ?? "unknown" };
    } catch {
      rep.warnings.push("the API did not return this issuer");
    }
    if (rep.registry === "error") rep.warnings.push("could not read the on-chain registry");
    if (rep.registry === "not_registered") rep.warnings.push("not registered in the on-chain registry");
    if (entry && rep.api) {
      if (entry.pubkey !== rep.api.publicKey) rep.drift.push("the API and the on-chain registry have different keys");
      if (entry.status === "revoked" && rep.api.status === "active") rep.drift.push("revoked on chain but active in the API");
      if (entry.status === "active" && rep.api.status !== "active") rep.drift.push(`active on chain but ${rep.api.status} in the API`);
    }
    if (rep.signatures.invalid) {
      rep.warnings.push(`${rep.signatures.invalid} signature(s) don't verify under the current registry key (signed with an earlier key, or a problem)`);
    }
    out.push(rep);
  }
  return out;
}
