/**
 * Completeness: are all of VitaLedger's anchors listed by its API?
 *
 * `--all` re-verifies every record the API lists, so an API that left a batch
 * out would go unnoticed. This module finds the anchors from the chain
 * instead: every label-22092 transaction paid from the operator's anchor
 * address(es), read from its own CBOR. Batches link to the previous one with
 * `p` (SPEC §5), so the anchors form one chain from the newest back to the
 * first; every batch on that chain must be listed by the API, with all `n`
 * of its records. Anchors off that chain (e.g. a test anchor made before
 * launch) are reported, not failed.
 *
 * Trust: the indexer is trusted to return the address's full transaction
 * list (no chain proof can show absence); each anchor's content is checked
 * from its raw bytes like any other.
 */
import type { ChainProvider, Network } from "./chain.js";
import { type BatchAnchor, parseBatchAnchor, VITALEDGER_LABEL } from "./metadata.js";
import { parseTransaction } from "./tx.js";

/** The operator's anchor (fee-paying) addresses, by network. */
export const ANCHOR_ADDRESSES: Partial<Record<Network, string[]>> = {
  preprod: ["addr_test1qpc8szswzp35c7f4f0znrwsvzccnxl5hrtglqq7jy3qkj0nz0m62jpesyr4rng6hmv5jjdvkjv9xur26ma3lsdhvvzrs5k33mc"],
};

/** Lists the transactions of addresses that carry metadata at `label`. */
export interface AnchorLister {
  readonly name: string;
  listLabelled(addresses: string[], label: number): Promise<Array<{ txHash: string; blockTime: number }>>;
}

const KOIOS: Record<Network, string> = {
  preprod: "https://preprod.koios.rest/api/v1",
  preview: "https://preview.koios.rest/api/v1",
  mainnet: "https://api.koios.rest/api/v1",
};

export function koiosAnchorLister(network: Network, baseUrl = KOIOS[network]): AnchorLister {
  const post = async (path: string, body: unknown) => {
    const res = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`Koios ${path} responded ${res.status}`);
    return res.json();
  };
  return {
    name: `Koios (${network})`,
    async listLabelled(addresses, label) {
      const txs: Array<{ tx_hash: string; block_time: number }> = [];
      for (let offset = 0; ; offset += 1000) {
        const page = (await post(`/address_txs?limit=1000&offset=${offset}`, { _addresses: addresses })) as typeof txs;
        txs.push(...page);
        if (page.length < 1000) break;
      }
      const out: Array<{ txHash: string; blockTime: number }> = [];
      for (let i = 0; i < txs.length; i += 50) {
        const chunk = txs.slice(i, i + 50);
        const meta = (await post("/tx_metadata", { _tx_hashes: chunk.map((t) => t.tx_hash) })) as Array<{
          tx_hash: string;
          metadata: Record<string, unknown> | null;
        }>;
        const labelled = new Set(meta.filter((m) => m.metadata && String(label) in m.metadata).map((m) => m.tx_hash));
        for (const t of chunk) if (labelled.has(t.tx_hash)) out.push({ txHash: t.tx_hash, blockTime: t.block_time });
      }
      return out;
    },
  };
}

export interface ChainAnchor {
  txHash: string;
  /** Unix seconds. */
  blockTime: number;
  anchor: BatchAnchor;
}

/** The operator's anchors for `registryId`, each read from its own transaction bytes. */
export async function chainAnchors(opts: {
  addresses: string[];
  lister: AnchorLister;
  provider: ChainProvider;
  registryId: string;
}): Promise<ChainAnchor[]> {
  const listed = await opts.lister.listLabelled(opts.addresses, VITALEDGER_LABEL);
  const out: ChainAnchor[] = [];
  for (const { txHash, blockTime } of listed) {
    const tx = await opts.provider.fetchTransaction(txHash);
    const parsed = parseTransaction(tx.cborHex);
    if (parsed.txHash !== txHash) throw new Error(`indexer returned bytes of another transaction for ${txHash}`);
    if (!parsed.isValid) continue;
    let anchor: BatchAnchor;
    try {
      anchor = parseBatchAnchor(parsed.metadata.get(VITALEDGER_LABEL)!);
    } catch {
      continue; // something else at this label: not one of our anchors
    }
    if (anchor.i === opts.registryId) out.push({ txHash, blockTime: tx.blockTime || blockTime, anchor });
  }
  return out;
}

export interface CompletenessReport {
  /** Anchors on the `p` chain, newest first. */
  history: ChainAnchor[];
  /** Anchors not on the chain (pre-launch tests, or a fork: see `problems`). */
  outside: ChainAnchor[];
  /** Batches on the chain the API doesn't list at all. */
  missing: Array<{ txHash: string; blockTime: number; n: number; recent: boolean }>;
  /** Batches the API lists with fewer records than the anchor's `n`. */
  short: Array<{ txHash: string; n: number; listed: number }>;
  /** Structural problems: a fork (two batches naming the same previous one), or a `p` that leads nowhere. */
  problems: string[];
  complete: boolean;
}

/**
 * Compares the chain's anchors with the records the API listed (count per
 * transaction). Anchors newer than `graceSeconds` that the API doesn't list
 * yet are marked `recent`: the API lists a batch only after confirming it.
 */
export function checkCompleteness(
  anchors: ChainAnchor[],
  listedPerTx: Map<string, number>,
  opts: { now?: number; graceSeconds?: number } = {},
): CompletenessReport {
  const now = opts.now ?? Date.now() / 1000;
  const grace = opts.graceSeconds ?? 3 * 3600;
  const byHash = new Map(anchors.map((a) => [a.txHash, a]));
  const problems: string[] = [];
  const children = new Map<string, string[]>();
  for (const a of anchors) {
    if (!a.anchor.p) continue;
    children.set(a.anchor.p, [...(children.get(a.anchor.p) ?? []), a.txHash]);
  }
  for (const [parent, kids] of children) if (kids.length > 1) problems.push(`fork: ${kids.length} batches name ${parent} as previous`);

  // Head: the newest anchor; follow p back to an anchor with no p.
  const newest = [...anchors].sort((x, y) => y.blockTime - x.blockTime)[0];
  const history: ChainAnchor[] = [];
  const seen = new Set<string>();
  for (let cur = newest; cur && !seen.has(cur.txHash); ) {
    seen.add(cur.txHash);
    history.push(cur);
    if (!cur.anchor.p) break;
    const prev = byHash.get(cur.anchor.p);
    if (!prev) {
      problems.push(`batch ${cur.txHash} names ${cur.anchor.p} as previous, which is not one of the operator's anchors`);
      break;
    }
    cur = prev;
  }
  const outside = anchors.filter((a) => !seen.has(a.txHash));
  const missing = history
    .filter((a) => !listedPerTx.has(a.txHash))
    .map((a) => ({ txHash: a.txHash, blockTime: a.blockTime, n: a.anchor.n, recent: now - a.blockTime < grace }));
  const short = history
    .filter((a) => listedPerTx.has(a.txHash) && listedPerTx.get(a.txHash)! < a.anchor.n)
    .map((a) => ({ txHash: a.txHash, n: a.anchor.n, listed: listedPerTx.get(a.txHash)! }));
  const complete = problems.length === 0 && short.length === 0 && missing.every((m) => m.recent);
  return { history, outside, missing, short, problems, complete };
}
