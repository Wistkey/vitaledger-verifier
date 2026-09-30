/**
 * Fetches raw transaction CBOR from a public indexer. The verifier checks the
 * bytes itself (see tx.ts); the indexer is trusted only for inclusion in a
 * block and the block time.
 */
export type Network = "preprod" | "preview" | "mainnet";

export interface ChainTransaction {
  cborHex: string;
  /** Unix seconds of the block that includes the transaction. */
  blockTime: number;
  blockHeight: number | null;
}

export interface ChainProvider {
  readonly name: string;
  fetchTransaction(txHash: string): Promise<ChainTransaction>;
}

export class TransactionNotFoundError extends Error {
  constructor(readonly txHash: string, provider: string) {
    super(`transaction ${txHash} not found on ${provider}`);
    this.name = "TransactionNotFoundError";
  }
}

const KOIOS: Record<Network, string> = {
  preprod: "https://preprod.koios.rest/api/v1",
  preview: "https://preview.koios.rest/api/v1",
  mainnet: "https://api.koios.rest/api/v1",
};

const BLOCKFROST: Record<Network, string> = {
  preprod: "https://cardano-preprod.blockfrost.io/api/v0",
  preview: "https://cardano-preview.blockfrost.io/api/v0",
  mainnet: "https://cardano-mainnet.blockfrost.io/api/v0",
};

export function koios(network: Network, baseUrl = KOIOS[network]): ChainProvider {
  return {
    name: `Koios (${network})`,
    async fetchTransaction(txHash) {
      const res = await fetch(`${baseUrl}/tx_cbor`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ _tx_hashes: [txHash] }),
      });
      if (!res.ok) throw new Error(`Koios responded ${res.status}`);
      const rows = (await res.json()) as Array<{ cbor: string; tx_timestamp: number; block_height: number | null }>;
      const row = rows[0];
      if (!row?.cbor) throw new TransactionNotFoundError(txHash, this.name);
      return { cborHex: row.cbor, blockTime: row.tx_timestamp, blockHeight: row.block_height };
    },
  };
}

export function blockfrost(network: Network, projectId: string): ChainProvider {
  const base = BLOCKFROST[network];
  const get = async (path: string) => {
    const res = await fetch(`${base}${path}`, { headers: { project_id: projectId } });
    if (res.status === 404) return undefined;
    if (!res.ok) throw new Error(`Blockfrost responded ${res.status}`);
    return res.json();
  };
  return {
    name: `Blockfrost (${network})`,
    async fetchTransaction(txHash) {
      const [cbor, info] = await Promise.all([get(`/txs/${txHash}/cbor`), get(`/txs/${txHash}`)]);
      if (!cbor || !info) throw new TransactionNotFoundError(txHash, this.name);
      return { cborHex: cbor.cbor, blockTime: info.block_time, blockHeight: info.block_height };
    },
  };
}

export function explorerUrl(network: Network, txHash: string): string {
  const host = network === "mainnet" ? "cardanoscan.io" : `${network}.cardanoscan.io`;
  return `https://${host}/transaction/${txHash}`;
}
