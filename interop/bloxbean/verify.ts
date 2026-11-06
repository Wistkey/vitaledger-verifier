import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { koios, parseTransaction, verifyAgainstTransaction, type ChainTransaction, type ProofBundle } from "../../src/index.js";
import { readArrayItems } from "../../src/cbor.js";
import { TOOLING_EVIDENCE_SCHEMA, writeToolingEvidence, type ToolingAssertion } from "../../scripts/tooling-evidence.js";

const [storeUrl = "http://127.0.0.1:8080/api/v1", input] = process.argv.slice(2);
if (!input) throw new Error("usage: tsx verify.ts <loopback-yaci-store-url> <output.json>");
const mode = process.env.BLOXBEAN_MODE === "preprod" ? "preprod" : "yaci";
const startedAt = new Date().toISOString();
const evidencePath = process.env.TOOLING_EVIDENCE ?? `${input}.evidence.json`;
const assertions: ToolingAssertion[] = [];
try {
const { txHash, cborHex, bundle, provider, registryId } = JSON.parse(await readFile(input, "utf8")) as {
  txHash: string;
  cborHex: string;
  bundle: ProofBundle;
  provider?: string;
  registryId?: string;
};
assert.equal(bundle.anchor.txHash, txHash);
assertions.push({ name: "bundle transaction hash matches the signed transaction", ok: true });

async function fetchYaci(): Promise<{ transaction: ChainTransaction; bodyCbor: string }> {
  const parsed = new URL(storeUrl);
  assert.ok(parsed.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname), "Yaci endpoint must be local");
  for (let attempt = 0; attempt < 90; attempt++) {
    const response = await fetch(`${storeUrl.replace(/\/$/, "")}/txs/${txHash}/cbor`);
    if (response.ok) {
      const bodyCbor = Buffer.from(await response.arrayBuffer()).toString("hex");
      const blockResponse = await fetch(`${storeUrl.replace(/\/$/, "")}/txs/${txHash}`);
      const info = await blockResponse.json();
      const block = await fetch(`${storeUrl.replace(/\/$/, "")}/blocks/${info.block_height}`).then((res) => res.json());
      return { transaction: { cborHex, blockTime: block.time, blockHeight: info.block_height }, bodyCbor };
    }
    if (response.status !== 404) throw new Error(`Yaci Store responded ${response.status}`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("transaction was not indexed by Yaci Store");
}

async function fetchPreprod(): Promise<{ transaction: ChainTransaction; bodyCbor: string }> {
  let transaction: ChainTransaction | undefined;
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      transaction = await koios("preprod").fetchTransaction(txHash);
      break;
    } catch (error) {
      if ((error as Error).name !== "TransactionNotFoundError") throw error;
      await new Promise((resolve) => setTimeout(resolve, 10_000));
    }
  }
  assert.ok(transaction, "transaction was not independently indexed by Koios");
  const items = readArrayItems(Buffer.from(transaction.cborHex, "hex"));
  assert.ok(items[0], "Koios transaction has no body");
  return { transaction, bodyCbor: Buffer.from(transaction.cborHex, "hex").subarray(items[0].start, items[0].end).toString("hex") };
}

const { transaction, bodyCbor } = mode === "preprod" ? await fetchPreprod() : await fetchYaci();
const signedBytes = Buffer.from(cborHex, "hex");
const body = readArrayItems(signedBytes)[0];
assert.ok(body, "BloxBean transaction has no body");
assert.equal(bodyCbor, signedBytes.subarray(body.start, body.end).toString("hex"), `${mode === "preprod" ? "Koios" : "Yaci"} stored different transaction body bytes than BloxBean signed`);
assertions.push({ name: "independent provider returned the body BloxBean signed", ok: true });
assert.equal(parseTransaction(transaction.cborHex).txHash, txHash);
assertions.push({ name: "independent transaction bytes reproduce the submitted hash", ok: true });
const result = verifyAgainstTransaction(bundle, transaction);
assert.equal(result.valid, true, result.reason);
assert.equal(result.merkleRoot, "1010a2ad39f3f3328aa75f4bcb736260d95d92a0715298f49bfb6d1d5ba9ff2b");
assertions.push({ name: "TypeScript verifier accepts metadata and Merkle proof", ok: true });
await writeToolingEvidence(evidencePath, {
  schema: TOOLING_EVIDENCE_SCHEMA,
  tool: "BloxBean Cardano Client Lib",
  toolVersion: "0.7.3",
  mode: mode === "preprod" ? "shadow-canary" : "ci",
  network: mode === "preprod" ? "preprod" : "yaci-local",
  startedAt,
  finishedAt: new Date().toISOString(),
  status: "passed",
  assertions,
  source: { recordDigest: result.recordDigest },
  transaction: { txHash, metadataLabel: 22092, provider: mode === "preprod" ? "Koios Preprod" : provider ?? "Yaci Store" },
  registryId,
});
console.log(`VALID BloxBean anchor ${txHash}; all TypeScript verifier checks passed`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  await writeToolingEvidence(evidencePath, {
    schema: TOOLING_EVIDENCE_SCHEMA,
    tool: "BloxBean Cardano Client Lib",
    toolVersion: "0.7.3",
    mode: mode === "preprod" ? "shadow-canary" : "ci",
    network: mode === "preprod" ? "preprod" : "yaci-local",
    startedAt,
    finishedAt: new Date().toISOString(),
    status: "failed",
    assertions: [...assertions, { name: "interop scenario completed", ok: false, detail: message }],
    error: message,
  });
  throw error;
}
