import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { verifyAgainstTransaction, type ProofBundle } from "../../src/index.js";
import { readArrayItems } from "../../src/cbor.js";

const [storeUrl = "http://127.0.0.1:8080/api/v1", input] = process.argv.slice(2);
if (!input) throw new Error("usage: tsx verify.ts <loopback-yaci-store-url> <output.json>");
const parsed = new URL(storeUrl);
assert.ok(parsed.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname), "Yaci endpoint must be local");
const { txHash, cborHex, bundle } = JSON.parse(await readFile(input, "utf8")) as {
  txHash: string;
  cborHex: string;
  bundle: ProofBundle;
};
assert.equal(bundle.anchor.txHash, txHash);

let chainCbor: string | undefined;
let blockTime = 0;
for (let attempt = 0; attempt < 90; attempt++) {
  const response = await fetch(`${storeUrl.replace(/\/$/, "")}/txs/${txHash}/cbor`);
  if (response.ok) {
    chainCbor = Buffer.from(await response.arrayBuffer()).toString("hex");
    const blockResponse = await fetch(`${storeUrl.replace(/\/$/, "")}/txs/${txHash}`);
    const info = await blockResponse.json();
    const block = await fetch(`${storeUrl.replace(/\/$/, "")}/blocks/${info.block_height}`).then((res) => res.json());
    blockTime = block.time;
    break;
  }
  if (response.status !== 404) throw new Error(`Yaci Store responded ${response.status}`);
  await new Promise((resolve) => setTimeout(resolve, 1000));
}
assert.ok(chainCbor, "transaction was not indexed by Yaci Store");
const signedBytes = Buffer.from(cborHex, "hex");
const body = readArrayItems(signedBytes)[0];
assert.ok(body, "BloxBean transaction has no body");
assert.equal(chainCbor, signedBytes.subarray(body.start, body.end).toString("hex"), "Yaci stored different transaction body bytes than BloxBean signed");
const result = verifyAgainstTransaction(bundle, { cborHex, blockTime, blockHeight: null });
assert.equal(result.valid, true, result.reason);
assert.equal(result.merkleRoot, "1010a2ad39f3f3328aa75f4bcb736260d95d92a0715298f49bfb6d1d5ba9ff2b");
console.log(`VALID BloxBean anchor ${txHash}; all TypeScript verifier checks passed`);
