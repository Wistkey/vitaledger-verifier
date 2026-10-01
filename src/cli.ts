#!/usr/bin/env node
/**
 * vitaledger-verify <bundle.json> [--json] [--koios <url>] [--blockfrost <project id>] [--mithril]
 * --mithril also proves the transaction is on chain with a Mithril certificate
 * (no indexer trust); needs: npm i @mithril-dev/mithril-client-wasm
 * Exit codes: 0 valid, 1 invalid, 2 error or not yet checkable.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { blockfrost, explorerUrl, koios, type Network } from "./chain.js";
import { mithrilClient, verifyInclusionWithMithril } from "./mithril.js";
import { type ProofBundle, verifyBundle } from "./verify.js";

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      koios: { type: "string" },
      blockfrost: { type: "string", default: process.env.BLOCKFROST_PROJECT_ID },
      mithril: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  if (values.help || positionals.length !== 1) {
    console.error("usage: vitaledger-verify <bundle.json> [--json] [--koios <url>] [--blockfrost <project id>] [--mithril]");
    return 2;
  }
  const bundle = JSON.parse(readFileSync(positionals[0], "utf8")) as ProofBundle;
  const network: Network = bundle.anchor?.network ?? "preprod";
  const provider = values.blockfrost ? blockfrost(network, values.blockfrost) : koios(network, values.koios);
  const result = await verifyBundle(bundle, provider);
  let mithrilPending = false;
  if (values.mithril && result.txHash) {
    const inclusion = await verifyInclusionWithMithril(result.txHash, await mithrilClient(network));
    if (inclusion.certified) {
      result.checks.push({
        name: "block inclusion (Mithril)",
        ok: true,
        detail: `certificate ${inclusion.certificateHash.slice(0, 16)}… verified to the ${network} genesis key, epoch ${inclusion.epoch}`,
      });
    } else {
      mithrilPending = inclusion.reason.startsWith("not certified");
      result.checks.push({ name: "block inclusion (Mithril)", ok: false, detail: inclusion.reason });
      if (!mithrilPending) {
        result.valid = false;
        result.reason ??= `block inclusion (Mithril): ${inclusion.reason}`;
      }
    }
  }

  if (values.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    for (const c of result.checks) console.log(`${c.ok ? "✓" : "✗"} ${c.name}${c.detail ? ` — ${c.detail}` : ""}`);
    console.log("");
    if (result.valid) {
      console.log(`VALID: record unchanged since it was anchored at ${result.anchoredAt} on ${network}.`);
      console.log(explorerUrl(network, result.txHash!));
    } else {
      console.log(`INVALID: ${result.reason}`);
    }
  }
  if (result.valid && mithrilPending) {
    console.log("Mithril has not certified this transaction yet; retry in a few minutes for a trustless inclusion check.");
    return 2;
  }
  return result.valid ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`error: ${(err as Error).message}`);
    process.exit(2);
  },
);
