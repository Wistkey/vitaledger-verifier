#!/usr/bin/env node
/**
 * vitaledger-verify <bundle.json> [--json] [--koios <url>] [--blockfrost <project id>]
 * Exit codes: 0 valid, 1 invalid, 2 error.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { blockfrost, explorerUrl, koios, type Network } from "./chain.js";
import { type ProofBundle, verifyBundle } from "./verify.js";

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      koios: { type: "string" },
      blockfrost: { type: "string", default: process.env.BLOCKFROST_PROJECT_ID },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  if (values.help || positionals.length !== 1) {
    console.error("usage: vitaledger-verify <bundle.json> [--json] [--koios <url>] [--blockfrost <project id>]");
    return 2;
  }
  const bundle = JSON.parse(readFileSync(positionals[0], "utf8")) as ProofBundle;
  const network: Network = bundle.anchor?.network ?? "preprod";
  const provider = values.blockfrost ? blockfrost(network, values.blockfrost) : koios(network, values.koios);
  const result = await verifyBundle(bundle, provider);

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
  return result.valid ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`error: ${(err as Error).message}`);
    process.exit(2);
  },
);
