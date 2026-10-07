#!/usr/bin/env node
/**
 * vitaledger-verify <bundle.json> [--json] [--koios <url>] [--blockfrost <project id>] [--mithril]
 * vitaledger-verify --all <api base, e.g. https://api.vitababy.ai> [--mithril] [--json] [--koios <url>]
 *   re-verifies every anchored record the API lists, from public chain data
 * --mithril also proves the transaction is on chain with a Mithril certificate
 * (no indexer trust); needs: npm i @mithril-dev/mithril-client-wasm
 * Exit codes: 0 valid, 1 invalid, 2 error or not yet checkable.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { blockfrost, explorerUrl, koios, type Network } from "./chain.js";
import { mithrilClient, verifyInclusionWithMithril } from "./mithril.js";
import { type ProofBundle, verifyBundle } from "./verify.js";
import { verifyAll } from "./verify-all.js";

const USAGE =
  "usage: vitaledger-verify <bundle.json> [--json] [--koios <url>] [--blockfrost <project id>] [--mithril]\n" +
  "       vitaledger-verify --all <api base, e.g. https://api.vitababy.ai> [--mithril] [--json] [--koios <url>] [--blockfrost <id>]";

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      koios: { type: "string" },
      blockfrost: { type: "string", default: process.env.BLOCKFROST_PROJECT_ID },
      mithril: { type: "boolean", default: false },
      all: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  if (values.all !== undefined && !values.help && positionals.length === 0) {
    return verifyEverything(values.all, values);
  }
  if (values.help || positionals.length !== 1) {
    console.error(USAGE);
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
    if (result.unsupported) {
      console.log(`UNSUPPORTED: this record uses a format newer than this verifier (${result.reason}). Upgrade vitaledger-verifier; this is not a sign of tampering.`);
    } else if (result.valid) {
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
  if (result.unsupported) return 2;
  return result.valid ? 0 : 1;
}

/** --all: every anchored record the API lists, re-verified from public data. */
async function verifyEverything(
  apiBase: string,
  values: { json?: boolean; koios?: string; blockfrost?: string; mithril?: boolean },
): Promise<number> {
  if (!/^https?:\/\//.test(apiBase)) {
    console.error(USAGE);
    return 2;
  }
  const clients = new Map<Network, Awaited<ReturnType<typeof mithrilClient>>>();
  const report = await verifyAll({
    apiBase,
    providerFor: (network) => (values.blockfrost ? blockfrost(network, values.blockfrost) : koios(network, values.koios)),
    mithril: values.mithril
      ? async (txHash, network) => {
          if (!clients.has(network)) clients.set(network, await mithrilClient(network));
          return verifyInclusionWithMithril(txHash, clients.get(network)!);
        }
      : undefined,
    onRecord: values.json
      ? undefined
      : (o) => {
          const m = o.mithril ? ` · Mithril ${o.mithril}` : "";
          const what = [o.claimType, o.issuer].filter(Boolean).join(" · ");
          console.log(
            o.valid
              ? `✓ ${o.recordDigest.slice(0, 16)}… ${what} · anchored ${o.anchoredAt}${m}`
              : `${o.unsupported ? "?" : "✗"} ${o.recordDigest.slice(0, 16)}… ${o.unsupported ? "newer format; upgrade the verifier" : o.reason}`,
          );
        },
  });
  if (values.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const pending = report.records.filter((r) => r.mithril === "pending").length;
    console.log("");
    console.log(`${report.records.length} records in ${report.transactions} transactions from ${report.apiBase}: ${report.valid} valid, ${report.invalid} invalid${report.unsupported ? `, ${report.unsupported} in a newer format (upgrade vitaledger-verifier)` : ""}.`);
    if (values.mithril) {
      console.log(`Mithril: ${report.records.filter((r) => r.mithril === "certified").length} certified${pending ? `, ${pending} not certified yet (recent anchors; retry in a few hours)` : ""}.`);
    }
    if (report.records.length === 0) console.log("No anchored records listed.");
  }
  return report.invalid > 0 ? 1 : report.errors.length > 0 || report.unsupported > 0 ? 2 : 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`error: ${(err as Error).message}`);
    process.exit(2);
  },
);
