#!/usr/bin/env node
/**
 * vitaledger-verify <bundle.json> [--json] [--koios <url>] [--blockfrost <project id>] [--mithril] [--registry]
 * vitaledger-verify --all <api base, e.g. https://api.vitababy.ai> [--mithril] [--complete] [--json] [--koios <url>]
 *   re-verifies every anchored record the API lists, from public chain data;
 *   --complete also finds VitaLedger's anchors on chain and checks the API lists them all
 * --mithril also proves the transaction is on chain with a Mithril certificate
 * (no indexer trust); needs: npm i @mithril-dev/mithril-client-wasm
 * --registry also checks the record's issuer against the on-chain issuer
 * registry (Aiken prototype; informational, does not change VALID/INVALID)
 * --keri [oobi url] also checks a CIP-0170 ATTEST (label 170) in the anchor
 * transaction against the operator's KERI key event log (informational)
 * Exit codes: 0 valid, 1 invalid, 2 error or not yet checkable.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { blockfrost, explorerUrl, koios, type Network } from "./chain.js";
import { mithrilClient, verifyInclusionWithMithril } from "./mithril.js";
import { KERI_OPERATOR, verifyAttest, fetchKel, type AttestResult } from "./cip170.js";
import { checkIssuer, koiosRegistryLocator, lookupIssuer, REGISTRY, type IssuerCheck } from "./registry.js";
import { type ProofBundle, verifyBundle } from "./verify.js";
import { verifyAll } from "./verify-all.js";
import { ANCHOR_ADDRESSES, koiosAnchorLister } from "./completeness.js";

const USAGE =
  "usage: vitaledger-verify <bundle.json> [--json] [--koios <url>] [--blockfrost <project id>] [--mithril] [--registry] [--keri [oobi url]]\n" +
  "       vitaledger-verify --all <api base, e.g. https://api.vitababy.ai> [--mithril] [--complete [--network <n>]] [--json] [--koios <url>] [--blockfrost <id>]";

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      koios: { type: "string" },
      blockfrost: { type: "string", default: process.env.BLOCKFROST_PROJECT_ID },
      mithril: { type: "boolean", default: false },
      registry: { type: "boolean", default: false },
      complete: { type: "boolean", default: false },
      network: { type: "string", default: "preprod" },
      keri: { type: "string" },
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

  const issuer = values.registry && result.recordDigest ? await registryCheck(bundle, result.recordDigest, network, provider, values) : undefined;

  const keri = values.keri !== undefined && result.txHash ? await keriCheck(result.txHash, network, provider, values.keri) : undefined;

  if (values.json) {
    console.log(JSON.stringify({ ...result, ...(issuer ? { issuer } : {}), ...(keri ? { keri } : {}) }, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
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
    if (issuer) console.log(`Issuer (on-chain registry, informational): ${issuer.summary}`);
    if (keri) console.log(`Operator KERI attestation (CIP-0170, informational): ${keri.summary}`);
  }
  if (result.valid && mithrilPending) {
    console.log("Mithril has not certified this transaction yet; retry in a few minutes for a trustless inclusion check.");
    return 2;
  }
  if (result.unsupported) return 2;
  return result.valid ? 0 : 1;
}

/** --keri: the anchor transaction's CIP-0170 ATTEST against the operator's KEL (src/cip170.ts). */
async function keriCheck(
  txHash: string,
  network: Network,
  provider: ReturnType<typeof koios>,
  oobiArg: string,
): Promise<{ result?: AttestResult; summary: string }> {
  const operator = KERI_OPERATOR[network];
  const oobi = oobiArg || operator?.oobi;
  if (!oobi) return { summary: `no KERI operator pinned for ${network}; pass --keri <oobi url>` };
  try {
    const [tx, kel] = await Promise.all([provider.fetchTransaction(txHash), fetchKel(oobi)]);
    const result = verifyAttest(tx.cborHex, kel, operator?.aid);
    const summary =
      result.status === "absent"
        ? "this anchor transaction carries no CIP-0170 ATTEST"
        : result.status === "valid"
          ? `valid: ${result.aid} anchored this batch's digest ${result.digest.slice(0, 12)}… in KEL event ${result.sn.toString(16)}${result.operator ? " (VitaLedger's pinned identifier)" : " (identifier not pinned in this verifier)"}`
          : `INVALID: ${result.reason}`;
    return { result, summary };
  } catch (err) {
    return { summary: `could not check: ${(err as Error).message}` };
  }
}

interface RegistryReport {
  check?: IssuerCheck;
  mithril?: string;
  summary: string;
  error?: string;
}

/** --registry: the record's issuer against the on-chain registry (src/registry.ts). */
async function registryCheck(
  bundle: ProofBundle,
  digest: string,
  network: Network,
  provider: ReturnType<typeof koios>,
  values: { koios?: string; mithril?: boolean },
): Promise<RegistryReport> {
  const deployment = REGISTRY[network];
  const issuerId = (bundle.record as { issuer?: unknown })?.issuer;
  if (!deployment) return { summary: `no issuer registry on ${network}` };
  if (typeof issuerId !== "string") return { summary: "record has no issuer" };
  try {
    const entry = await lookupIssuer(issuerId, {
      policyId: deployment.policyId,
      locator: koiosRegistryLocator(network, values.koios),
      provider,
    });
    const check = checkIssuer(entry, digest, bundle.issuerSignature);
    let mithril: string | undefined;
    if (values.mithril && entry) {
      const inclusion = await verifyInclusionWithMithril(entry.txHash, await mithrilClient(network));
      mithril = inclusion.certified ? "entry transaction certified by Mithril" : `entry transaction: ${inclusion.reason}`;
    }
    const where = entry ? ` (entry ${entry.txHash.slice(0, 16)}…#${entry.outputIndex}${mithril ? `; ${mithril}` : ""})` : "";
    const summary =
      check.status === "not_registered"
        ? `${issuerId} is not in the on-chain registry`
        : check.status === "revoked"
          ? `${issuerId} is REVOKED in the on-chain registry${where}`
          : check.signature === "valid"
            ? `${issuerId} is active; the issuer's signature verifies under the registered key${where}`
            : check.signature === "invalid"
              ? `${issuerId} is active, but the bundle's signature does NOT verify under the registered key${where}`
              : `${issuerId} is active (registered key ${check.entry.pubkey.slice(0, 16)}…); the bundle carries no signature to check${where}`;
    return { check, mithril, summary };
  } catch (err) {
    return { summary: `could not read the registry: ${(err as Error).message}`, error: (err as Error).message };
  }
}

/** --all: every anchored record the API lists, re-verified from public data. */
async function verifyEverything(
  apiBase: string,
  values: { json?: boolean; koios?: string; blockfrost?: string; mithril?: boolean; complete?: boolean; network?: string },
): Promise<number> {
  const completeNetwork = (values.network ?? "preprod") as Network;
  const addresses = ANCHOR_ADDRESSES[completeNetwork];
  if (values.complete && !addresses) {
    console.error(`no anchor addresses pinned for ${completeNetwork}`);
    return 2;
  }
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
    completeness: values.complete
      ? { network: completeNetwork, addresses: addresses!, lister: koiosAnchorLister(completeNetwork, values.koios) }
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
    const c = report.completeness;
    if (c) {
      console.log("");
      console.log(`Completeness (from chain): ${c.history.length} batches on the operator's chain from ${c.history.at(-1)?.txHash.slice(0, 16) ?? "?"}… to ${c.history[0]?.txHash.slice(0, 16) ?? "?"}…`);
      for (const m of c.missing) console.log(`${m.recent ? "?" : "✗"} batch ${m.txHash} (${m.n} records) is on chain but not listed by the API${m.recent ? " (recent: the API may not have confirmed it yet)" : ""}`);
      for (const s of c.short) console.log(`✗ batch ${s.txHash} anchors ${s.n} records but the API lists ${s.listed}`);
      for (const p of c.problems) console.log(`✗ ${p}`);
      for (const o of c.outside) console.log(`· ${o.txHash} is an anchor outside the chain (for example a test made before launch); not counted`);
      console.log(c.complete ? "COMPLETE: the API lists every batch on the operator's chain, with all their records." : "INCOMPLETE: see above.");
      console.log("(The indexer is trusted to return the anchor address's full transaction list.)");
    }
  }
  const incomplete = report.completeness && !report.completeness.complete;
  const pendingOnly = report.completeness?.complete && report.completeness.missing.length > 0;
  if (report.invalid > 0 || incomplete) return 1;
  return report.errors.length > 0 || report.unsupported > 0 || pendingOnly ? 2 : 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`error: ${(err as Error).message}`);
    process.exit(2);
  },
);
