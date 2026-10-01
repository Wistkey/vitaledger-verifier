#!/usr/bin/env node
/**
 * vitaledger-issuer — tools for organisations publishing VitaLedger records.
 *
 *   vitaledger-issuer keygen --out issuer.key.json
 *   vitaledger-issuer check  record.json
 *   vitaledger-issuer sign   record.json --key issuer.key.json [--out request.json]
 *   vitaledger-issuer submit record.json --key issuer.key.json [--api https://api.vitababy.ai]
 *
 * Exit codes: 0 ok, 1 invalid record or rejected submission, 2 usage/IO error.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { canonicalise } from "./canonical.js";
import { recordDigest } from "./digest.js";
import { generateIssuerKey, InvalidRecordError, signRecord } from "./issuer.js";
import { validateRecord } from "./record.js";

const USAGE = `usage:
  vitaledger-issuer keygen --out <issuer.key.json>
  vitaledger-issuer check  <record.json>
  vitaledger-issuer sign   <record.json> --key <issuer.key.json> [--out <request.json>]
  vitaledger-issuer submit <record.json> --key <issuer.key.json> [--api <base url>]`;

const readJson = (path: string) => JSON.parse(readFileSync(path, "utf8"));

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      out: { type: "string" },
      key: { type: "string" },
      api: { type: "string", default: "https://api.vitababy.ai" },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  const [command, file] = positionals;
  if (values.help || !command) {
    console.error(USAGE);
    return 2;
  }

  if (command === "keygen") {
    if (!values.out) return (console.error(USAGE), 2);
    const key = generateIssuerKey();
    writeFileSync(values.out, JSON.stringify(key, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    console.log(`Wrote ${values.out} (private: keep it safe, never email it).`);
    console.log(`Public key to send to VitaLedger:\n${key.publicKey}`);
    return 0;
  }

  if (!file) return (console.error(USAGE), 2);
  const record = readJson(file);

  if (command === "check") {
    const problems = validateRecord(record);
    if (problems.length) {
      console.log(`INVALID:\n- ${problems.join("\n- ")}`);
      return 1;
    }
    console.log(`Valid vitaledger.record.v1\nrecord digest: ${recordDigest(record)}\ncanonical form:\n${canonicalise(record)}`);
    return 0;
  }

  if (command === "sign" || command === "submit") {
    if (!values.key) return (console.error(USAGE), 2);
    let body;
    try {
      body = signRecord(record, readJson(values.key).privateKeyPem);
    } catch (e) {
      if (e instanceof InvalidRecordError) {
        console.log(`INVALID:\n- ${e.problems.join("\n- ")}`);
        return 1;
      }
      throw e;
    }
    const request = { record: body.record, signature: body.signature };
    if (command === "sign") {
      const json = JSON.stringify(request, null, 2) + "\n";
      if (values.out) writeFileSync(values.out, json);
      else process.stdout.write(json);
      console.error(`record digest: ${body.recordDigest}`);
      return 0;
    }
    const res = await fetch(`${values.api.replace(/\/$/, "")}/api/v1/attestation-records`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const reply = (await res.json().catch(() => ({}))) as { data?: { proofUrl?: string; status?: string }; error?: { code: string; message: string } };
    if (!res.ok) {
      console.log(`REJECTED (${res.status} ${reply.error?.code ?? ""}): ${reply.error?.message ?? "no details"}`);
      return 1;
    }
    console.log(`${res.status === 201 ? "Accepted" : "Already submitted"}: ${reply.data?.status}`);
    console.log(`record digest: ${body.recordDigest}`);
    console.log(`public proof (live once anchored, about an hour): ${reply.data?.proofUrl}`);
    return 0;
  }

  console.error(USAGE);
  return 2;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`error: ${(err as Error).message}`);
    process.exit(2);
  },
);
