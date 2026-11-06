import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const TOOLING_EVIDENCE_SCHEMA = "vitaledger.tooling-evidence.v1" as const;

export interface ToolingAssertion {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface ToolingEvidence {
  schema: typeof TOOLING_EVIDENCE_SCHEMA;
  tool: string;
  toolVersion: string;
  mode: "ci" | "local" | "shadow-canary";
  network: "yaci-local" | "yano-local" | "preprod";
  startedAt: string;
  finishedAt: string;
  status: "passed" | "failed";
  assertions: ToolingAssertion[];
  source?: { recordDigest?: string; proofUrl?: string; [key: string]: unknown };
  transaction?: { txHash?: string; metadataLabel?: number; provider?: string; [key: string]: unknown };
  error?: string;
  [key: string]: unknown;
}

const iso = (value: unknown): value is string =>
  typeof value === "string" && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;

export function validateToolingEvidence(value: unknown): asserts value is ToolingEvidence {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("evidence must be an object");
  const e = value as Record<string, unknown>;
  if (e.schema !== TOOLING_EVIDENCE_SCHEMA) throw new Error(`schema must be ${TOOLING_EVIDENCE_SCHEMA}`);
  for (const field of ["tool", "toolVersion"] as const) {
    if (typeof e[field] !== "string" || e[field].length === 0) throw new Error(`${field} must be a non-empty string`);
  }
  if (!["ci", "local", "shadow-canary"].includes(String(e.mode))) throw new Error("invalid evidence mode");
  if (!["yaci-local", "yano-local", "preprod"].includes(String(e.network))) throw new Error("invalid evidence network");
  if (!iso(e.startedAt) || !iso(e.finishedAt)) throw new Error("evidence timestamps must be canonical ISO dates");
  if (Date.parse(e.finishedAt as string) < Date.parse(e.startedAt as string)) throw new Error("evidence finishedAt precedes startedAt");
  if (!Array.isArray(e.assertions) || e.assertions.length === 0) throw new Error("evidence must contain assertions");
  for (const assertion of e.assertions) {
    if (!assertion || typeof assertion !== "object" || Array.isArray(assertion)) throw new Error("invalid assertion");
    const a = assertion as Record<string, unknown>;
    if (typeof a.name !== "string" || a.name.length === 0 || typeof a.ok !== "boolean") throw new Error("invalid assertion");
  }
  const failed = (e.assertions as ToolingAssertion[]).some((a) => !a.ok);
  if (e.status !== (failed ? "failed" : "passed")) throw new Error("evidence status disagrees with its assertions");
  const digest = (e.source as Record<string, unknown> | undefined)?.recordDigest;
  if (digest !== undefined && (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest))) throw new Error("invalid source recordDigest");
  const txHash = (e.transaction as Record<string, unknown> | undefined)?.txHash;
  if (txHash !== undefined && (typeof txHash !== "string" || !/^[0-9a-f]{64}$/.test(txHash))) throw new Error("invalid transaction txHash");
}

export function assertPassingToolingEvidence(value: unknown): asserts value is ToolingEvidence {
  validateToolingEvidence(value);
  if (value.status !== "passed") throw new Error(`tooling evidence reports failure${value.error ? `: ${value.error}` : ""}`);
}

export async function writeToolingEvidence(path: string, evidence: ToolingEvidence): Promise<void> {
  validateToolingEvidence(evidence);
  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(path, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
}

async function main() {
  const path = process.argv[2];
  if (!path) throw new Error("usage: tsx scripts/tooling-evidence.ts <evidence.json>");
  const evidence: unknown = JSON.parse(await readFile(path, "utf8"));
  assertPassingToolingEvidence(evidence);
  console.log(`VALID ${evidence.tool} ${evidence.toolVersion} evidence: ${path}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  void main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
