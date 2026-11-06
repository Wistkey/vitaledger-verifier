import { describe, expect, it } from "vitest";
import { assertPassingToolingEvidence, TOOLING_EVIDENCE_SCHEMA, validateToolingEvidence, type ToolingEvidence } from "../scripts/tooling-evidence.js";

const valid = (): ToolingEvidence => ({
  schema: TOOLING_EVIDENCE_SCHEMA,
  tool: "Yaci DevKit",
  toolVersion: "0.12.0",
  mode: "ci",
  network: "yaci-local",
  startedAt: "2026-11-06T09:00:00.000Z",
  finishedAt: "2026-11-06T09:01:00.000Z",
  status: "passed",
  assertions: [{ name: "transaction bytes match", ok: true }],
  source: { recordDigest: "11".repeat(32) },
  transaction: { txHash: "22".repeat(32), metadataLabel: 22092 },
});

describe("tooling evidence", () => {
  it("accepts a complete passing report", () => {
    expect(() => validateToolingEvidence(valid())).not.toThrow();
  });

  it("rejects a passing status with a failed assertion", () => {
    const evidence = valid();
    evidence.assertions.push({ name: "root persisted", ok: false });
    expect(() => validateToolingEvidence(evidence)).toThrow(/status disagrees/);
  });

  it("rejects malformed chain identifiers", () => {
    const evidence = valid();
    evidence.transaction = { txHash: "not-a-hash" };
    expect(() => validateToolingEvidence(evidence)).toThrow(/txHash/);
  });

  it("accepts a structurally valid failure for retention but rejects it as a passing gate", () => {
    const evidence = valid();
    evidence.status = "failed";
    evidence.assertions = [{ name: "review receipt is present", ok: false }];
    evidence.error = "receipt missing";
    expect(() => validateToolingEvidence(evidence)).not.toThrow();
    expect(() => assertPassingToolingEvidence(evidence)).toThrow(/receipt missing/);
  });
});
