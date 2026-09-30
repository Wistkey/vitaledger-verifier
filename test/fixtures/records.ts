import type { RecordV1 } from "../../src/record.js";

export const allergenRecord: RecordV1 = {
  schema: "vitaledger.record.v1",
  eventType: "attestation_created",
  subject: { kind: "gtin", value: "4006381333931" },
  issuer: "vl:issuer:example-brand",
  claim: { type: "allergen_declaration", contains: ["milk", "soy"], mayContain: ["peanut"] },
  sourceDigest: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  issuedAt: "2026-11-03T09:30:00Z",
};

export const labRecord: RecordV1 = {
  schema: "vitaledger.record.v1",
  eventType: "attestation_created",
  subject: { kind: "gtin", value: "96385074" },
  issuer: "vl:issuer:example-lab",
  claim: { type: "lab_result", analyte: "lead", valueMgPerKg: 0.01, limitMgPerKg: 0.02, method: "ICP-MS" },
  issuedAt: "2026-11-04T14:00:00Z",
};

export const recallRecord: RecordV1 = {
  schema: "vitaledger.record.v1",
  eventType: "attestation_created",
  subject: { kind: "gtin", value: "036000291452" },
  issuer: "vl:issuer:example-authority",
  claim: { type: "recall_notice", reason: "undeclared sesame", lots: ["L2611A"] },
  issuedAt: "2026-11-05T08:00:00Z",
};
