/**
 * VitaLedger record, schema `vitaledger.record.v1` — see SPEC.md §3.
 * A record is a statement by an issuer about a product. It never carries
 * data about a person.
 */
import { isHex32 } from "./digest.js";

export const RECORD_SCHEMA_V1 = "vitaledger.record.v1";

export const EVENT_TYPES = ["attestation_created", "record_updated", "revoked"] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export const CLAIM_TYPES = [
  "allergen_declaration",
  "certification",
  "lab_result",
  "label_snapshot",
  "recall_notice",
] as const;
export type ClaimType = (typeof CLAIM_TYPES)[number];

export type Subject = { kind: "gtin"; value: string } | { kind: "vl_product"; value: string };

export interface RecordV1 {
  schema: typeof RECORD_SCHEMA_V1;
  eventType: EventType;
  subject: Subject;
  issuer: string;
  claim: { type: ClaimType; [field: string]: unknown };
  sourceDigest?: string;
  issuedAt: string;
  prev?: string;
}

export const ISSUER_ID = /^vl:issuer:[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/;
const ISSUED_AT = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOP_LEVEL_KEYS = new Set(["schema", "eventType", "subject", "issuer", "claim", "sourceDigest", "issuedAt", "prev"]);

/** True when the YYYY-MM-DD part names a real calendar day (no 2026-02-30). */
function isCalendarDate(iso: string): boolean {
  const [y, m, d] = iso.slice(0, 10).split("-").map(Number);
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}

/** GS1 mod-10 check digit for GTIN-8, -12, -13 and -14. */
export function isValidGtin(value: string): boolean {
  if (!/^(\d{8}|\d{12,14})$/.test(value)) return false;
  const digits = [...value].map(Number);
  const check = digits.pop()!;
  const sum = digits
    .reverse()
    .reduce((acc, d, i) => acc + d * (i % 2 === 0 ? 3 : 1), 0);
  return (10 - (sum % 10)) % 10 === check;
}

/** Returns a list of problems; an empty list means the record is valid v1. */
export function validateRecord(input: unknown): string[] {
  const errors: string[] = [];
  if (typeof input !== "object" || input === null || Array.isArray(input)) return ["record must be a JSON object"];
  const r = input as Record<string, unknown>;

  for (const key of Object.keys(r)) if (!TOP_LEVEL_KEYS.has(key)) errors.push(`unknown field "${key}"`);
  if (r.schema !== RECORD_SCHEMA_V1) errors.push(`schema must be "${RECORD_SCHEMA_V1}"`);
  if (!EVENT_TYPES.includes(r.eventType as EventType)) errors.push(`eventType must be one of ${EVENT_TYPES.join(", ")}`);

  const s = r.subject as Record<string, unknown> | undefined;
  if (typeof s !== "object" || s === null || Array.isArray(s)) {
    errors.push("subject must be an object");
  } else if (Object.keys(s).some((k) => k !== "kind" && k !== "value")) {
    errors.push("subject may only have kind and value");
  } else if (s.kind === "gtin") {
    if (typeof s.value !== "string" || !isValidGtin(s.value)) errors.push("subject.value must be a GTIN with a valid check digit");
  } else if (s.kind === "vl_product") {
    if (typeof s.value !== "string" || !UUID.test(s.value)) errors.push("subject.value must be a lowercase UUID");
  } else {
    errors.push('subject.kind must be "gtin" or "vl_product"');
  }

  if (typeof r.issuer !== "string" || !ISSUER_ID.test(r.issuer)) errors.push("issuer must match vl:issuer:<slug>");

  const c = r.claim as Record<string, unknown> | undefined;
  if (typeof c !== "object" || c === null || Array.isArray(c)) errors.push("claim must be an object");
  else if (!CLAIM_TYPES.includes(c.type as ClaimType)) errors.push(`claim.type must be one of ${CLAIM_TYPES.join(", ")}`);

  if (r.sourceDigest !== undefined && !isHex32(r.sourceDigest)) errors.push("sourceDigest must be 64 lowercase hex characters");
  if (typeof r.issuedAt !== "string" || !ISSUED_AT.test(r.issuedAt) || !isCalendarDate(r.issuedAt)) {
    errors.push("issuedAt must be a real UTC date-time with second precision, e.g. 2026-11-03T09:30:00Z");
  }

  if (r.eventType === "attestation_created") {
    if (r.prev !== undefined) errors.push("prev is not allowed on attestation_created");
  } else if (!isHex32(r.prev)) {
    errors.push(`prev (the digest of the record being ${r.eventType === "revoked" ? "revoked" : "updated"}) is required`);
  }
  return errors;
}
