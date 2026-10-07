/**
 * Writes test-vectors/v1.json: canonical forms, digests, the batch root and
 * every inclusion proof for the example records. Other implementations should
 * reproduce every value byte for byte.
 */
import { writeFileSync } from "node:fs";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalise } from "../src/canonical.js";
import { recordDigest } from "../src/digest.js";
import { inclusionProof, leafHash, merkleRoot } from "../src/merkle.js";
import { buildBatchAnchor, VITALEDGER_LABEL } from "../src/metadata.js";
import { validateRecord } from "../src/record.js";
import { allergenRecord, labRecord, recallRecord } from "../test/fixtures/records.js";

const records = [allergenRecord, labRecord, recallRecord];

// Edge cases implementations most often get wrong.
const updateRecord = {
  ...allergenRecord,
  eventType: "record_updated",
  claim: { type: "allergen_declaration", contains: ["milk"], mayContain: [] },
  issuedAt: "2026-12-01T08:00:00Z",
  prev: recordDigest(allergenRecord),
};
const productRecord = {
  schema: "vitaledger.record.v1",
  eventType: "attestation_created",
  subject: { kind: "vl_product", value: "3f2b8c1e-9a4d-4e6b-8f1a-2c3d4e5f6a7b" },
  issuer: "vl:issuer:example-lab",
  claim: {
    type: "lab_result",
    // ECMAScript number forms: exponent switch-over points, -0, binary fractions.
    numbers: [1e21, 1e20, 1e-7, 0.000001, -0, 0.1, 100, 4.5, 333333333.3333333, 9007199254740993],
    // Non-ASCII values and keys that sort by UTF-16 code units, not code points.
    note: "Café ✓ 日本 😀 \u0000 \"quoted\"",
    "\u20ac": 1, "\ud83d\ude00": 2, "\ufb33": 3, "a": 4,
  },
  issuedAt: "2028-02-29T23:59:59Z",
};
const edgeRecords = [updateRecord, productRecord];
// Spec 1.1 (additive): a relayed official notice. Kept apart so earlier vectors don't change.
const noticeRecord = {
  schema: "vitaledger.record.v1",
  eventType: "attestation_created",
  subject: { kind: "official_notice", value: "uk-fsa:FSA-AA-45-2026" },
  issuer: "vl:issuer:vitaledger-relay",
  claim: {
    type: "recall_notice",
    authority: "UK Food Standards Agency",
    title: "Example Foods recalls Oat Bars because they contain milk not mentioned on the label",
    allergens: ["dairy"],
    products: [{ name: "Example Foods Oat Bars", packSize: "6 x 30g", batchCodes: ["L2611A"], bestBefore: ["2027-03-01"] }],
    officialNoticeUrl: "https://www.food.gov.uk/news-alerts/alert/fsa-aa-45-2026",
    officialPublishedAt: "2026-11-05",
  },
  sourceDigest: "5bb4a606d17a5798695f442c779a8c72f4d7eadac91b9b58867cf38ba05a47ef",
  issuedAt: "2026-11-05T10:00:00Z",
};
const extensionRecords = [noticeRecord];
if (validateRecord(noticeRecord).length) throw new Error(`notice record invalid: ${validateRecord(noticeRecord)}`);
const invalidRecords = [
  { why: "revoked without prev", record: { ...allergenRecord, eventType: "revoked" } },
  { why: "prev on attestation_created", record: { ...allergenRecord, prev: recordDigest(labRecord) } },
  { why: "uppercase hex in prev", record: { ...updateRecord, prev: recordDigest(allergenRecord).toUpperCase() } },
  { why: "impossible date", record: { ...allergenRecord, issuedAt: "2026-02-30T09:30:00Z" } },
  { why: "fractional seconds", record: { ...allergenRecord, issuedAt: "2026-11-03T09:30:00.000Z" } },
  { why: "bad GTIN check digit", record: { ...allergenRecord, subject: { kind: "gtin", value: "4006381333932" } } },
  { why: "unknown top-level field", record: { ...allergenRecord, childName: "x" } },
  { why: "extra member in subject", record: { ...allergenRecord, subject: { kind: "gtin", value: "4006381333931", lot: "A1" } } },
  { why: "uppercase UUID", record: { ...productRecord, subject: { kind: "vl_product", value: "3F2B8C1E-9A4D-4E6B-8F1A-2C3D4E5F6A7B" } } },
  { why: "unknown claim type", record: { ...allergenRecord, claim: { type: "opinion" } } },
  { why: "unknown subject kind", record: { ...allergenRecord, subject: { kind: "batch", value: "L2611A" } } },
  { why: "official notice without authority", record: { ...allergenRecord, subject: { kind: "official_notice", value: "FSA-AA-45-2026" } } },
];
for (const r of edgeRecords) if (validateRecord(r).length) throw new Error(`edge record invalid: ${validateRecord(r)}`);
for (const r of invalidRecords) if (!validateRecord(r.record).length) throw new Error(`expected invalid: ${r.why}`);
const chainedDigests = edgeRecords.map(recordDigest);
const chainedRoot = merkleRoot(chainedDigests);
const digests = records.map(recordDigest);
const root = merkleRoot(digests);

const vectors = {
  description: "VitaLedger record v1 / anchor v1 test vectors. See SPEC.md.",
  records: records.map((record, i) => ({
    record,
    canonical: canonicalise(record),
    recordDigest: digests[i],
    leafHash: bytesToHex(leafHash(digests[i])),
    proof: inclusionProof(digests, i),
  })),
  batch: {
    merkleRoot: root,
    metadata: { [VITALEDGER_LABEL]: buildBatchAnchor({ r: root, n: digests.length, i: "vl:registry:vitaledger" }) },
  },
  edgeRecords: edgeRecords.map((record, i) => ({
    record,
    canonical: canonicalise(record),
    recordDigest: chainedDigests[i],
    proof: inclusionProof(chainedDigests, i),
  })),
  invalidRecords,
  extensionRecords: extensionRecords.map((record) => ({
    since: "spec 1.1",
    record,
    canonical: canonicalise(record),
    recordDigest: recordDigest(record),
  })),
  chainedBatch: {
    description: "A second batch from the same registry; `p` links it to the first batch's transaction.",
    merkleRoot: chainedRoot,
    metadata: {
      [VITALEDGER_LABEL]: buildBatchAnchor({
        r: chainedRoot,
        n: chainedDigests.length,
        i: "vl:registry:vitaledger",
        p: "7111eecc3510eb132bc4ec1794514a58f9ca812b2995a23a02bc7bcc7a6a50ff",
      }),
    },
  },
  merkleSizes: [1, 2, 3, 4, 5, 7, 8, 9].map((n) => {
    const ds = Array.from({ length: n }, (_, i) => digests[i % 3].slice(0, 62) + i.toString(16).padStart(2, "0"));
    return { recordDigests: ds, merkleRoot: merkleRoot(ds) };
  }),
};

writeFileSync("test-vectors/v1.json", JSON.stringify(vectors, null, 2) + "\n");
console.log(`wrote test-vectors/v1.json (root ${root})`);
