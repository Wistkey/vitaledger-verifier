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
import { allergenRecord, labRecord, recallRecord } from "../test/fixtures/records.js";

const records = [allergenRecord, labRecord, recallRecord];
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
  merkleSizes: [1, 2, 3, 4, 5, 7, 8, 9].map((n) => {
    const ds = Array.from({ length: n }, (_, i) => digests[i % 3].slice(0, 62) + i.toString(16).padStart(2, "0"));
    return { recordDigests: ds, merkleRoot: merkleRoot(ds) };
  }),
};

writeFileSync("test-vectors/v1.json", JSON.stringify(vectors, null, 2) + "\n");
console.log(`wrote test-vectors/v1.json (root ${root})`);
