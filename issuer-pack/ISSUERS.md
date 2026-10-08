# Publishing verifiable records with VitaLedger — issuer guide

> **Pilot on the Cardano Preprod testnet.** During the Cardano Accelerator pilot (Nov 2026 – Feb 2027), records are anchored on a test network. Nothing is live on mainnet.

This guide is for **brands, laboratories, certifiers and recall authorities** who want people using VitaBaby to be able to check that a statement about a food product is exactly what you published, and when you published it.

## What you get

- Each record you publish gets a **public proof page**. Anyone can open it with no wallet or account, and it shows that the record is unchanged since it was anchored on Cardano.
- VitaBaby shows a **"Verified record · Testnet"** badge on the product, with a link to that proof.
- An open-source verifier (`vitaledger-verify`, plus an independent Python implementation) lets anyone check a proof without trusting VitaLedger.

## What it does *not* do

- It doesn't certify that your claim is true. The proof shows that the record is **unchanged and came from you**. The content is your responsibility, just as on your label.
- It never stores personal data. **Records describe products only.** Never put a customer's, patient's or employee's name or identifier in a record, not even hashed.

## The quick way: the issuer studio (nothing to install)

Open **https://api.vitababy.ai/issuer** in a recent browser:

1. **Create a new key.** Your browser makes it and downloads `vitaledger-issuer-key.json`. Keep that file like a password, and send VitaLedger **only the public key** the page shows. The key never leaves your computer.
2. **We register you** and send you your issuer id, `vl:issuer:<your-slug>`. Load your key file in the studio and check the registration.
3. **Enter the barcode** and, optionally, **upload a photo of the label**. AI drafts the allergens and ingredients from it. Check every field against the label: the AI only fills in the form, and the statement is yours.
4. **Review the exact record, sign and publish.** You get its proof link. The studio can also put the photo's SHA-256 in the record, so you can later show which label it was drawn from; keep the photo.

The studio covers allergen declarations and label snapshots. For other claim types, updates and withdrawals, or to script publishing, use the command-line tool below. Both use the same key file.

## Five steps with the command-line tool

1. **Install the tool** (Node.js 20 or later):
   ```bash
   npm install -g vitaledger-verifier   # provides vitaledger-issuer and vitaledger-verify
   ```
2. **Create your signing key**, once per organisation:
   ```bash
   vitaledger-issuer keygen --out my-org.key.json
   ```
   Send VitaLedger **only the public key** it prints. Keep `my-org.key.json` like a password: anyone holding it can publish records in your name. If it leaks, tell us; we suspend the key and you create a new one.
3. **We register you** as `vl:issuer:<your-slug>` with your organisation name and kind (brand, lab, certifier or recall authority).
4. **Write a record.** Start from a template in `templates/`, set `issuer` to your id, set the product's barcode, and fill in the claim. Then check it:
   ```bash
   vitaledger-issuer check my-record.json
   ```
5. **Sign and submit:**
   ```bash
   vitaledger-issuer submit my-record.json --key my-org.key.json
   ```
   It prints the record's fingerprint and its public proof URL. Records are anchored in batches about once an hour, and the proof page turns green once the batch is on chain.

## Writing good records

- **One product, one statement.** Use one record per barcode and claim type.
- **Barcodes:** use the GTIN printed on the pack (8, 12, 13 or 14 digits). The tool checks the check digit.
- **Times:** `issuedAt` is UTC to the second, e.g. `2026-11-03T09:30:00Z`.
- **Numbers:** put the unit in the field name (`valueMgPerKg`, `energyKcal`). Plain decimals are fine; avoid huge integers and send IDs as text.
- **Source documents:** for a lab report or label artwork, put the file's SHA-256 in `sourceDigest`, e.g. `shasum -a 256 report.pdf`. The document stays with you, but anyone you later share it with can match it to the record.

### Recommended fields for each claim type

| `claim.type` | Recommended fields |
|---|---|
| `allergen_declaration` | `contains`, `mayContain`: arrays of allergen tokens (below); `basis` (free text) |
| `lab_result` | `analyte`, `value…` with unit, `limit…` with unit, `result` (`below_limit` / `above_limit` / `not_detected`), `method`, `accreditation`, `batchOrLot`, `testedOn` |
| `certification` | `scheme`, `certificateId`, `certifiedBy`, `validFrom`, `validUntil` |
| `label_snapshot` | `ingredientsText`, `allergens`, `per100` `{unit, energyKcal, fatG, carbsG, sugarsG, proteinG, saltG}`, `labelVersion` |
| `recall_notice` | `reason`, `allergens`, `lots`, `bestBefore`, `action`, `officialNoticeUrl` |

**Allergen tokens:** `dairy`, `egg`, `peanut`, `tree_nut`, `soy`, `gluten`, `fish`, `shellfish` (crustaceans only), `sesame`, `celery`, `mustard`, `sulphites`, `lupin`, `molluscs`: the 14 allergens of UK and EU food law, which VitaBaby lets people watch for.

## Correcting or withdrawing a record

Published records never change. To change one, publish a new record whose `prev` is the old record's fingerprint:
- `"eventType": "record_updated"` replaces it;
- `"eventType": "revoked"` withdraws it (see `templates/revocation.json`).

VitaBaby then stops showing the old record as current, and its proof page links to the newer one. A record can be superseded only once, so a chain of records never forks.

## Limits

- A record can be at most 16 KB of JSON, nested at most 8 levels.
- You can submit up to 30 records a minute.
- Submitting the same record twice is harmless: you get the same fingerprint back.

Questions: contact the VitaLedger team. The full technical specification is in [`../SPEC.md`](../SPEC.md).
