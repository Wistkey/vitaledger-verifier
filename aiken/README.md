# On-chain issuer registry (Aiken prototype)

**Status: Preprod prototype.** v1 verification (SPEC.md §§4–6) does not use it, and it isn't part of the published npm package.

## Why

In the pilot, the issuer registry is kept off chain by VitaLedger (SPEC §8). A verifier can prove a record was anchored, but has to take VitaLedger's word for which Ed25519 key belongs to which issuer. This prototype puts the registry itself on Cardano. Anyone can read who the registered issuers are and what their current keys are, and see every key rotation or revocation as a transaction, without asking VitaLedger.

## Design

One Plutus V3 validator, `issuer_registry(admins)` in [`validators/registry.ak`](validators/registry.ak), written in Aiken. It acts both as the **minting policy** of the registry tokens and as the **spending script** of the registry address, so policy id = script hash = the address's payment credential.

Each issuer is **one UTxO at the registry address** holding:
- **exactly one registry token**, whose asset name is `blake2b_224(issuer_id)`. The token is what makes an entry genuine. Anyone can send an output with any datum to a script address, but only the admins can mint a registry token. Readers ignore UTxOs that don't hold one.
- an **inline datum** `IssuerEntry { issuer_id, kind, pubkey, status, updated_at }`. `issuer_id` is `vl:issuer:<slug>` (at most 64 bytes), `kind` is Brand, Lab, Certifier or RecallAuthority, `pubkey` is the raw 32-byte Ed25519 key that signs `vitaledger.record.v1:<digest>`, and `status` is Active or Revoked.

| Action | Redeemer | Enforced on chain |
|---|---|---|
| Register | mint `Register` | M-of-N admins signed; exactly 1 token minted; the only output carrying it is at the registry address with a well-formed, Active entry; token name = `blake2b_224(issuer_id)` |
| Rotate key / change kind / revoke | spend `Update` | M-of-N admins signed; no registry mint or burn; one output at the same address carries the same token; the new entry is well formed with the same `issuer_id` |
| Retire | spend `Retire` + mint `Remove` | M-of-N admins signed; the entry's token is burned |
| Sweep junk | spend (any) | M-of-N admins signed; only for UTxOs at the address holding no registry token (junk, or the reference-script output when replacing it) |

Revoking keeps the entry, with `status = Revoked`, so its history stays readable. Retiring removes it.

**Admins: M of N.** The validator is parameterised by `MultiSig { keys, required }`, a list of admin payment-key hashes and a threshold. At least `required` *distinct* admin keys must sign every change; duplicate keys or signatures count once, and `required = 0` is rejected. Preprod uses **2 of 3**. Changing the admin set means a new script hash, so a new policy and address: a migration, by design.

**Reference script (CIP-33).** The script (about 1.6 kB) is published once as a reference script at the registry address (`npm run deploy-ref`). Registry transactions then read it from chain instead of carrying it: a register transaction drops from about 2.4 kB to about 0.6 kB.

**Trust model.** The chain doesn't make the admins honest. It makes every change public, timestamped and permanent, it needs a quorum of admins, and it guarantees the entries are well formed.

## Layout

| Path | What |
|---|---|
| `validators/registry.ak` | The validator and its 20 unit tests (`aiken check`) |
| `lib/vitaledger/registry.ak` | `IssuerEntry` and `MultiSig` types, well-formedness, quorum check, token name |
| `plutus.json` | CIP-57 blueprint created by `aiken build` and committed (CI checks that it is current) |
| `scripts/` | Off-chain TypeScript using Lucid Evolution and Koios: `new-admin-wallet`, `deploy-ref`, `register`, `update`, `list`, and an Emulator end-to-end run (2-of-3, reference script, attacker cases) |
| `deployments/` | Preprod deployment record: admin keys, threshold, policy, address, reference script |

## Run

```sh
cd aiken
aiken check            # unit tests
aiken build            # regenerate plutus.json

cd scripts && npm ci
npm run e2e            # compiled validator in the Lucid Emulator, including attacker cases

# Preprod (admin keys + threshold in deployments/preprod.json)
npm run new-admin-wallet -- --out admin-1.env             # once per admin; fund the fee payer from the faucet
npm run deploy-ref -- --env admin-1.env                    # once: CIP-33 reference script
npm run register -- --env admin-1.env --cosign admin-2.env --id vl:issuer:acme-foods --kind brand --pubkey <64 hex>
npm run update   -- --env admin-1.env --cosign admin-3.env --id vl:issuer:acme-foods --pubkey <new hex>   # or --revoke / --retire
npm run list                                                # read-only
```

`*.env` files are gitignored. Never commit an admin mnemonic. `--cosign` signs locally, so for real use each admin keeps their own key; passing a partly signed transaction between admins is a follow-up.

## Reading it

`vitaledger-verify bundle.json --registry [--mithril]` looks up the record's issuer (`src/registry.ts`). It decodes the entry from the raw CBOR of the transaction that created it and checks that against its transaction id. The issuer must hold exactly one token, at the script address, with the token name bound to the issuer id. With `--mithril` the entry transaction is also certified, so Koios is trusted only for "this UTxO is the current one". When the bundle carries `issuerSignature`, it is verified against the registered key. The pinned policy id is in `REGISTRY` in `src/registry.ts`.

## Not yet

- Mainnet is not deployed.
