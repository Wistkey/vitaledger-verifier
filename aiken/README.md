# On-chain issuer registry (Aiken prototype)

**Status: Preprod prototype.** v1 verification (SPEC.md §§4–6) does not use it, and it isn't part of the published npm package.

## Why

In the pilot, the issuer registry is kept off chain by VitaLedger (SPEC §8). A verifier can prove a record was anchored, but has to take VitaLedger's word for which Ed25519 key belongs to which issuer. This prototype puts the registry itself on Cardano. Anyone can read who the registered issuers are and what their current keys are, and see every key rotation or revocation as a transaction, without asking VitaLedger.

## Design

One Plutus V3 validator, `issuer_registry(admin)` in [`validators/registry.ak`](validators/registry.ak), written in Aiken. It acts both as the **minting policy** of the registry tokens and as the **spending script** of the registry address, so policy id = script hash = the address's payment credential.

Each issuer is **one UTxO at the registry address** holding:
- **exactly one registry token**, whose asset name is `blake2b_224(issuer_id)`. The token is what makes an entry genuine. Anyone can send an output with any datum to a script address, but only the admin can mint a registry token. Readers ignore UTxOs that don't hold one.
- an **inline datum** `IssuerEntry { issuer_id, kind, pubkey, status, updated_at }`. `issuer_id` is `vl:issuer:<slug>` (at most 64 bytes), `kind` is Brand, Lab, Certifier or RecallAuthority, `pubkey` is the raw 32-byte Ed25519 key that signs `vitaledger.record.v1:<digest>`, and `status` is Active or Revoked.

| Action | Redeemer | Enforced on chain |
|---|---|---|
| Register | mint `Register` | admin signed; exactly 1 token minted; the only output carrying it is at the registry address with a well-formed, Active entry; token name = `blake2b_224(issuer_id)` |
| Rotate key / change kind / revoke | spend `Update` | admin signed; no registry mint or burn; one output at the same address carries the same token; the new entry is well formed with the same `issuer_id` |
| Retire | spend `Retire` + mint `Remove` | admin signed; the entry's token is burned |
| Sweep junk | spend (any) | admin signed; only for UTxOs at the address holding no registry token |

Revoking keeps the entry, with `status = Revoked`, so its history stays readable. Retiring removes it.

**Trust model.** The registry is still run by one admin key. The chain doesn't make the admin honest. It makes every change public, timestamped and permanent, and it guarantees the entries are well formed. Before production, the admin should become a multisig (for example a native script, or a list of admin key hashes with a threshold).

## Layout

| Path | What |
|---|---|
| `validators/registry.ak` | The validator and its 16 unit tests (`aiken check`) |
| `lib/vitaledger/registry.ak` | `IssuerEntry` type, well-formedness, token name |
| `plutus.json` | CIP-57 blueprint created by `aiken build` and committed (CI checks that it is current) |
| `scripts/` | Off-chain TypeScript using Lucid Evolution and Koios: `new-admin-wallet`, `register`, `update`, `list`, and an Emulator end-to-end run |
| `deployments/` | Preprod deployment record |

## Run

```sh
cd aiken
aiken check            # unit tests
aiken build            # regenerate plutus.json

cd scripts && npm ci
npm run e2e            # compiled validator in the Lucid Emulator, including attacker cases

# Preprod
npm run new-admin-wallet -- --out registry-admin.env      # fund the printed address from the faucet
npm run register -- --env registry-admin.env --id vl:issuer:acme-foods --kind brand --pubkey <64 hex>
npm run update   -- --env registry-admin.env --id vl:issuer:acme-foods --pubkey <new hex>   # or --revoke / --retire
npm run list                                                # read-only, uses deployments/preprod.json
```

`*.env` files are gitignored. Never commit the admin mnemonic.

## Not yet

- The verifier, the proof page and the API don't read the registry yet. The next step would be checking a record's issuer key against the on-chain entry, ideally through a Mithril-certified read.
- The admin is a single key, not a multisig.
- Mainnet is not deployed.
