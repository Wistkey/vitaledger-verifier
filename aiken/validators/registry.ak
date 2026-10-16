//// VitaLedger issuer registry (Preprod prototype; not used by v1 verification).
////
//// One validator serves as both the minting policy of the registry tokens
//// and the spending script of the registry address, so policy id = script
//// hash = payment credential of every entry. Every action needs the admin's
//// signature; the script's job is to keep the registry well formed: one
//// token per entry, the token stays at the registry address, the token name
//// is bound to the issuer id, and the issuer id never changes.

use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Address, Script}
use cardano/assets.{AssetName, Assets, PolicyId}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use vitaledger/registry.{
  Active, Brand, IssuerEntry, IssuerStatus, Revoked, expect_entry,
  is_well_formed, registry_tokens, token_name,
}

pub type MintAction {
  /// Mint one token for a new entry.
  Register
  /// Burn one token (entry removed together with `Retire`).
  Remove
}

pub type SpendAction {
  /// Replace the entry's datum: rotate the key, change the kind, or revoke.
  Update
  /// Spend the entry and burn its token.
  Retire
}

validator issuer_registry(admin: VerificationKeyHash) {
  mint(redeemer: MintAction, policy_id: PolicyId, self: Transaction) {
    expect list.has(self.extra_signatories, admin)
    expect [Pair(name, quantity)] = registry_tokens(self.mint, policy_id)
    when redeemer is {
      Register -> {
        expect quantity == 1
        // Exactly one output carries the new token, and nothing else of ours.
        expect [output] = list.filter(
          self.outputs,
          fn(o) { registry_tokens(o.value, policy_id) != [] },
        )
        expect [Pair(name, 1)] == registry_tokens(output.value, policy_id)
        expect output.address.payment_credential == Script(policy_id)
        let entry = expect_entry(output)
        and {
          is_well_formed(entry),
          entry.status == Active,
          name == token_name(entry.issuer_id),
        }
      }
      Remove -> quantity == -1
    }
  }

  spend(
    _datum: Option<Data>,
    redeemer: SpendAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect list.has(self.extra_signatories, admin)
    expect Some(own_input) = list.find(
      self.inputs,
      fn(i) { i.output_reference == own_ref },
    )
    let own_address = own_input.output.address
    expect Script(policy_id) = own_address.payment_credential
    when registry_tokens(own_input.output.value, policy_id) is {
      // Not a registry entry (e.g. someone sent ADA or a fake datum to the
      // script address): the admin may sweep it.
      [] -> True
      [Pair(name, 1)] -> {
        let old_entry = expect_entry(own_input.output)
        when redeemer is {
          Update -> {
            // Entries are only moved here, never minted or burned alongside.
            expect registry_tokens(self.mint, policy_id) == []
            expect [output] = list.filter(
              self.outputs,
              fn(o) { registry_tokens(o.value, policy_id) == [Pair(name, 1)] },
            )
            expect output.address == own_address
            let new_entry = expect_entry(output)
            and {
              is_well_formed(new_entry),
              new_entry.issuer_id == old_entry.issuer_id,
            }
          }
          Retire -> registry_tokens(self.mint, policy_id) == [Pair(name, -1)]
        }
      }
      _ -> False
    }
  }

  else(_) {
    fail
  }
}

// ## Tests

const admin: VerificationKeyHash =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const intruder: VerificationKeyHash =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const policy: PolicyId =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const issuer_id: ByteArray = "vl:issuer:acme-foods"

const key_a: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

const key_b: ByteArray =
  #"2222222222222222222222222222222222222222222222222222222222222222"

const own_ref: OutputReference =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
    output_index: 0,
  }

fn entry(id: ByteArray, pubkey: ByteArray, status: IssuerStatus) -> IssuerEntry {
  IssuerEntry { issuer_id: id, kind: Brand, pubkey, status, updated_at: 0 }
}

fn entry_output(
  address: Address,
  tokens: Pairs<AssetName, Int>,
  datum: IssuerEntry,
) -> Output {
  let value = list.foldl(
    tokens,
    assets.from_lovelace(2_000_000),
    fn(Pair(n, q), acc) { assets.add(acc, policy, n, q) },
  )
  Output { address, value, datum: InlineDatum(datum), reference_script: None }
}

fn registry_address() -> Address {
  address.from_script(policy)
}

fn register_tx(output: Output, signer: VerificationKeyHash) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    outputs: [output],
    mint: assets.from_asset(policy, token_name(issuer_id), 1),
    extra_signatories: [signer],
  }
}

fn good_output() -> Output {
  entry_output(
    registry_address(),
    [Pair(token_name(issuer_id), 1)],
    entry(issuer_id, key_a, Active),
  )
}

fn spend_tx(
  input: Output,
  outputs: List<Output>,
  mint: Assets,
  signer: VerificationKeyHash,
) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [Input { output_reference: own_ref, output: input }],
    outputs,
    mint,
    extra_signatories: [signer],
  }
}

fn updated(datum: IssuerEntry) -> Output {
  entry_output(registry_address(), [Pair(token_name(issuer_id), 1)], datum)
}

test register_ok() {
  issuer_registry.mint(
    admin,
    Register,
    policy,
    register_tx(good_output(), admin),
  )
}

test register_needs_admin() fail {
  issuer_registry.mint(
    admin,
    Register,
    policy,
    register_tx(good_output(), intruder),
  )
}

test register_token_sent_elsewhere() fail {
  let output = entry_output(
    address.from_verification_key(intruder),
    [Pair(token_name(issuer_id), 1)],
    entry(issuer_id, key_a, Active),
  )
  issuer_registry.mint(admin, Register, policy, register_tx(output, admin))
}

test register_bad_pubkey_length() fail {
  let output = entry_output(
    registry_address(),
    [Pair(token_name(issuer_id), 1)],
    entry(issuer_id, #"1111", Active),
  )
  issuer_registry.mint(admin, Register, policy, register_tx(output, admin))
}

test register_bad_issuer_prefix() fail {
  let id = "acme-foods"
  let output = entry_output(
    registry_address(),
    [Pair(token_name(issuer_id), 1)],
    entry(id, key_a, Active),
  )
  issuer_registry.mint(admin, Register, policy, register_tx(output, admin))
}

test register_name_not_bound_to_id() fail {
  let output = entry_output(
    registry_address(),
    [Pair(token_name(issuer_id), 1)],
    entry("vl:issuer:someone-else", key_a, Active),
  )
  issuer_registry.mint(admin, Register, policy, register_tx(output, admin))
}

test register_two_tokens() fail {
  let tx = Transaction {
    ..register_tx(good_output(), admin),
    mint: assets.from_asset(policy, token_name(issuer_id), 2),
  }
  issuer_registry.mint(admin, Register, policy, tx)
}

test register_revoked_entry() fail {
  let output = entry_output(
    registry_address(),
    [Pair(token_name(issuer_id), 1)],
    entry(issuer_id, key_a, Revoked),
  )
  issuer_registry.mint(admin, Register, policy, register_tx(output, admin))
}

test update_rotates_key() {
  let tx = spend_tx(
    good_output(),
    [updated(entry(issuer_id, key_b, Active))],
    assets.zero,
    admin,
  )
  issuer_registry.spend(admin, None, Update, own_ref, tx)
}

test update_revokes() {
  let tx = spend_tx(
    good_output(),
    [updated(entry(issuer_id, key_a, Revoked))],
    assets.zero,
    admin,
  )
  issuer_registry.spend(admin, None, Update, own_ref, tx)
}

test update_needs_admin() fail {
  let tx = spend_tx(
    good_output(),
    [updated(entry(issuer_id, key_b, Active))],
    assets.zero,
    intruder,
  )
  issuer_registry.spend(admin, None, Update, own_ref, tx)
}

test update_changes_issuer_id() fail {
  let tx = spend_tx(
    good_output(),
    [updated(entry("vl:issuer:someone-else", key_b, Active))],
    assets.zero,
    admin,
  )
  issuer_registry.spend(admin, None, Update, own_ref, tx)
}

test update_drops_token() fail {
  let leaked = entry_output(
    address.from_verification_key(admin),
    [Pair(token_name(issuer_id), 1)],
    entry(issuer_id, key_a, Active),
  )
  let tx = spend_tx(good_output(), [leaked], assets.zero, admin)
  issuer_registry.spend(admin, None, Update, own_ref, tx)
}

test retire_burns_token() {
  let tx = spend_tx(
    good_output(),
    [],
    assets.from_asset(policy, token_name(issuer_id), -1),
    admin,
  )
  and {
    issuer_registry.spend(admin, None, Retire, own_ref, tx),
    issuer_registry.mint(admin, Remove, policy, tx),
  }
}

test retire_without_burn() fail {
  let tx = spend_tx(good_output(), [], assets.zero, admin)
  issuer_registry.spend(admin, None, Retire, own_ref, tx)
}

test sweep_non_entry() {
  let junk = Output {
    address: registry_address(),
    value: assets.from_lovelace(5_000_000),
    datum: InlineDatum(entry(issuer_id, key_a, Active)),
    reference_script: None,
  }
  issuer_registry.spend(
    admin,
    None,
    Update,
    own_ref,
    spend_tx(junk, [], assets.zero, admin),
  )
}
