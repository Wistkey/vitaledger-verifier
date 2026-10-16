//// On-chain issuer registry (prototype). See ../../README.md.
////
//// Each registered issuer is one UTxO at the registry script address that
//// holds exactly one registry token (policy = the same script) and an
//// inline `IssuerEntry` datum. The token is what makes an entry genuine:
//// anyone can send an output with an arbitrary datum to a script address,
//// but only the admin can mint a registry token.

use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash, blake2b_224}
use aiken/primitive/bytearray
use cardano/assets.{AssetName, Assets, PolicyId}
use cardano/transaction.{InlineDatum, Output}

/// The registry admins: at least `required` of `keys` must sign every change.
pub type MultiSig {
  keys: List<VerificationKeyHash>,
  required: Int,
}

/// True when at least `required` distinct admin keys signed. Duplicate keys
/// in the parameter or in the signatories count once.
pub fn is_authorized(
  admins: MultiSig,
  signatories: List<VerificationKeyHash>,
) -> Bool {
  admins.required >= 1 && list.count(
    list.unique(admins.keys),
    fn(k) { list.has(signatories, k) },
  ) >= admins.required
}

/// The issuer kinds of SPEC §8.
pub type IssuerKind {
  Brand
  Lab
  Certifier
  RecallAuthority
}

pub type IssuerStatus {
  Active
  Revoked
}

pub type IssuerEntry {
  /// UTF-8 `vl:issuer:<slug>`, as in SPEC §2.
  issuer_id: ByteArray,
  kind: IssuerKind,
  /// Raw 32-byte Ed25519 public key that signs `vitaledger.record.v1:<digest>`.
  pubkey: ByteArray,
  status: IssuerStatus,
  /// POSIX milliseconds, set by the admin; informational, not checked on chain.
  updated_at: Int,
}

pub const issuer_prefix: ByteArray = "vl:issuer:"

/// Longest issuer id; matches the 64-byte metadata string limit used for `i`.
pub const max_issuer_id_length: Int = 64

/// The asset name of an issuer's registry token.
pub fn token_name(issuer_id: ByteArray) -> AssetName {
  blake2b_224(issuer_id)
}

pub fn is_well_formed(entry: IssuerEntry) -> Bool {
  let id_length = bytearray.length(entry.issuer_id)
  and {
    bytearray.starts_with(entry.issuer_id, issuer_prefix),
    id_length > bytearray.length(issuer_prefix),
    id_length <= max_issuer_id_length,
    bytearray.length(entry.pubkey) == 32,
  }
}

/// The registry tokens in `value`, as (asset name, quantity) pairs.
pub fn registry_tokens(
  value: Assets,
  policy_id: PolicyId,
) -> Pairs<AssetName, Int> {
  assets.tokens(value, policy_id) |> dict.to_pairs
}

/// The inline datum of `output` as an `IssuerEntry`; fails if absent or malformed.
pub fn expect_entry(output: Output) -> IssuerEntry {
  expect InlineDatum(data) = output.datum
  expect entry: IssuerEntry = data
  entry
}
