//! Trust boundary for the flooding pipeline.
//!
//! This module is the single place where raw transaction bytes are turned into
//! a [`ValidatedTx`]. There are exactly two ways in, one per provenance:
//!
//! * [`ValidatedTx::from_network`] — bytes that arrived from an untrusted peer.
//!   The caller (a per-peer stream reader) has *already* strict-decoded the
//!   enclosing `StellarMessage`, so we accept the decoded envelope and its
//!   original bytes and do **not** decode again (see the crate perf notes on
//!   parse-once).
//! * [`ValidatedTx::from_core_trusted`] — bytes submitted by our local core over
//!   IPC. We strict-decode once (a few µs per locally submitted tx) so that the
//!   account/sequence metadata the mempool keys on is always derived from the
//!   bytes themselves; the fee/op-count core supplies alongside are only
//!   cross-checked in debug builds.
//!
//! Fee-bump envelopes are accepted by both constructors. Because the fields are
//! private and the only constructors are these two, every `ValidatedTx` in the
//! system upholds the invariant: `bytes` is a canonical `TransactionEnvelope`
//! encoding, `hash == sha256(bytes)`, and the metadata matches the bytes.

use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use stellar_xdr::curr::{
    FeeBumpTransactionInnerTx, Limits, MuxedAccount, ReadXdr, TransactionEnvelope, TransactionExt,
};

use crate::xdr::{self, XdrError};

/// A transaction whose bytes are known-valid, canonical `TransactionEnvelope`
/// XDR, with its hash and fee/account metadata computed once.
///
/// Shared through the pipeline as `Arc<ValidatedTx>`; immutable after
/// construction, so sharing across tasks can never expose stale metadata.
pub struct ValidatedTx {
    bytes: Vec<u8>,
    hash: [u8; 32],
    meta: TxMeta,
}

/// Metadata read off a decoded envelope. Vocabulary follows core:
///
/// * `fee` — the *full* fee: `tx.fee` for plain txs, the outer `fee` for
///   fee-bumps.
/// * `inclusion_fee` — `fee` minus the declared Soroban `resourceFee` of the
///   (inner) tx, floored at 0. This is what surge pricing orders on.
/// * `num_ops` — operation count used for per-op rates: inner op count (at
///   least 1) plus one for fee-bumps, matching `getNumOperations()`.
/// * `source_account` — the *sequence-number* source: the inner tx source for
///   fee-bumps; muxed accounts map to their underlying ed25519 key.
/// * `seq_num` — the (inner) tx sequence number.
/// * `fee_source` — the fee-bump fee source, `None` for plain txs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TxMeta {
    fee: i64,
    inclusion_fee: i64,
    num_ops: u32,
    source_account: [u8; 32],
    seq_num: i64,
    fee_source: Option<[u8; 32]>,
    is_soroban: bool,
}

impl TxMeta {
    fn from_envelope(envelope: &TransactionEnvelope) -> Result<Self, XdrError> {
        match envelope {
            TransactionEnvelope::TxV0(v0) => {
                let fee = i64::from(v0.tx.fee);
                Ok(TxMeta {
                    fee,
                    inclusion_fee: fee,
                    num_ops: op_count(v0.tx.operations.len()),
                    source_account: v0.tx.source_account_ed25519.0,
                    seq_num: v0.tx.seq_num.0,
                    fee_source: None,
                    is_soroban: false,
                })
            }
            TransactionEnvelope::Tx(v1) => {
                let fee = i64::from(v1.tx.fee);
                let (is_soroban, resource_fee) = soroban_resource_fee(&v1.tx.ext)?;
                Ok(TxMeta {
                    fee,
                    inclusion_fee: fee.saturating_sub(resource_fee).max(0),
                    num_ops: op_count(v1.tx.operations.len()),
                    source_account: ed25519_of(&v1.tx.source_account),
                    seq_num: v1.tx.seq_num.0,
                    fee_source: None,
                    is_soroban,
                })
            }
            TransactionEnvelope::TxFeeBump(fb) => {
                let fee = fb.tx.fee;
                if fee < 0 {
                    return Err(XdrError::Malformed("negative fee-bump fee".into()));
                }
                let FeeBumpTransactionInnerTx::Tx(inner) = &fb.tx.inner_tx;
                let (is_soroban, resource_fee) = soroban_resource_fee(&inner.tx.ext)?;
                Ok(TxMeta {
                    fee,
                    inclusion_fee: fee.saturating_sub(resource_fee).max(0),
                    // Core counts the fee-bump wrapper as one extra operation.
                    num_ops: op_count(inner.tx.operations.len()) + 1,
                    source_account: ed25519_of(&inner.tx.source_account),
                    seq_num: inner.tx.seq_num.0,
                    fee_source: Some(ed25519_of(&fb.tx.fee_source)),
                    is_soroban,
                })
            }
        }
    }
}

/// Operation count as used for per-op fee rates; never zero so rates are
/// well-defined (a zero-op tx is malformed and core rejects it anyway).
fn op_count(len: usize) -> u32 {
    len.max(1) as u32
}

/// `(is_soroban, declared resource fee)` for a v1 transaction extension.
/// A negative resource fee is malformed (core: `txMALFORMED`).
fn soroban_resource_fee(ext: &TransactionExt) -> Result<(bool, i64), XdrError> {
    match ext {
        TransactionExt::V0 => Ok((false, 0)),
        TransactionExt::V1(data) => {
            if data.resource_fee < 0 {
                return Err(XdrError::Malformed("negative soroban resource fee".into()));
            }
            Ok((true, data.resource_fee))
        }
    }
}

/// The ed25519 key behind a (possibly muxed) account — what core's
/// `getSourceID()` returns.
fn ed25519_of(account: &MuxedAccount) -> [u8; 32] {
    match account {
        MuxedAccount::Ed25519(key) => key.0,
        MuxedAccount::MuxedEd25519(muxed) => muxed.ed25519.0,
    }
}

/// Compare two inclusion-fee rates `fee_a / ops_a` vs `fee_b / ops_b` by
/// cross-multiplication in 128 bits (fee-bump fees are `i64`, so a 64-bit
/// product could overflow). `Greater` means `a` pays the higher rate.
pub fn compare_rates(fee_a: i64, ops_a: u32, fee_b: i64, ops_b: u32) -> Ordering {
    let left = i128::from(fee_a) * i128::from(ops_b);
    let right = i128::from(fee_b) * i128::from(ops_a);
    left.cmp(&right)
}

impl ValidatedTx {
    /// Mint from bytes received off the network.
    ///
    /// `envelope` must be the decode of `envelope_bytes` (the reader produced
    /// both from a single `StellarMessage` decode). We read metadata off the
    /// already-decoded `envelope` and hash the original `envelope_bytes` — no
    /// re-decode, no re-encode.
    ///
    /// Crate-private: this constructor cannot check that `envelope` really is
    /// the decode of `envelope_bytes`, so it is only exposed to the per-peer
    /// stream readers that produce both from a single decode.
    pub(crate) fn from_network(
        envelope: &TransactionEnvelope,
        envelope_bytes: &[u8],
    ) -> Result<Arc<Self>, XdrError> {
        let meta = TxMeta::from_envelope(envelope)?;
        Ok(Arc::new(Self {
            hash: xdr::sha256_hash(envelope_bytes),
            bytes: envelope_bytes.to_vec(),
            meta,
        }))
    }

    /// Mint from bytes submitted by the trusted local core.
    ///
    /// The envelope is strict-decoded so the account/sequence metadata always
    /// comes from the bytes. `fee`/`num_ops` are what core computed for the
    /// same envelope; they are cross-checked against the decode in debug builds
    /// only (for plain txs — core does not currently derive them for
    /// fee-bumps), and otherwise ignored.
    pub fn from_core_trusted(
        bytes: Vec<u8>,
        fee: i64,
        num_ops: u32,
    ) -> Result<Arc<Self>, XdrError> {
        if bytes.len() < 4 {
            return Err(XdrError::Malformed("transaction envelope too short".into()));
        }
        let envelope = TransactionEnvelope::from_xdr(&bytes, Limits::none())?;
        let meta = TxMeta::from_envelope(&envelope)?;
        if meta.fee_source.is_none() {
            debug_assert_eq!(meta.fee, fee, "core-supplied fee disagrees with envelope");
            debug_assert_eq!(
                meta.num_ops,
                num_ops.max(1),
                "core-supplied op count disagrees with envelope"
            );
        }
        Ok(Arc::new(Self {
            hash: xdr::sha256_hash(&bytes),
            bytes,
            meta,
        }))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Full fee (outer fee for fee-bumps).
    pub fn fee(&self) -> i64 {
        self.meta.fee
    }

    /// Full fee minus the declared Soroban resource fee (0 floor).
    pub fn inclusion_fee(&self) -> i64 {
        self.meta.inclusion_fee
    }

    /// Operation count for per-op rates: inner ops (≥ 1), +1 for fee-bumps.
    pub fn num_ops(&self) -> u32 {
        self.meta.num_ops
    }

    /// Sequence-number source account (inner source for fee-bumps; muxed
    /// accounts reduced to their ed25519 key).
    pub fn source_account(&self) -> &[u8; 32] {
        &self.meta.source_account
    }

    /// (Inner) transaction sequence number.
    pub fn seq_num(&self) -> i64 {
        self.meta.seq_num
    }

    /// Fee-bump fee source, `None` for plain transactions.
    pub fn fee_source(&self) -> Option<&[u8; 32]> {
        self.meta.fee_source.as_ref()
    }

    /// Whether the (inner) tx carries Soroban data (`ext.v1`).
    pub fn is_soroban(&self) -> bool {
        self.meta.is_soroban
    }

    /// Inclusion fee per operation (integer division). Used as the flood
    /// prioritization hint in INV entries.
    pub fn inclusion_fee_per_op(&self) -> i64 {
        self.meta.inclusion_fee / i64::from(self.meta.num_ops)
    }

    /// Alias of [`Self::inclusion_fee_per_op`] kept for existing callers.
    pub fn fee_per_op(&self) -> i64 {
        self.inclusion_fee_per_op()
    }

    /// Exact inclusion-fee-rate comparison (`Greater` = `self` pays more per
    /// op); see [`compare_rates`].
    pub fn rate_cmp(&self, other: &ValidatedTx) -> Ordering {
        compare_rates(
            self.meta.inclusion_fee,
            self.meta.num_ops,
            other.meta.inclusion_fee,
            other.meta.num_ops,
        )
    }

    /// The `StellarMessage::Transaction(..)` wire framing for flooding this tx.
    pub fn to_flood_frame(&self) -> Vec<u8> {
        xdr::frame_transaction(&self.bytes)
    }
}

impl fmt::Debug for ValidatedTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedTx")
            .field("hash", &format_args!("{:02x?}", &self.hash[..4]))
            .field(
                "source",
                &format_args!("{:02x?}", &self.meta.source_account[..4]),
            )
            .field("seq", &self.meta.seq_num)
            .field("fee", &self.meta.fee)
            .field("inclusion_fee", &self.meta.inclusion_fee)
            .field("num_ops", &self.meta.num_ops)
            .field("soroban", &self.meta.is_soroban)
            .field("fee_bump", &self.meta.fee_source.is_some())
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::tests::{
        fee_bump_xdr, muxed_transaction_xdr, soroban_transaction_xdr, transaction_xdr,
        v0_transaction_xdr, valid_transaction_xdr,
    };
    use std::cmp::Ordering;
    use stellar_xdr::curr::{Limits, TransactionEnvelope, WriteXdr};

    fn decode(bytes: &[u8]) -> TransactionEnvelope {
        use stellar_xdr::curr::ReadXdr;
        TransactionEnvelope::from_xdr(bytes, Limits::none()).unwrap()
    }

    fn trusted(bytes: Vec<u8>) -> Arc<ValidatedTx> {
        let env = decode(&bytes);
        let (fee, ops) = match &env {
            TransactionEnvelope::Tx(v1) => (i64::from(v1.tx.fee), v1.tx.operations.len() as u32),
            TransactionEnvelope::TxV0(v0) => (i64::from(v0.tx.fee), v0.tx.operations.len() as u32),
            TransactionEnvelope::TxFeeBump(fb) => (fb.tx.fee, 0),
        };
        ValidatedTx::from_core_trusted(bytes, fee, ops).unwrap()
    }

    #[test]
    fn from_network_extracts_metadata_and_hashes_original_bytes() {
        let bytes = transaction_xdr(7, 1000, 42, 3);
        let tx = ValidatedTx::from_network(&decode(&bytes), &bytes).unwrap();

        assert_eq!(tx.fee(), 1000);
        assert_eq!(tx.inclusion_fee(), 1000);
        assert_eq!(tx.num_ops(), 3);
        assert_eq!(tx.source_account(), &[7u8; 32]);
        assert_eq!(tx.seq_num(), 42);
        assert_eq!(tx.fee_source(), None);
        assert!(!tx.is_soroban());
        assert_eq!(tx.bytes(), &bytes[..]);
        assert_eq!(tx.hash(), &xdr::sha256_hash(&bytes));
    }

    #[test]
    fn from_core_trusted_decodes_and_exposes_source_and_seq() {
        let bytes = transaction_xdr(9, 555, 77, 2);
        let tx = ValidatedTx::from_core_trusted(bytes.clone(), 555, 2).unwrap();

        assert_eq!(tx.fee(), 555);
        assert_eq!(tx.num_ops(), 2);
        assert_eq!(tx.source_account(), &[9u8; 32]);
        assert_eq!(tx.seq_num(), 77);
        assert_eq!(tx.hash(), &xdr::sha256_hash(&bytes));

        // Both constructors agree on every field.
        let net = ValidatedTx::from_network(&decode(&bytes), &bytes).unwrap();
        assert_eq!(net.source_account(), tx.source_account());
        assert_eq!(net.seq_num(), tx.seq_num());
        assert_eq!(net.inclusion_fee(), tx.inclusion_fee());
        assert_eq!(net.num_ops(), tx.num_ops());
        assert_eq!(net.hash(), tx.hash());
    }

    #[test]
    fn v0_envelope_exposes_source_and_seq() {
        let bytes = v0_transaction_xdr(3, 200, 11, 2);
        let tx = trusted(bytes.clone());
        assert_eq!(tx.source_account(), &[3u8; 32]);
        assert_eq!(tx.seq_num(), 11);
        assert_eq!(tx.fee(), 200);
        assert_eq!(tx.num_ops(), 2);
        assert!(!tx.is_soroban());
        let net = ValidatedTx::from_network(&decode(&bytes), &bytes).unwrap();
        assert_eq!(net.source_account(), &[3u8; 32]);
    }

    #[test]
    fn muxed_source_maps_to_inner_ed25519() {
        let bytes = muxed_transaction_xdr(5, 0xdead_beef, 300, 8, 1);
        let tx = trusted(bytes.clone());
        assert_eq!(tx.source_account(), &[5u8; 32]);
        assert_eq!(tx.seq_num(), 8);
        let net = ValidatedTx::from_network(&decode(&bytes), &bytes).unwrap();
        assert_eq!(net.source_account(), &[5u8; 32]);
    }

    #[test]
    fn fee_bump_is_accepted_and_keyed_by_inner_source() {
        let inner = transaction_xdr(1, 100, 5, 2);
        let bytes = fee_bump_xdr(2, 6000, &inner);
        for tx in [
            trusted(bytes.clone()),
            ValidatedTx::from_network(&decode(&bytes), &bytes).unwrap(),
        ] {
            assert_eq!(
                tx.source_account(),
                &[1u8; 32],
                "inner source is the seq source"
            );
            assert_eq!(tx.seq_num(), 5, "inner seq");
            assert_eq!(tx.fee_source(), Some(&[2u8; 32]));
            assert_eq!(tx.fee(), 6000, "full fee is the outer fee");
            assert_eq!(tx.inclusion_fee(), 6000);
            // master semantics: fee-bump ops = inner ops + 1
            assert_eq!(tx.num_ops(), 3);
            assert!(!tx.is_soroban());
            assert_eq!(tx.bytes(), &bytes[..]);
            assert_eq!(tx.hash(), &xdr::sha256_hash(&bytes));
        }
    }

    #[test]
    fn soroban_resource_fee_is_excluded_from_inclusion_fee() {
        let bytes = soroban_transaction_xdr(4, 1_000_100, 9, 1_000_000);
        let tx = trusted(bytes.clone());
        assert!(tx.is_soroban());
        assert_eq!(tx.fee(), 1_000_100);
        assert_eq!(tx.inclusion_fee(), 100);
        assert_eq!(tx.num_ops(), 1);
        let net = ValidatedTx::from_network(&decode(&bytes), &bytes).unwrap();
        assert_eq!(net.inclusion_fee(), 100);
        assert!(net.is_soroban());
    }

    #[test]
    fn fee_bump_of_soroban_subtracts_inner_resource_fee() {
        let inner = soroban_transaction_xdr(4, 1_000_100, 9, 1_000_000);
        let bytes = fee_bump_xdr(6, 1_000_400, &inner);
        let tx = trusted(bytes);
        assert!(tx.is_soroban());
        assert_eq!(tx.fee(), 1_000_400);
        assert_eq!(tx.inclusion_fee(), 400);
        assert_eq!(tx.num_ops(), 2);
        assert_eq!(tx.fee_source(), Some(&[6u8; 32]));
        assert_eq!(tx.source_account(), &[4u8; 32]);
    }

    #[test]
    fn inclusion_fee_floors_at_zero_when_resource_fee_exceeds_fee() {
        let bytes = soroban_transaction_xdr(4, 100, 9, 1_000_000);
        let tx = trusted(bytes);
        assert_eq!(tx.inclusion_fee(), 0);
        assert_eq!(tx.inclusion_fee_per_op(), 0);
    }

    #[test]
    fn negative_resource_fee_is_malformed() {
        let bytes = soroban_transaction_xdr(4, 100, 9, -1);
        assert!(matches!(
            ValidatedTx::from_core_trusted(bytes.clone(), 100, 1),
            Err(XdrError::Malformed(_))
        ));
        assert!(matches!(
            ValidatedTx::from_network(&decode(&bytes), &bytes),
            Err(XdrError::Malformed(_))
        ));
    }

    #[test]
    fn negative_fee_bump_fee_is_malformed() {
        let inner = transaction_xdr(1, 100, 5, 1);
        let bytes = fee_bump_xdr(2, -5, &inner);
        assert!(matches!(
            ValidatedTx::from_core_trusted(bytes, -5, 2),
            Err(XdrError::Malformed(_))
        ));
    }

    #[test]
    fn zero_ops_tx_counts_as_one_op() {
        let bytes = transaction_xdr(1, 300, 1, 0);
        let tx = ValidatedTx::from_core_trusted(bytes, 300, 0).unwrap();
        assert_eq!(tx.num_ops(), 1);
        assert_eq!(tx.fee_per_op(), 300);
        assert_eq!(tx.inclusion_fee_per_op(), 300);
    }

    #[test]
    fn from_core_trusted_rejects_short_input() {
        assert!(matches!(
            ValidatedTx::from_core_trusted(vec![0, 0], 0, 0),
            Err(XdrError::Malformed(_))
        ));
    }

    #[test]
    fn from_core_trusted_rejects_undecodable_bytes() {
        let mut bytes = valid_transaction_xdr(100, 1, 1);
        bytes.push(0); // trailing garbage breaks strict decode
        assert!(matches!(
            ValidatedTx::from_core_trusted(bytes, 100, 1),
            Err(XdrError::Malformed(_))
        ));
    }

    #[test]
    fn compare_rates_orders_by_inclusion_fee_per_op_with_i128_safety() {
        // 100/op vs 150/op
        assert_eq!(compare_rates(200, 2, 150, 1), Ordering::Less);
        assert_eq!(compare_rates(150, 1, 200, 2), Ordering::Greater);
        assert_eq!(compare_rates(200, 2, 100, 1), Ordering::Equal);
        // fee-bump fees are i64: cross-multiplication must not overflow
        assert_eq!(
            compare_rates(i64::MAX, 101, i64::MAX - 1, 101),
            Ordering::Greater
        );
        assert_eq!(compare_rates(i64::MAX, 101, 1, 1), Ordering::Greater);
    }

    #[test]
    fn to_flood_frame_matches_typed_stellar_message() {
        use stellar_xdr::curr::StellarMessage;
        let bytes = valid_transaction_xdr(1000, 1, 1);
        let tx = ValidatedTx::from_network(&decode(&bytes), &bytes).unwrap();

        let expected = StellarMessage::Transaction(decode(&bytes))
            .to_xdr(Limits::none())
            .unwrap();
        assert_eq!(tx.to_flood_frame(), expected);
    }
}
