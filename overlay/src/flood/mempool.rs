//! Account-aware transaction mempool.
//!
//! Stores transactions waiting to be included in a ledger, indexed for:
//! - deduplication by hash and a ban list of recently removed hashes;
//! - one sorted chain of pending sequence numbers per source account, with at
//!   most one tx per `(account, seq)` (replace-by-fee) and a per-account cap;
//! - nomination: per phase (classic / Soroban), the set of account **heads** —
//!   each account's lowest-seq pending tx — ordered by inclusion fee per op.
//!
//! Nomination only ever sees heads, so a tx set built from `top_heads` never
//! contains two txs from one account and one account cannot crowd others out
//! of the candidate window, however many txs it has queued. When a head is
//! removed (applied, dropped, expired) the account's next seq is promoted.
//!
//! Complexity: every insert/remove is `O(log n)`; `top_heads(k)` is `O(k)`;
//! the only linear work is `evict_expired`, which walks the arrival queue
//! front and stops at the first unexpired record.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

use crate::metrics::OverlayMetrics;
use crate::wire::{compare_rates, ValidatedTx};

/// 32-byte transaction hash
pub type TxHash = [u8; 32];

/// ed25519 public key of a source account
pub type AccountId = [u8; 32];

/// How many ledgers a removed/applied tx hash stays banned by default.
pub const BAN_LEDGERS: u32 = 10;

/// Default per-account pending chain cap.
pub const DEFAULT_MAX_TXS_PER_ACCOUNT: usize = 8;

/// Floor for the ban-map size cap (see [`Mempool::max_banned`]).
const MIN_MAX_BANNED: usize = 1024;

/// Result of [`Mempool::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Stored as a new entry.
    Inserted,
    /// Stored, displacing the given hash which had the same `(account, seq)`
    /// at a lower inclusion-fee rate.
    Replaced(TxHash),
    /// Same hash already present.
    Duplicate,
    /// Hash is banned (recently applied or removed as invalid).
    RejectedBanned,
    /// Did not beat the rate of the equally-useful tx it would have to
    /// displace: the same `(account, seq)` resident, a future tail, or (when
    /// every resident is already a head) the cheapest account head.
    RejectedLowerFee,
    /// The account already has `max_txs_per_account` pending txs and this seq
    /// is above all of them.
    RejectedAccountFull,
}

/// A mempool-resident transaction: the shared validated tx plus its arrival
/// time (for age-based eviction). Internal detail — callers get the shared
/// `Arc<ValidatedTx>` back from [`Mempool::get`].
#[derive(Debug, Clone)]
struct MempoolEntry {
    meta: Arc<ValidatedTx>,
    received_at: Instant,
}

/// Ordering key for the head sets: higher inclusion fee per op sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeePriority {
    inclusion_fee: i64,
    num_ops: u32,
    hash: TxHash,
}

impl Ord for FeePriority {
    fn cmp(&self, other: &Self) -> Ordering {
        // Descending rate, then fewer ops, then hash for determinism.
        compare_rates(
            self.inclusion_fee,
            self.num_ops,
            other.inclusion_fee,
            other.num_ops,
        )
        .reverse()
        .then_with(|| self.num_ops.cmp(&other.num_ops))
        .then_with(|| self.hash.cmp(&other.hash))
    }
}

impl PartialOrd for FeePriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FeePriority {
    fn of(tx: &ValidatedTx) -> Self {
        FeePriority {
            inclusion_fee: tx.inclusion_fee(),
            num_ops: tx.num_ops(),
            hash: *tx.hash(),
        }
    }
}

/// Transaction mempool.
pub struct Mempool {
    /// Transactions by hash (for dedup and lookup)
    by_hash: HashMap<TxHash, MempoolEntry>,

    /// Per account: pending seq → hash. At most one tx per `(account, seq)`.
    by_account: HashMap<AccountId, BTreeMap<i64, TxHash>>,

    /// Account heads (lowest pending seq) whose head tx is classic.
    heads_classic: BTreeSet<FeePriority>,

    /// Account heads whose head tx is Soroban.
    heads_soroban: BTreeSet<FeePriority>,

    /// Arrival records in insertion order for `O(expired)` expiry. Records of
    /// txs that were removed earlier are skipped lazily (`received_at` check).
    arrivals: VecDeque<(Instant, TxHash)>,

    /// Banned hash → ledger seq at whose close the ban is lifted.
    banned: HashMap<TxHash, u32>,

    /// Ban expiry buckets: until-ledger → hashes (may hold stale entries for
    /// hashes whose ban was later extended; resolved against `banned`).
    ban_expiry: BTreeMap<u32, Vec<TxHash>>,

    /// Last ledger seq reported via `on_ledger_closed` (default ban base).
    current_ledger: u32,

    /// Maximum number of transactions to hold
    max_size: usize,

    /// Maximum age before eviction
    max_age: Duration,

    /// Per-account pending chain cap
    max_txs_per_account: usize,

    /// Upper bound on `banned.len()` (defence against a missing ledger feed)
    max_banned: usize,

    metrics: Arc<OverlayMetrics>,
}

impl Mempool {
    /// Associated alias of [`BAN_LEDGERS`] for callers outside `flood`.
    pub const BAN_LEDGERS: u32 = BAN_LEDGERS;

    /// Associated alias of [`DEFAULT_MAX_TXS_PER_ACCOUNT`].
    pub const DEFAULT_MAX_TXS_PER_ACCOUNT: usize = DEFAULT_MAX_TXS_PER_ACCOUNT;

    /// Create a new mempool with given limits, the default per-account cap and
    /// private metrics.
    pub fn new(max_size: usize, max_age: Duration) -> Self {
        Self::with_options(
            max_size,
            max_age,
            DEFAULT_MAX_TXS_PER_ACCOUNT,
            Arc::new(OverlayMetrics::new()),
        )
    }

    /// Create a new mempool with all limits explicit and shared metrics.
    pub fn with_options(
        max_size: usize,
        max_age: Duration,
        max_txs_per_account: usize,
        metrics: Arc<OverlayMetrics>,
    ) -> Self {
        let max_size = max_size.max(1);
        Self {
            by_hash: HashMap::with_capacity(max_size.min(1 << 16)),
            by_account: HashMap::new(),
            heads_classic: BTreeSet::new(),
            heads_soroban: BTreeSet::new(),
            arrivals: VecDeque::new(),
            banned: HashMap::new(),
            ban_expiry: BTreeMap::new(),
            current_ledger: 0,
            max_size,
            max_age,
            max_txs_per_account: max_txs_per_account.max(1),
            max_banned: (max_size * 4).max(MIN_MAX_BANNED),
            metrics,
        }
    }

    /// Add a transaction to the mempool. See [`InsertOutcome`].
    pub fn insert(&mut self, tx: Arc<ValidatedTx>) -> InsertOutcome {
        let hash = *tx.hash();

        if self.by_hash.contains_key(&hash) {
            trace!("Duplicate transaction: {:02x?}", &hash[..4]);
            self.metrics
                .mempool_rejected_duplicate
                .fetch_add(1, Relaxed);
            return InsertOutcome::Duplicate;
        }
        if self.banned.contains_key(&hash) {
            trace!("Banned transaction: {:02x?}", &hash[..4]);
            self.metrics.mempool_rejected_banned.fetch_add(1, Relaxed);
            return InsertOutcome::RejectedBanned;
        }

        let account = *tx.source_account();
        let seq = tx.seq_num();
        let account_already_pending = self.by_account.contains_key(&account);

        // Same (account, seq) already pending: replace-by-fee.
        let resident = self
            .by_account
            .get(&account)
            .and_then(|chain| chain.get(&seq))
            .copied();
        if let Some(resident_hash) = resident {
            let resident_tx = &self.by_hash[&resident_hash].meta;
            if tx.rate_cmp(resident_tx) != Ordering::Greater {
                self.metrics
                    .mempool_rejected_lower_fee
                    .fetch_add(1, Relaxed);
                return InsertOutcome::RejectedLowerFee;
            }
            // Same slot: neither the chain cap nor the pool capacity changes.
            self.remove_entry(&resident_hash);
            self.insert_entry(tx);
            self.metrics.mempool_replaced.fetch_add(1, Relaxed);
            self.update_gauges();
            return InsertOutcome::Replaced(resident_hash);
        }

        // Per-account chain cap.
        let account_tail = self.by_account.get(&account).and_then(|chain| {
            (chain.len() >= self.max_txs_per_account)
                .then(|| chain.last_key_value().map(|(s, h)| (*s, *h)))
                .flatten()
        });
        if let Some((max_seq, tail_hash)) = account_tail {
            if seq > max_seq {
                self.metrics
                    .mempool_rejected_account_full
                    .fetch_add(1, Relaxed);
                return InsertOutcome::RejectedAccountFull;
            }
            // A lower seq is closer to applying than the current tail: make
            // room by dropping the tail. Pool size is unchanged, so no
            // capacity eviction is needed.
            self.remove_entry(&tail_hash);
            self.metrics.mempool_evicted_capacity.fetch_add(1, Relaxed);
        } else {
            // Pool capacity: maximize immediately nominatable account heads
            // first, then fee priority among entries with the same utility.
            // A new account head displaces the cheapest non-head tail before
            // considering a head, even if the incoming rate is lower, because
            // that increases next-ledger source diversity. An existing
            // account may replace its own farther tail with a closer seq;
            // otherwise it must outbid another account's actual tail. It
            // never sacrifices its predecessor or a different account's sole
            // head merely to store another future tx.
            while self.by_hash.len() >= self.max_size {
                let Some((victim, must_outbid)) =
                    self.capacity_victim(&account, seq, account_already_pending)
                else {
                    self.metrics
                        .mempool_rejected_lower_fee
                        .fetch_add(1, Relaxed);
                    return InsertOutcome::RejectedLowerFee;
                };
                if must_outbid
                    && compare_rates(
                        tx.inclusion_fee(),
                        tx.num_ops(),
                        victim.inclusion_fee,
                        victim.num_ops,
                    ) != Ordering::Greater
                {
                    self.metrics
                        .mempool_rejected_lower_fee
                        .fetch_add(1, Relaxed);
                    return InsertOutcome::RejectedLowerFee;
                }
                trace!("Evicting tx at capacity: {:02x?}", &victim.hash[..4]);
                self.remove_entry(&victim.hash);
                self.metrics.mempool_evicted_capacity.fetch_add(1, Relaxed);
            }
        }

        self.insert_entry(tx);
        self.metrics.mempool_inserts.fetch_add(1, Relaxed);
        self.update_gauges();
        InsertOutcome::Inserted
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, hash: &TxHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &TxHash) -> Option<&Arc<ValidatedTx>> {
        self.by_hash.get(hash).map(|entry| &entry.meta)
    }

    /// Remove a transaction by hash, returning the removed tx if present. If it
    /// was its account's head, the account's next seq becomes the head.
    pub fn remove(&mut self, hash: &TxHash) -> Option<Arc<ValidatedTx>> {
        let removed = self.remove_entry(hash);
        if removed.is_some() {
            self.update_gauges();
        }
        removed
    }

    /// Remove the given hashes (those present) and ban all of them until the
    /// close of `until_ledger`. Returns how many were actually removed.
    pub fn remove_and_ban(&mut self, hashes: &[TxHash], until_ledger: u32) -> usize {
        let mut removed = 0;
        for hash in hashes {
            if self.remove_entry(hash).is_some() {
                removed += 1;
            }
            self.ban(*hash, until_ledger);
        }
        self.update_gauges();
        removed
    }

    /// Is this hash currently banned?
    pub fn is_banned(&self, hash: &TxHash) -> bool {
        self.banned.contains_key(hash)
    }

    /// Ledger-close maintenance: expire old txs and lift bans whose horizon
    /// is `<= ledger_seq`. Returns `(expired, bans_pruned)`.
    pub fn on_ledger_closed(&mut self, ledger_seq: u32) -> (usize, usize) {
        self.current_ledger = ledger_seq;
        let expired = self.evict_expired();
        let pruned = self.prune_bans(ledger_seq);
        self.update_gauges();
        debug!(
            "Mempool at ledger {}: {} txs, {} accounts, {} expired, {} bans pruned, {} banned",
            ledger_seq,
            self.by_hash.len(),
            self.by_account.len(),
            expired,
            pruned,
            self.banned.len()
        );
        (expired, pruned)
    }

    /// Last ledger seq seen via [`Self::on_ledger_closed`].
    pub fn current_ledger(&self) -> u32 {
        self.current_ledger
    }

    /// Default ban horizon for a removal happening now.
    pub fn default_ban_until(&self) -> u32 {
        self.current_ledger.saturating_add(BAN_LEDGERS)
    }

    /// Account heads for nomination: the first `classic_n` classic heads then
    /// the first `soroban_n` Soroban heads, each group in descending
    /// inclusion-fee-per-op order. Never returns two txs of one account.
    pub fn top_heads(&self, classic_n: usize, soroban_n: usize) -> Vec<TxHash> {
        let out: Vec<TxHash> = self
            .heads_classic
            .iter()
            .take(classic_n)
            .chain(self.heads_soroban.iter().take(soroban_n))
            .map(|p| p.hash)
            .collect();
        self.note_top_txs(out.len());
        out
    }

    /// Top `n` account heads across both phases merged in descending
    /// inclusion-fee-per-op order (compatibility view of [`Self::top_heads`]).
    pub fn top_by_fee(&self, n: usize) -> Vec<TxHash> {
        let mut classic = self.heads_classic.iter().peekable();
        let mut soroban = self.heads_soroban.iter().peekable();
        let mut out = Vec::with_capacity(n.min(self.by_account.len()));
        while out.len() < n {
            let next = match (classic.peek(), soroban.peek()) {
                (Some(c), Some(s)) => {
                    if c <= s {
                        classic.next()
                    } else {
                        soroban.next()
                    }
                }
                (Some(_), None) => classic.next(),
                (None, Some(_)) => soroban.next(),
                (None, None) => break,
            };
            out.push(next.expect("peeked").hash);
        }
        self.note_top_txs(out.len());
        out
    }

    /// Remove transactions older than `max_age`. Returns how many were removed.
    pub fn evict_expired(&mut self) -> usize {
        let now = Instant::now();
        let mut count = 0;
        while let Some(&(received_at, hash)) = self.arrivals.front() {
            if now.duration_since(received_at) <= self.max_age {
                break;
            }
            self.arrivals.pop_front();
            // Skip records of txs removed earlier (or re-inserted since).
            let live = self
                .by_hash
                .get(&hash)
                .is_some_and(|entry| entry.received_at == received_at);
            if live {
                trace!("Expiring tx: {:02x?}", &hash[..4]);
                self.remove_entry(&hash);
                count += 1;
            }
        }
        if count > 0 {
            self.metrics
                .mempool_evicted_expired
                .fetch_add(count as u64, Relaxed);
            self.update_gauges();
        }
        count
    }

    /// Current number of transactions.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Is the mempool empty?
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Number of pending txs of `account`.
    pub fn account_len(&self, account: &AccountId) -> usize {
        self.by_account.get(account).map_or(0, BTreeMap::len)
    }

    /// Number of accounts with pending txs.
    pub fn account_count(&self) -> usize {
        self.by_account.len()
    }

    /// Number of banned hashes.
    pub fn banned_len(&self) -> usize {
        self.banned.len()
    }

    /// Upper bound on the ban map; when exceeded the soonest-expiring bans are
    /// dropped early (only matters if ledger closes stop being reported).
    pub fn max_banned(&self) -> usize {
        self.max_banned
    }

    // --- internals ------------------------------------------------------------

    /// Index a tx that is known not to be present and whose `(account, seq)`
    /// slot is free.
    fn insert_entry(&mut self, tx: Arc<ValidatedTx>) {
        let hash = *tx.hash();
        let account = *tx.source_account();
        let seq = tx.seq_num();
        let priority = FeePriority::of(&tx);
        let received_at = Instant::now();

        let chain = self.by_account.entry(account).or_default();
        let old_head = chain.first_key_value().map(|(s, h)| (*s, *h));
        let displaced = chain.insert(seq, hash);
        debug_assert!(displaced.is_none(), "(account, seq) slot must be free");

        match old_head {
            None => {
                heads_mut(
                    &mut self.heads_classic,
                    &mut self.heads_soroban,
                    tx.is_soroban(),
                )
                .insert(priority);
            }
            Some((head_seq, head_hash)) if seq < head_seq => {
                let old = &self.by_hash[&head_hash].meta;
                heads_mut(
                    &mut self.heads_classic,
                    &mut self.heads_soroban,
                    old.is_soroban(),
                )
                .remove(&FeePriority::of(old));
                heads_mut(
                    &mut self.heads_classic,
                    &mut self.heads_soroban,
                    tx.is_soroban(),
                )
                .insert(priority);
            }
            Some(_) => {}
        }

        self.arrivals.push_back((received_at, hash));
        self.by_hash.insert(
            hash,
            MempoolEntry {
                meta: tx,
                received_at,
            },
        );
    }

    /// Unindex a tx, promoting the account's next seq if it was the head.
    fn remove_entry(&mut self, hash: &TxHash) -> Option<Arc<ValidatedTx>> {
        let entry = self.by_hash.remove(hash)?;
        let tx = entry.meta;
        let account = tx.source_account();
        let seq = tx.seq_num();

        let chain = self
            .by_account
            .get_mut(account)
            .expect("indexed tx has an account chain");
        let was_head = chain.first_key_value().map(|(s, _)| *s) == Some(seq);
        chain.remove(&seq);

        if was_head {
            heads_mut(
                &mut self.heads_classic,
                &mut self.heads_soroban,
                tx.is_soroban(),
            )
            .remove(&FeePriority::of(&tx));
            if let Some((_, next_hash)) = chain.first_key_value() {
                let next = &self.by_hash[next_hash].meta;
                heads_mut(
                    &mut self.heads_classic,
                    &mut self.heads_soroban,
                    next.is_soroban(),
                )
                .insert(FeePriority::of(next));
            }
        }
        if chain.is_empty() {
            self.by_account.remove(account);
        }
        Some(tx)
    }

    /// Choose a capacity victim and whether the incoming tx must outbid it.
    /// See the capacity-policy comment in [`Self::insert`].
    fn capacity_victim(
        &self,
        incoming: &AccountId,
        incoming_seq: i64,
        incoming_already_pending: bool,
    ) -> Option<(FeePriority, bool)> {
        if incoming_already_pending {
            let own_chain = &self.by_account[incoming];
            let (&tail_seq, &tail_hash) = own_chain.last_key_value().expect("pending account");
            if incoming_seq < tail_seq {
                return Some((FeePriority::of(&self.by_hash[&tail_hash].meta), false));
            }

            return self
                .cheapest_tail(Some(incoming))
                .map(|victim| (victim, true));
        }

        if let Some(tail) = self.cheapest_tail(None) {
            return Some((tail, false));
        }

        // No future entries remain, so preserving head count is impossible:
        // fall back to a normal fee-rate replacement of the cheapest head.
        self.heads_classic
            .iter()
            .chain(self.heads_soroban.iter())
            // FeePriority's ordering is reversed by fee rate, so max is the
            // cheapest entry.
            .max()
            .copied()
            .map(|victim| (victim, true))
    }

    /// Cheapest actual non-head tail, optionally excluding one account.
    fn cheapest_tail(&self, exclude: Option<&AccountId>) -> Option<FeePriority> {
        self.by_account
            .iter()
            .filter(|(account, chain)| {
                chain.len() > 1 && exclude.is_none_or(|excluded| *account != excluded)
            })
            .map(|(_, chain)| {
                let tail_hash = chain.last_key_value().expect("non-empty chain").1;
                FeePriority::of(&self.by_hash[tail_hash].meta)
            })
            // FeePriority's ordering is reversed by fee rate, so max is the
            // cheapest entry.
            .max()
    }

    fn ban(&mut self, hash: TxHash, until_ledger: u32) {
        if self.banned.get(&hash).is_some_and(|&u| u >= until_ledger) {
            return;
        }
        self.banned.insert(hash, until_ledger);
        self.ban_expiry.entry(until_ledger).or_default().push(hash);
        while self.banned.len() > self.max_banned {
            let Some((until, hashes)) = self.ban_expiry.pop_first() else {
                break;
            };
            self.drop_ban_bucket(until, hashes);
        }
    }

    /// Lift bans with `until <= ledger_seq`. Returns how many were lifted.
    fn prune_bans(&mut self, ledger_seq: u32) -> usize {
        let mut pruned = 0;
        while let Some((&until, _)) = self.ban_expiry.first_key_value() {
            if until > ledger_seq {
                break;
            }
            let (until, hashes) = self.ban_expiry.pop_first().expect("peeked");
            pruned += self.drop_ban_bucket(until, hashes);
        }
        pruned
    }

    /// Remove the bans in a bucket whose current horizon is still `until`
    /// (entries extended to a later horizon live in another bucket).
    fn drop_ban_bucket(&mut self, until: u32, hashes: Vec<TxHash>) -> usize {
        let mut dropped = 0;
        for hash in hashes {
            if self.banned.get(&hash) == Some(&until) {
                self.banned.remove(&hash);
                dropped += 1;
            }
        }
        dropped
    }

    fn note_top_txs(&self, returned: usize) {
        self.metrics.mempool_top_txs_requests.fetch_add(1, Relaxed);
        self.metrics
            .mempool_top_txs_returned
            .fetch_add(returned as u64, Relaxed);
    }

    fn update_gauges(&self) {
        let m = &self.metrics;
        m.mempool_size.store(self.by_hash.len() as i64, Relaxed);
        m.mempool_accounts
            .store(self.by_account.len() as i64, Relaxed);
        m.mempool_heads_classic
            .store(self.heads_classic.len() as i64, Relaxed);
        m.mempool_heads_soroban
            .store(self.heads_soroban.len() as i64, Relaxed);
        m.mempool_banned_size
            .store(self.banned.len() as i64, Relaxed);
    }
}

/// Select the head set for a phase without borrowing the whole `Mempool`.
fn heads_mut<'a>(
    classic: &'a mut BTreeSet<FeePriority>,
    soroban: &'a mut BTreeSet<FeePriority>,
    is_soroban: bool,
) -> &'a mut BTreeSet<FeePriority> {
    if is_soroban {
        soroban
    } else {
        classic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::tests::{
        fee_bump_xdr, muxed_transaction_xdr, soroban_transaction_xdr, transaction_xdr,
    };

    const AGE: Duration = Duration::from_secs(300);

    fn pool(max_size: usize) -> Mempool {
        Mempool::new(max_size, AGE)
    }

    /// Plain 1-op classic tx from account `[acct; 32]`.
    fn tx(acct: u8, seq: i64, fee: i64) -> Arc<ValidatedTx> {
        tx_ops(acct, seq, fee, 1)
    }

    fn tx_ops(acct: u8, seq: i64, fee: i64, ops: usize) -> Arc<ValidatedTx> {
        let bytes = transaction_xdr(acct, fee as u32, seq, ops);
        ValidatedTx::from_core_trusted(bytes, fee, ops as u32).unwrap()
    }

    fn soroban(acct: u8, seq: i64, fee: i64, resource_fee: i64) -> Arc<ValidatedTx> {
        let bytes = soroban_transaction_xdr(acct, fee as u32, seq, resource_fee);
        ValidatedTx::from_core_trusted(bytes, fee, 1).unwrap()
    }

    fn fee_bump(fee_source: u8, fee: i64, inner: &ValidatedTx) -> Arc<ValidatedTx> {
        let bytes = fee_bump_xdr(fee_source, fee, inner.bytes());
        ValidatedTx::from_core_trusted(bytes, fee, inner.num_ops() + 1).unwrap()
    }

    fn h(tx: &Arc<ValidatedTx>) -> TxHash {
        *tx.hash()
    }

    // --- basics -------------------------------------------------------------

    #[test]
    fn test_insert_and_get() {
        let mut mempool = pool(100);
        let t = tx(1, 1, 1000);
        let hash = h(&t);

        assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        assert!(mempool.contains(&hash));
        assert_eq!(mempool.len(), 1);
        assert_eq!(mempool.account_len(&[1u8; 32]), 1);
        assert_eq!(mempool.get(&hash).unwrap().fee(), 1000);
    }

    #[test]
    fn test_dedup() {
        let mut mempool = pool(100);
        let t = tx(1, 1, 1000);

        assert_eq!(mempool.insert(t.clone()), InsertOutcome::Inserted);
        assert_eq!(mempool.insert(t), InsertOutcome::Duplicate);
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_fee_ordering_across_accounts() {
        let mut mempool = pool(100);
        let low = tx(1, 1, 100);
        let mid = tx(2, 1, 500);
        let high = tx(3, 1, 1000);
        let (low_h, mid_h, high_h) = (h(&low), h(&mid), h(&high));

        mempool.insert(low);
        mempool.insert(high);
        mempool.insert(mid);

        assert_eq!(mempool.top_by_fee(3), vec![high_h, mid_h, low_h]);
        assert_eq!(mempool.top_heads(3, 0), vec![high_h, mid_h, low_h]);
    }

    #[test]
    fn heads_are_ordered_by_fee_per_op_then_ops_then_hash() {
        let mut mempool = pool(100);
        let a = tx_ops(1, 1, 200, 2); // 100/op
        let b = tx_ops(2, 1, 150, 1); // 150/op (first)
        let c = tx_ops(3, 1, 100, 1); // 100/op, fewer ops than `a`
        let d = tx_ops(4, 1, 100, 1); // 100/op, tie with `c` → hash order
        let (ah, bh, ch, dh) = (h(&a), h(&b), h(&c), h(&d));
        for t in [a, b, c, d] {
            mempool.insert(t);
        }
        let top = mempool.top_by_fee(4);
        assert_eq!(top[0], bh);
        assert_eq!(top[3], ah, "same rate, more ops sorts after fewer ops");
        let mut tie = vec![ch, dh];
        tie.sort();
        assert_eq!(&top[1..3], &tie[..], "equal rate+ops tie broken by hash");
    }

    #[test]
    fn test_remove() {
        let mut mempool = pool(100);
        let t = tx(1, 1, 1000);
        let hash = h(&t);

        mempool.insert(t);
        assert!(mempool.remove(&hash).is_some());
        assert!(!mempool.contains(&hash));
        assert_eq!(mempool.len(), 0);
        assert_eq!(mempool.account_len(&[1u8; 32]), 0);
        assert!(mempool.top_by_fee(10).is_empty());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut mempool = pool(100);
        assert!(mempool.remove(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_stress_insert_many_accounts() {
        let mut mempool = pool(1000);
        for i in 0..200i64 {
            assert_eq!(
                mempool.insert(tx(i as u8, 1, (i + 1) * 10)),
                InsertOutcome::Inserted
            );
        }
        assert_eq!(mempool.len(), 200);
        assert_eq!(mempool.top_by_fee(10).len(), 10);
        assert_eq!(mempool.top_heads(200, 0).len(), 200);
    }

    #[test]
    fn test_top_by_fee_empty() {
        let mempool = pool(100);
        assert!(mempool.top_by_fee(10).is_empty());
        assert!(mempool.top_heads(10, 10).is_empty());
    }

    #[test]
    fn test_remove_all() {
        let mut mempool = pool(100);
        let mut hashes = Vec::new();
        for i in 0..10i64 {
            let t = tx(i as u8, 1, 100);
            hashes.push(h(&t));
            mempool.insert(t);
        }
        assert_eq!(mempool.len(), 10);
        for hash in hashes {
            mempool.remove(&hash);
        }
        assert_eq!(mempool.len(), 0);
        assert!(mempool.top_by_fee(10).is_empty());
    }

    #[test]
    fn test_zero_fee_tx_sorts_last() {
        let mut mempool = pool(100);
        mempool.insert(tx(1, 1, 0));
        let high = tx(2, 1, 1000);
        let high_hash = h(&high);
        mempool.insert(high);

        let top = mempool.top_by_fee(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], high_hash);
        assert_eq!(mempool.get(&top[1]).unwrap().fee(), 0);
    }

    // --- one head per account ----------------------------------------------

    #[test]
    fn top_by_fee_returns_at_most_one_tx_per_source_account() {
        let mut mempool = pool(100);
        let a1 = tx(1, 1, 1000);
        let a2 = tx(1, 2, 1000);
        let a3 = tx(1, 3, 1000);
        let b1 = tx(2, 1, 10);
        let (a1h, b1h) = (h(&a1), h(&b1));
        for t in [a2, a3, a1, b1] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.len(), 4, "the whole chain is retained");
        assert_eq!(mempool.account_len(&[1u8; 32]), 3);
        assert_eq!(mempool.top_by_fee(10), vec![a1h, b1h]);
    }

    #[test]
    fn head_is_lowest_seq_regardless_of_fee() {
        let mut mempool = pool(100);
        let a6 = tx(1, 6, 100_000);
        let a5 = tx(1, 5, 100);
        let a5h = h(&a5);
        mempool.insert(a6);
        mempool.insert(a5);
        assert_eq!(mempool.top_by_fee(10), vec![a5h]);
    }

    #[test]
    fn remove_head_promotes_next_seq() {
        let mut mempool = pool(100);
        let a1 = tx(1, 1, 1000);
        let a2 = tx(1, 2, 1000);
        let a3 = tx(1, 3, 1000);
        let b1 = tx(2, 1, 10);
        let (a1h, a2h, a3h, b1h) = (h(&a1), h(&a2), h(&a3), h(&b1));
        for t in [a1, a2, a3, b1] {
            mempool.insert(t);
        }
        assert_eq!(mempool.top_by_fee(10), vec![a1h, b1h]);
        mempool.remove(&a1h);
        assert_eq!(mempool.top_by_fee(10), vec![a2h, b1h]);
        mempool.remove(&a2h);
        assert_eq!(mempool.top_by_fee(10), vec![a3h, b1h]);
        mempool.remove(&a3h);
        assert_eq!(mempool.top_by_fee(10), vec![b1h]);
        assert_eq!(mempool.account_len(&[1u8; 32]), 0);
    }

    #[test]
    fn removing_a_non_head_does_not_change_the_head() {
        let mut mempool = pool(100);
        let a1 = tx(1, 1, 100);
        let a2 = tx(1, 2, 100);
        let a3 = tx(1, 3, 100);
        let (a1h, a2h) = (h(&a1), h(&a2));
        for t in [a1, a2, a3] {
            mempool.insert(t);
        }
        mempool.remove(&a2h);
        assert_eq!(mempool.top_by_fee(10), vec![a1h]);
        assert_eq!(mempool.account_len(&[1u8; 32]), 2);
    }

    #[test]
    fn one_account_cannot_crowd_out_others() {
        let mut mempool = Mempool::with_options(10_000, AGE, 200, Arc::new(OverlayMetrics::new()));
        for seq in 1..=100 {
            assert_eq!(
                mempool.insert(tx(1, seq, 1_000_000)),
                InsertOutcome::Inserted
            );
        }
        let mut others = Vec::new();
        for acct in 2..=11u8 {
            let t = tx(acct, 1, 100);
            others.push(h(&t));
            mempool.insert(t);
        }
        let top = mempool.top_by_fee(20);
        assert_eq!(top.len(), 11);
        for o in &others {
            assert!(top.contains(o));
        }
        assert_eq!(mempool.top_heads(20, 0).len(), 11);
    }

    #[test]
    fn top_heads_returns_n_distinct_accounts_when_one_account_has_2n_higher_fee_txs() {
        let n = 5usize;
        let mut mempool =
            Mempool::with_options(10_000, AGE, 2 * n, Arc::new(OverlayMetrics::new()));
        for seq in 1..=(2 * n as i64) {
            mempool.insert(tx(1, seq, 10_000));
        }
        for acct in 2..=(n as u8) {
            mempool.insert(tx(acct, 1, 100));
        }
        let top = mempool.top_heads(n, 0);
        assert_eq!(top.len(), n);
        let mut accounts: Vec<[u8; 32]> = top
            .iter()
            .map(|hash| *mempool.get(hash).unwrap().source_account())
            .collect();
        accounts.sort();
        accounts.dedup();
        assert_eq!(accounts.len(), n, "one tx per account");
    }

    #[test]
    fn muxed_and_plain_source_share_one_head() {
        let mut mempool = pool(100);
        let muxed = ValidatedTx::from_core_trusted(muxed_transaction_xdr(7, 42, 100, 1, 1), 100, 1)
            .unwrap();
        let plain = tx(7, 2, 100);
        let muxed_h = h(&muxed);
        mempool.insert(plain);
        mempool.insert(muxed);
        assert_eq!(mempool.account_len(&[7u8; 32]), 2);
        assert_eq!(mempool.top_by_fee(10), vec![muxed_h]);
    }

    // --- replace-by-fee for the same (account, seq) --------------------------

    #[test]
    fn same_account_same_seq_replace_by_fee_keeps_higher_rate() {
        let mut mempool = pool(100);
        let low = tx(1, 5, 100);
        let high = tx(1, 5, 200);
        let (low_h, high_h) = (h(&low), h(&high));

        assert_eq!(mempool.insert(low.clone()), InsertOutcome::Inserted);
        assert_eq!(mempool.insert(high), InsertOutcome::Replaced(low_h));
        assert_eq!(mempool.len(), 1);
        assert!(!mempool.contains(&low_h));
        assert!(mempool.contains(&high_h));
        assert_eq!(mempool.top_by_fee(10), vec![high_h]);

        // The loser (and an equal-rate variant) cannot displace the winner.
        assert_eq!(mempool.insert(low), InsertOutcome::RejectedLowerFee);
        let equal = tx_ops(1, 5, 400, 2); // 200/op == winner's rate
        assert_eq!(mempool.insert(equal), InsertOutcome::RejectedLowerFee);
        assert_eq!(mempool.len(), 1);
        assert_eq!(mempool.top_by_fee(10), vec![high_h]);
    }

    #[test]
    fn replacing_a_non_head_keeps_the_head() {
        let mut mempool = pool(100);
        let a1 = tx(1, 1, 100);
        let a2 = tx(1, 2, 100);
        let a2_bumped = tx(1, 2, 500);
        let (a1h, a2h, a2bh) = (h(&a1), h(&a2), h(&a2_bumped));
        mempool.insert(a1);
        mempool.insert(a2);
        assert_eq!(mempool.insert(a2_bumped), InsertOutcome::Replaced(a2h));
        assert_eq!(mempool.top_by_fee(10), vec![a1h]);
        mempool.remove(&a1h);
        assert_eq!(mempool.top_by_fee(10), vec![a2bh]);
    }

    #[test]
    fn fee_bump_is_keyed_by_inner_source_and_replaces_inner() {
        let mut mempool = pool(100);
        let inner = tx(1, 5, 100);
        let inner_h = h(&inner);
        // 2 ops (inner + 1) at 2000 → 1000/op beats the inner's 100/op.
        let bump = fee_bump(9, 2000, &inner);
        let bump_h = h(&bump);
        assert_eq!(bump.fee_source(), Some(&[9u8; 32]));

        assert_eq!(mempool.insert(inner), InsertOutcome::Inserted);
        assert_eq!(mempool.insert(bump), InsertOutcome::Replaced(inner_h));
        assert_eq!(mempool.account_len(&[1u8; 32]), 1);
        assert_eq!(
            mempool.account_len(&[9u8; 32]),
            0,
            "fee source holds no seq"
        );
        assert_eq!(mempool.top_by_fee(10), vec![bump_h]);
    }

    // --- chain cap ------------------------------------------------------------

    #[test]
    fn chain_cap_rejects_seq_above_max_when_account_is_full() {
        let mut mempool = Mempool::with_options(100, AGE, 3, Arc::new(OverlayMetrics::new()));
        for seq in 1..=3 {
            assert_eq!(mempool.insert(tx(1, seq, 100)), InsertOutcome::Inserted);
        }
        assert_eq!(
            mempool.insert(tx(1, 4, 100)),
            InsertOutcome::RejectedAccountFull
        );
        assert_eq!(
            mempool.insert(tx(1, 99, 1_000_000)),
            InsertOutcome::RejectedAccountFull
        );
        assert_eq!(mempool.account_len(&[1u8; 32]), 3);
        assert_eq!(mempool.len(), 3);
        // Other accounts are unaffected.
        assert_eq!(mempool.insert(tx(2, 1, 1)), InsertOutcome::Inserted);
    }

    #[test]
    fn chain_cap_lower_seq_into_full_account_evicts_tail() {
        let mut mempool = Mempool::with_options(100, AGE, 3, Arc::new(OverlayMetrics::new()));
        let a5 = tx(1, 5, 100);
        let a6 = tx(1, 6, 100);
        let a7 = tx(1, 7, 100);
        let a4 = tx(1, 4, 100);
        let (a4h, a7h) = (h(&a4), h(&a7));
        for t in [a5, a6, a7] {
            mempool.insert(t);
        }
        assert_eq!(mempool.insert(a4), InsertOutcome::Inserted);
        assert_eq!(mempool.account_len(&[1u8; 32]), 3);
        assert!(!mempool.contains(&a7h), "tail evicted to make room");
        assert_eq!(mempool.top_by_fee(10), vec![a4h]);
    }

    #[test]
    fn default_chain_cap_is_eight() {
        let mut mempool = pool(100);
        for seq in 1..=8 {
            assert_eq!(mempool.insert(tx(1, seq, 100)), InsertOutcome::Inserted);
        }
        assert_eq!(
            mempool.insert(tx(1, 9, 100)),
            InsertOutcome::RejectedAccountFull
        );
    }

    // --- classic / soroban split ---------------------------------------------

    #[test]
    fn top_heads_splits_classic_and_soroban() {
        let mut mempool = pool(100);
        let a = tx(1, 1, 500);
        let b = soroban(2, 1, 1_000_900, 1_000_000); // 900 inclusion
        let c = tx(3, 1, 100);
        let d = soroban(4, 1, 50, 0);
        let (ah, bh, ch, dh) = (h(&a), h(&b), h(&c), h(&d));
        for t in [a, b, c, d] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.top_heads(2, 2), vec![ah, ch, bh, dh]);
        assert_eq!(mempool.top_heads(1, 1), vec![ah, bh]);
        assert_eq!(mempool.top_heads(0, 5), vec![bh, dh]);
        assert_eq!(mempool.top_heads(5, 0), vec![ah, ch]);
        // Merged view is in inclusion-fee order across phases.
        assert_eq!(mempool.top_by_fee(10), vec![bh, ah, ch, dh]);
    }

    #[test]
    fn account_head_phase_follows_lowest_seq() {
        let mut mempool = pool(100);
        let classic = tx(1, 1, 100);
        let sor = soroban(1, 2, 100, 0);
        let (ch, sh) = (h(&classic), h(&sor));
        mempool.insert(sor);
        mempool.insert(classic);
        assert_eq!(mempool.top_heads(5, 5), vec![ch]);
        assert!(mempool.top_heads(0, 5).is_empty());
        mempool.remove(&ch);
        assert_eq!(mempool.top_heads(5, 5), vec![sh]);
        assert!(mempool.top_heads(5, 0).is_empty());
    }

    #[test]
    fn ordering_uses_inclusion_fee_not_total_fee() {
        let mut mempool = pool(100);
        let sor = soroban(1, 1, 1_000_100, 1_000_000); // total 1_000_100, inclusion 100
        let classic = tx(2, 1, 500);
        let (sh, ch) = (h(&sor), h(&classic));
        mempool.insert(sor);
        mempool.insert(classic);
        assert_eq!(mempool.top_by_fee(2), vec![ch, sh]);
    }

    // --- bans -------------------------------------------------------------------

    #[test]
    fn ban_blocks_reinsert_until_pruned() {
        let mut mempool = pool(100);
        let t = tx(1, 1, 100);
        let hash = h(&t);
        mempool.insert(t.clone());

        assert_eq!(mempool.remove_and_ban(&[hash], 15), 1);
        assert!(!mempool.contains(&hash));
        assert!(mempool.is_banned(&hash));
        assert_eq!(mempool.insert(t.clone()), InsertOutcome::RejectedBanned);
        assert_eq!(mempool.len(), 0);

        assert_eq!(mempool.on_ledger_closed(14), (0, 0));
        assert!(mempool.is_banned(&hash));
        assert_eq!(mempool.insert(t.clone()), InsertOutcome::RejectedBanned);

        assert_eq!(mempool.on_ledger_closed(15), (0, 1));
        assert!(!mempool.is_banned(&hash));
        assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
    }

    #[test]
    fn ban_of_unknown_hash_still_bans() {
        let mut mempool = pool(100);
        let t = tx(1, 1, 100);
        let hash = h(&t);
        assert_eq!(mempool.remove_and_ban(&[hash], 5), 0);
        assert!(mempool.is_banned(&hash));
        assert_eq!(mempool.insert(t), InsertOutcome::RejectedBanned);
    }

    #[test]
    fn ban_extension_keeps_the_later_expiry() {
        let mut mempool = pool(100);
        let hash = [1u8; 32];
        mempool.remove_and_ban(&[hash], 20);
        mempool.remove_and_ban(&[hash], 10);
        mempool.on_ledger_closed(10);
        assert!(mempool.is_banned(&hash), "earlier until must not shorten");
        mempool.on_ledger_closed(20);
        assert!(!mempool.is_banned(&hash));
    }

    #[test]
    fn externalized_removal_bans_and_promotes_next_seq() {
        let mut mempool = pool(100);
        let a1 = tx(1, 1, 100);
        let a2 = tx(1, 2, 100);
        let b1 = tx(2, 1, 100);
        let (a1h, a2h, b1h) = (h(&a1), h(&a2), h(&b1));
        for t in [a1.clone(), a2, b1.clone()] {
            mempool.insert(t);
        }
        assert_eq!(mempool.remove_and_ban(&[a1h, b1h], 1 + BAN_LEDGERS), 2);
        assert_eq!(mempool.top_by_fee(10), vec![a2h]);
        assert!(mempool.is_banned(&a1h) && mempool.is_banned(&b1h));
        assert!(!mempool.is_banned(&a2h));
        assert_eq!(mempool.insert(a1), InsertOutcome::RejectedBanned);
        assert_eq!(mempool.insert(b1), InsertOutcome::RejectedBanned);
    }

    #[test]
    fn ban_map_is_bounded() {
        let mut mempool = pool(100);
        let cap = mempool.max_banned();
        for i in 0..(cap as u64 + 10) {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&i.to_le_bytes());
            mempool.remove_and_ban(&[hash], (i / 1000) as u32 + 1);
        }
        assert!(mempool.banned_len() <= cap);
    }

    // --- capacity eviction ------------------------------------------------------

    #[test]
    fn capacity_eviction_evicts_tail_of_cheapest_head_account() {
        let mut mempool = pool(3);
        let a1 = tx(1, 1, 100);
        let a2 = tx(1, 2, 100);
        let a3 = tx(1, 3, 100);
        let b1 = tx(2, 1, 10_000);
        let (a1h, a2h, a3h, b1h) = (h(&a1), h(&a2), h(&a3), h(&b1));
        for t in [a1, a2, a3] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.insert(b1), InsertOutcome::Inserted);
        assert_eq!(mempool.len(), 3);
        assert!(!mempool.contains(&a3h), "tail evicted first");
        assert!(mempool.contains(&a1h) && mempool.contains(&a2h) && mempool.contains(&b1h));
        assert_eq!(mempool.top_by_fee(10), vec![b1h, a1h]);
    }

    #[test]
    fn capacity_eviction_rejects_newcomer_that_does_not_beat_cheapest_head() {
        let mut mempool = pool(2);
        let a1 = tx(1, 1, 100);
        let b1 = tx(2, 1, 200);
        let (a1h, b1h) = (h(&a1), h(&b1));
        mempool.insert(a1);
        mempool.insert(b1);

        assert_eq!(
            mempool.insert(tx(3, 1, 50)),
            InsertOutcome::RejectedLowerFee
        );
        assert_eq!(
            mempool.insert(tx(3, 1, 100)),
            InsertOutcome::RejectedLowerFee
        );
        assert_eq!(mempool.len(), 2);
        assert!(mempool.contains(&a1h) && mempool.contains(&b1h));

        let c1 = tx(3, 1, 150);
        let c1h = h(&c1);
        assert_eq!(mempool.insert(c1), InsertOutcome::Inserted);
        assert_eq!(mempool.len(), 2);
        assert!(!mempool.contains(&a1h));
        assert_eq!(mempool.top_by_fee(10), vec![b1h, c1h]);
    }

    #[test]
    fn full_pool_never_drops_a_distinct_head_to_store_an_existing_accounts_tail() {
        // A future tx for an account that already has a head contributes no
        // nomination candidate until that head applies.  Even an arbitrarily
        // high-fee future tx must therefore not evict another account's sole
        // head: doing so would reduce a full three-account candidate set to
        // two accounts and needlessly underfill the next ledger.
        let mut mempool = pool(3);
        let a1 = tx(1, 1, 100);
        let b1 = tx(2, 1, 90);
        let c1 = tx(3, 1, 80);
        let a2 = tx(1, 2, 100_000);
        let (a1h, b1h, c1h, a2h) = (h(&a1), h(&b1), h(&c1), h(&a2));

        for t in [a1, b1, c1] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.top_heads(3, 0), vec![a1h, b1h, c1h]);

        assert_ne!(mempool.insert(a2), InsertOutcome::Inserted);
        assert_eq!(mempool.len(), 3);
        assert!(!mempool.contains(&a2h));
        assert!(mempool.contains(&a1h));
        assert!(mempool.contains(&b1h));
        assert!(mempool.contains(&c1h));
        assert_eq!(mempool.account_count(), 3);
        assert_eq!(mempool.top_heads(3, 0), vec![a1h, b1h, c1h]);
    }

    #[test]
    fn capacity_eviction_never_discards_a_predecessor_for_its_own_future_tx() {
        // If A's head is the cheapest candidate, admitting A(n+2) must not
        // pick A as the victim and remove A(n+1).  That both loses an
        // immediately-applicable transaction and strands the newcomer behind
        // a sequence gap.
        let mut mempool = pool(2);
        let a1 = tx(1, 1, 100);
        let b1 = tx(2, 1, 1_000);
        let a2 = tx(1, 2, 500);
        let (a1h, b1h, a2h) = (h(&a1), h(&b1), h(&a2));

        assert_eq!(mempool.insert(a1), InsertOutcome::Inserted);
        assert_eq!(mempool.insert(b1), InsertOutcome::Inserted);
        assert_ne!(mempool.insert(a2), InsertOutcome::Inserted);

        assert_eq!(mempool.len(), 2);
        assert!(mempool.contains(&a1h));
        assert!(mempool.contains(&b1h));
        assert!(!mempool.contains(&a2h));
        assert_eq!(mempool.top_heads(2, 0), vec![b1h, a1h]);
    }

    #[test]
    fn existing_account_tail_may_replace_another_tail_but_not_a_sole_head() {
        // C is the cheapest account but has only its head, while B has a
        // replaceable tail. A's incoming tail may displace B2 without reducing
        // the three nomination heads in the full pool.
        let mut mempool = pool(4);
        let a1 = tx(1, 1, 300);
        let b1 = tx(2, 1, 100);
        let b2 = tx(2, 2, 100);
        let c1 = tx(3, 1, 1);
        let a2 = tx(1, 2, 1_000);
        let (a1h, b1h, b2h, c1h, a2h) = (h(&a1), h(&b1), h(&b2), h(&c1), h(&a2));

        for t in [a1, b1, b2, c1] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.insert(a2), InsertOutcome::Inserted);

        assert_eq!(mempool.len(), 4);
        assert!(mempool.contains(&a1h));
        assert!(mempool.contains(&a2h));
        assert!(mempool.contains(&b1h));
        assert!(!mempool.contains(&b2h));
        assert!(mempool.contains(&c1h));
        assert_eq!(mempool.top_heads(3, 0), vec![a1h, b1h, c1h]);
    }

    #[test]
    fn new_account_head_displaces_a_tail_even_at_a_lower_fee() {
        // A tail cannot participate in the next nomination while its head is
        // pending. Replacing it with a third account head increases the next
        // candidate set from two sources to three, irrespective of fee rate.
        let mut mempool = pool(3);
        let a1 = tx(1, 1, 1_000);
        let a2 = tx(1, 2, 100_000);
        let b1 = tx(2, 1, 1_000);
        let c1 = tx(3, 1, 1);
        let (a1h, a2h, b1h, c1h) = (h(&a1), h(&a2), h(&b1), h(&c1));

        for t in [a1, a2, b1] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.account_count(), 2);
        assert_eq!(mempool.insert(c1), InsertOutcome::Inserted);

        assert_eq!(mempool.len(), 3);
        assert!(mempool.contains(&a1h));
        assert!(!mempool.contains(&a2h));
        assert!(mempool.contains(&b1h));
        assert!(mempool.contains(&c1h));
        assert_eq!(mempool.account_count(), 3);
    }

    #[test]
    fn capacity_evicts_the_cheapest_tail_not_the_tail_of_the_cheapest_head() {
        // B has the cheapest head but the most valuable future tail. Choosing
        // a victim by head rate needlessly loses B2 when A2 is the cheapest
        // non-head entry and either eviction preserves all account heads.
        let mut mempool = pool(4);
        let a1 = tx(1, 1, 1_000);
        let a2 = tx(1, 2, 10);
        let b1 = tx(2, 1, 1);
        let b2 = tx(2, 2, 100_000);
        let c1 = tx(3, 1, 500);
        let (a1h, a2h, b1h, b2h, c1h) = (h(&a1), h(&a2), h(&b1), h(&b2), h(&c1));

        for t in [a1, a2, b1, b2] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.insert(c1), InsertOutcome::Inserted);

        assert_eq!(mempool.len(), 4);
        assert!(mempool.contains(&a1h));
        assert!(!mempool.contains(&a2h));
        assert!(mempool.contains(&b1h));
        assert!(mempool.contains(&b2h));
        assert!(mempool.contains(&c1h));
        assert_eq!(mempool.account_count(), 3);
    }

    #[test]
    fn closer_own_sequence_replaces_a_stranded_own_tail_at_capacity() {
        // A3 arrived before A2. At capacity, A2 must replace A3: it is the
        // immediately useful successor and turns a gapped chain into a
        // contiguous one without reducing account-head diversity.
        let mut mempool = pool(3);
        let a1 = tx(1, 1, 100);
        let a3 = tx(1, 3, 100_000);
        let b1 = tx(2, 1, 100);
        let a2 = tx(1, 2, 1);
        let (a1h, a2h, a3h, b1h) = (h(&a1), h(&a2), h(&a3), h(&b1));

        for t in [a1, a3, b1] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.insert(a2), InsertOutcome::Inserted);

        assert_eq!(mempool.len(), 3);
        assert!(mempool.contains(&a1h));
        assert!(mempool.contains(&a2h));
        assert!(!mempool.contains(&a3h));
        assert!(mempool.contains(&b1h));
        let heads = mempool.top_heads(2, 0);
        assert_eq!(heads.len(), 2);
        assert!(heads.contains(&a1h));
        assert!(heads.contains(&b1h));
    }

    #[test]
    fn existing_account_tail_does_not_evict_a_more_valuable_other_tail() {
        // Neither tail changes the next candidate set. The incoming A2 must
        // therefore beat the actual tail it would displace, not merely that
        // tail's cheap account head.
        let mut mempool = pool(4);
        let a1 = tx(1, 1, 300);
        let b1 = tx(2, 1, 1);
        let b2 = tx(2, 2, 1_000);
        let c1 = tx(3, 1, 200);
        let a2 = tx(1, 2, 500);
        let (a1h, a2h, b1h, b2h, c1h) = (h(&a1), h(&a2), h(&b1), h(&b2), h(&c1));

        for t in [a1, b1, b2, c1] {
            assert_eq!(mempool.insert(t), InsertOutcome::Inserted);
        }
        assert_eq!(mempool.insert(a2), InsertOutcome::RejectedLowerFee);

        assert_eq!(mempool.len(), 4);
        assert!(mempool.contains(&a1h));
        assert!(!mempool.contains(&a2h));
        assert!(mempool.contains(&b1h));
        assert!(mempool.contains(&b2h));
        assert!(mempool.contains(&c1h));
    }

    #[test]
    fn capacity_eviction_picks_the_cheapest_head_across_phases() {
        let mut mempool = pool(2);
        let a1 = soroban(1, 1, 100, 0);
        let b1 = tx(2, 1, 200);
        let (a1h, b1h) = (h(&a1), h(&b1));
        mempool.insert(a1);
        mempool.insert(b1);
        let c1 = tx(3, 1, 150);
        assert_eq!(mempool.insert(c1), InsertOutcome::Inserted);
        assert!(!mempool.contains(&a1h));
        assert!(mempool.contains(&b1h));
    }

    #[test]
    fn replacement_at_capacity_does_not_evict() {
        let mut mempool = pool(2);
        let a1 = tx(1, 1, 100);
        let b1 = tx(2, 1, 200);
        let a1_bumped = tx(1, 1, 300);
        let (a1h, b1h, a1bh) = (h(&a1), h(&b1), h(&a1_bumped));
        mempool.insert(a1);
        mempool.insert(b1);
        assert_eq!(mempool.insert(a1_bumped), InsertOutcome::Replaced(a1h));
        assert_eq!(mempool.len(), 2);
        assert!(mempool.contains(&b1h) && mempool.contains(&a1bh));
    }

    // --- expiry ---------------------------------------------------------------------

    #[test]
    fn test_evict_expired() {
        let mut mempool = Mempool::new(100, Duration::from_millis(0));
        mempool.insert(tx(1, 1, 100));
        // With a zero max_age every entry is immediately expired.
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(mempool.evict_expired(), 1);
        assert!(mempool.is_empty());
    }

    #[test]
    fn evict_expired_removes_whole_chain_and_reindexes_heads() {
        let mut mempool = Mempool::new(100, Duration::from_millis(0));
        for seq in 1..=3 {
            mempool.insert(tx(1, seq, 100));
        }
        mempool.insert(tx(2, 1, 100));
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(mempool.evict_expired(), 4);
        assert!(mempool.is_empty());
        assert!(mempool.top_by_fee(10).is_empty());
        assert!(mempool.top_heads(10, 10).is_empty());
        assert_eq!(mempool.account_len(&[1u8; 32]), 0);
    }

    #[test]
    fn expiry_on_ledger_close() {
        let mut mempool = Mempool::new(100, Duration::from_millis(0));
        mempool.insert(tx(1, 1, 100));
        mempool.insert(tx(2, 1, 100));
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(mempool.on_ledger_closed(7), (2, 0));
        assert!(mempool.is_empty());
        assert!(mempool.top_heads(10, 10).is_empty());
    }

    #[test]
    fn fresh_txs_survive_ledger_close() {
        let mut mempool = pool(100);
        mempool.insert(tx(1, 1, 100));
        assert_eq!(mempool.on_ledger_closed(7), (0, 0));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn expiry_survives_replacement_of_the_expired_slot() {
        // The arrival queue may hold a stale record for a replaced tx; expiry
        // must not remove the replacement.
        let mut mempool = Mempool::new(100, Duration::from_millis(20));
        let old = tx(1, 1, 100);
        mempool.insert(old);
        std::thread::sleep(Duration::from_millis(25));
        let new = tx(1, 1, 200);
        let new_h = h(&new);
        assert!(matches!(mempool.insert(new), InsertOutcome::Replaced(_)));
        assert_eq!(mempool.evict_expired(), 0);
        assert!(mempool.contains(&new_h));
    }

    // --- metrics --------------------------------------------------------------------

    #[test]
    fn metrics_reflect_mempool_state() {
        use std::sync::atomic::Ordering::Relaxed;
        let metrics = Arc::new(OverlayMetrics::new());
        let mut mempool = Mempool::with_options(3, AGE, 2, Arc::clone(&metrics));
        let a1 = tx(1, 1, 100);
        let a1h = h(&a1);
        assert_eq!(mempool.insert(a1.clone()), InsertOutcome::Inserted);
        assert_eq!(mempool.insert(a1.clone()), InsertOutcome::Duplicate);
        assert_eq!(mempool.insert(tx(1, 2, 100)), InsertOutcome::Inserted);
        assert_eq!(
            mempool.insert(tx(1, 3, 100)),
            InsertOutcome::RejectedAccountFull
        );
        assert_eq!(
            mempool.insert(tx(1, 2, 500)),
            InsertOutcome::Replaced(h(&tx(1, 2, 100)))
        );
        assert_eq!(
            mempool.insert(soroban(2, 1, 5000, 0)),
            InsertOutcome::Inserted
        );
        // At capacity, C's new account head replaces A's tail even at a lower
        // rate because this increases head diversity.
        assert_eq!(mempool.insert(tx(3, 1, 10)), InsertOutcome::Inserted);
        assert_eq!(
            mempool.insert(tx(3, 1, 1000)),
            InsertOutcome::Replaced(h(&tx(3, 1, 10)))
        );
        // With only heads left, a lower-rate fourth account cannot displace
        // any of them.
        assert_eq!(
            mempool.insert(tx(4, 1, 10)),
            InsertOutcome::RejectedLowerFee
        );
        mempool.remove_and_ban(&[a1h], 5);
        assert_eq!(mempool.insert(a1), InsertOutcome::RejectedBanned);
        let _ = mempool.top_heads(5, 5);

        let s = metrics.snapshot();
        assert_eq!(s.mempool_size, mempool.len() as i64);
        assert_eq!(s.mempool_size, 2);
        assert_eq!(s.mempool_accounts, 2);
        assert_eq!(s.mempool_heads_classic, 1);
        assert_eq!(s.mempool_heads_soroban, 1);
        assert_eq!(s.mempool_banned_size, 1);
        assert_eq!(s.mempool_inserts, 4);
        assert_eq!(s.mempool_replaced, 2);
        assert_eq!(s.mempool_rejected_duplicate, 1);
        assert_eq!(s.mempool_rejected_account_full, 1);
        assert_eq!(s.mempool_rejected_lower_fee, 1);
        assert_eq!(s.mempool_rejected_banned, 1);
        assert_eq!(s.mempool_evicted_capacity, 1);
        assert_eq!(s.mempool_top_txs_requests, 1);
        assert_eq!(s.mempool_top_txs_returned, 2);
        assert_eq!(metrics.mempool_evicted_expired.load(Relaxed), 0);
    }
}
