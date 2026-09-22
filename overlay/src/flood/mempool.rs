//! Transaction mempool.
//!
//! Stores transactions waiting to be included in the ledger, indexed for:
//! - Deduplication by hash
//! - Fee-based ordering for nomination

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::trace;

use crate::wire::ValidatedTx;

/// 32-byte transaction hash
pub type TxHash = [u8; 32];

/// Result of [`Mempool::insert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Added. `evicted` lists the lower-priority residents displaced to make
    /// room (empty unless the pool was at capacity).
    Inserted { evicted: Vec<TxHash> },
    /// Already present; nothing changed.
    Duplicate,
    /// The pool is at capacity and the newcomer does not outrank its
    /// lowest-priority resident; nothing changed.
    Rejected,
}

impl InsertOutcome {
    /// True if the transaction is now in the mempool because of this call.
    pub fn is_inserted(&self) -> bool {
        matches!(self, InsertOutcome::Inserted { .. })
    }
}

/// A mempool-resident transaction: the shared validated tx plus its arrival
/// time (for age-based eviction) and arrival sequence number (for FIFO
/// ordering among equal-fee transactions). Internal detail — callers get the
/// shared `Arc<ValidatedTx>` back from [`Mempool::get`].
#[derive(Debug, Clone)]
struct MempoolEntry {
    meta: Arc<ValidatedTx>,
    received_at: Instant,
    arrival_seq: u64,
}

/// Comparison key for fee-sorted ordering (higher fee = higher priority)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeePriority {
    /// Fee (higher is better)
    fee: i64,
    /// Number of ops (lower is better for same fee)
    num_ops: u32,
    /// Arrival order (earlier is better for same fee and ops)
    arrival_seq: u64,
    /// Hash for tie-breaking
    hash: TxHash,
}

impl Ord for FeePriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher fee per op = higher priority
        // fee1/ops1 > fee2/ops2 iff fee1*ops2 > fee2*ops1
        let left = self.fee * (other.num_ops as i64);
        let right = other.fee * (self.num_ops as i64);

        match left.cmp(&right).reverse() {
            // reverse for descending order
            std::cmp::Ordering::Equal => {
                // Same fee/op ratio: prefer fewer ops (simpler tx), then the
                // earlier arrival, so equal-fee transactions are served (and
                // retained) first-come first-served rather than by hash.
                self.num_ops
                    .cmp(&other.num_ops)
                    .then(self.arrival_seq.cmp(&other.arrival_seq))
                    .then(self.hash.cmp(&other.hash))
            }
            other => other,
        }
    }
}

impl PartialOrd for FeePriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl FeePriority {
    fn of(entry: &MempoolEntry) -> Self {
        FeePriority {
            fee: entry.meta.fee(),
            num_ops: entry.meta.num_ops(),
            arrival_seq: entry.arrival_seq,
            hash: *entry.meta.hash(),
        }
    }
}

/// Transaction mempool.
pub struct Mempool {
    /// Transactions by hash (for dedup and lookup)
    by_hash: HashMap<TxHash, MempoolEntry>,

    /// Fee-sorted index (for nomination)
    by_fee: BTreeSet<FeePriority>,

    /// Maximum number of transactions to hold
    max_size: usize,

    /// Maximum age before eviction
    max_age: Duration,

    /// Arrival sequence number assigned to the next inserted transaction
    next_arrival_seq: u64,
}

impl Mempool {
    /// Create a new mempool with given limits.
    pub fn new(max_size: usize, max_age: Duration) -> Self {
        Self {
            by_hash: HashMap::with_capacity(max_size),
            by_fee: BTreeSet::new(),
            max_size,
            max_age,
            next_arrival_seq: 0,
        }
    }

    /// Add a transaction to the mempool.
    ///
    /// Live duplicates are rejected before any capacity handling. At capacity
    /// the newcomer is admitted only if it outranks the lowest-priority
    /// resident, which is then evicted; otherwise the newcomer is refused and
    /// the residents stay. Because equal-fee ties are broken by arrival order,
    /// a full pool of equal-fee transactions refuses newcomers rather than
    /// displacing older arrivals.
    pub fn insert(&mut self, meta: Arc<ValidatedTx>) -> InsertOutcome {
        let hash = *meta.hash();

        // Check for duplicate
        if self.by_hash.contains_key(&hash) {
            trace!("Duplicate transaction: {:?}", &hash[..4]);
            return InsertOutcome::Duplicate;
        }

        let entry = MempoolEntry {
            meta,
            received_at: Instant::now(),
            arrival_seq: self.next_arrival_seq,
        };
        let priority = FeePriority::of(&entry);

        // Make room if at capacity, but only for a newcomer that outranks
        // the lowest-priority resident (`by_fee` is ordered best first).
        let mut evicted = Vec::new();
        while self.by_hash.len() >= self.max_size {
            match self.by_fee.iter().next_back() {
                Some(worst) if priority < *worst => {
                    let worst_hash = worst.hash;
                    trace!("Evicting lowest-priority tx: {:?}", &worst_hash[..4]);
                    self.remove(&worst_hash);
                    evicted.push(worst_hash);
                }
                _ => {
                    trace!("Mempool full, refusing tx: {:?}", &hash[..4]);
                    return InsertOutcome::Rejected;
                }
            }
        }

        self.next_arrival_seq += 1;
        self.by_fee.insert(priority);
        self.by_hash.insert(hash, entry);
        InsertOutcome::Inserted { evicted }
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, hash: &TxHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &TxHash) -> Option<&Arc<ValidatedTx>> {
        self.by_hash.get(hash).map(|entry| &entry.meta)
    }

    /// Remove a transaction by hash, returning the removed tx if present.
    pub fn remove(&mut self, hash: &TxHash) -> Option<Arc<ValidatedTx>> {
        let entry = self.by_hash.remove(hash)?;
        self.by_fee.remove(&FeePriority::of(&entry));
        Some(entry.meta)
    }

    /// Get the top N transactions by fee (for nomination).
    pub fn top_by_fee(&self, n: usize) -> Vec<TxHash> {
        self.by_fee.iter().take(n).map(|p| p.hash).collect()
    }

    /// Remove transactions that are too old.
    pub fn evict_expired(&mut self) -> usize {
        let now = Instant::now();
        let to_remove: Vec<TxHash> = self
            .by_hash
            .values()
            .filter(|entry| now.duration_since(entry.received_at) > self.max_age)
            .map(|entry| *entry.meta.hash())
            .collect();

        let count = to_remove.len();
        for hash in to_remove {
            self.remove(&hash);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::tests::valid_transaction_xdr;

    /// Build a validated tx with a distinct hash per `seq`.
    fn make_tx(fee: i64, num_ops: u32, seq: i64) -> Arc<ValidatedTx> {
        let bytes = valid_transaction_xdr(fee as u32, seq, num_ops as usize);
        ValidatedTx::from_core_trusted(bytes, fee, num_ops).unwrap()
    }

    #[test]
    fn test_insert_and_get() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        let tx = make_tx(1000, 1, 1);
        let hash = *tx.hash();

        assert!(mempool.insert(tx).is_inserted());
        assert!(mempool.contains(&hash));
        assert_eq!(mempool.len(), 1);
        assert_eq!(mempool.get(&hash).unwrap().fee(), 1000);
    }

    #[test]
    fn test_dedup() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        let tx = make_tx(1000, 1, 1);

        assert!(mempool.insert(tx.clone()).is_inserted());
        assert_eq!(mempool.insert(tx), InsertOutcome::Duplicate);
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_fee_ordering() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        let low = make_tx(100, 1, 1);
        let mid = make_tx(500, 1, 2);
        let high = make_tx(1000, 1, 3);
        let (low_h, mid_h, high_h) = (*low.hash(), *mid.hash(), *high.hash());

        mempool.insert(low);
        mempool.insert(high);
        mempool.insert(mid);

        let top = mempool.top_by_fee(3);
        assert_eq!(top, vec![high_h, mid_h, low_h]);
    }

    #[test]
    fn test_fee_per_op_ordering() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        let tx1 = make_tx(200, 2, 1); // 100 per op
        let tx2 = make_tx(150, 1, 2); // 150 per op (higher priority)
        let (h1, h2) = (*tx1.hash(), *tx2.hash());

        mempool.insert(tx1);
        mempool.insert(tx2);

        let top = mempool.top_by_fee(2);
        assert_eq!(top, vec![h2, h1]);
    }

    #[test]
    fn test_equal_fee_ordering_is_first_come_first_served() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        let txs: Vec<_> = (1..=20).map(|seq| make_tx(100, 1, seq)).collect();
        let mut arrival: Vec<TxHash> = txs.iter().map(|tx| *tx.hash()).collect();
        // Make sure the check below cannot pass by accident: the arrival order
        // must differ from the hash order that used to break ties.
        let mut by_hash = arrival.clone();
        by_hash.sort();
        assert_ne!(arrival, by_hash);

        for tx in txs {
            assert!(mempool.insert(tx).is_inserted());
        }
        assert_eq!(mempool.top_by_fee(20), arrival);

        // Removing an early arrival keeps the rest in arrival order.
        let removed = arrival.remove(3);
        mempool.remove(&removed);
        assert_eq!(mempool.top_by_fee(19), arrival);
    }

    #[test]
    fn test_fee_still_dominates_arrival_order() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        let early_low = make_tx(100, 1, 1);
        let late_high = make_tx(200, 1, 2);
        let (low_h, high_h) = (*early_low.hash(), *late_high.hash());
        mempool.insert(early_low);
        mempool.insert(late_high);
        assert_eq!(mempool.top_by_fee(2), vec![high_h, low_h]);
    }

    #[test]
    fn test_evict_at_capacity_removes_lowest_fee() {
        let mut mempool = Mempool::new(3, Duration::from_secs(300));
        let tx1 = make_tx(100, 1, 1); // lowest fee
        let hash1 = *tx1.hash();
        mempool.insert(tx1);
        mempool.insert(make_tx(200, 1, 2));
        mempool.insert(make_tx(300, 1, 3));
        assert_eq!(mempool.len(), 3);

        let tx4 = make_tx(400, 1, 4);
        let hash4 = *tx4.hash();
        assert_eq!(
            mempool.insert(tx4),
            InsertOutcome::Inserted {
                evicted: vec![hash1]
            }
        );

        assert_eq!(mempool.len(), 3);
        assert!(!mempool.contains(&hash1)); // evicted
        assert!(mempool.contains(&hash4)); // kept
    }

    #[test]
    fn test_full_pool_refuses_newcomer_not_outranking_worst() {
        let mut mempool = Mempool::new(3, Duration::from_secs(300));
        let residents: Vec<_> = (1..=3).map(|seq| make_tx(200, 1, seq)).collect();
        let resident_hashes: Vec<TxHash> = residents.iter().map(|tx| *tx.hash()).collect();
        for tx in residents {
            assert!(mempool.insert(tx).is_inserted());
        }

        // Equal fee: the newcomer is the latest arrival, so it ranks below
        // every resident and is refused instead of displacing one.
        let equal = make_tx(200, 1, 4);
        let equal_hash = *equal.hash();
        assert_eq!(mempool.insert(equal), InsertOutcome::Rejected);
        assert!(!mempool.contains(&equal_hash));

        // Lower fee: refused too.
        assert_eq!(mempool.insert(make_tx(100, 1, 5)), InsertOutcome::Rejected);

        assert_eq!(mempool.len(), 3);
        assert_eq!(mempool.top_by_fee(3), resident_hashes);

        // A refused transaction can be admitted once there is room.
        mempool.remove(&resident_hashes[0]);
        assert!(mempool.insert(make_tx(200, 1, 4)).is_inserted());
        assert!(mempool.contains(&equal_hash));
    }

    #[test]
    fn test_full_pool_evicts_latest_equal_fee_arrival_for_higher_fee() {
        let mut mempool = Mempool::new(3, Duration::from_secs(300));
        let residents: Vec<_> = (1..=3).map(|seq| make_tx(200, 1, seq)).collect();
        let resident_hashes: Vec<TxHash> = residents.iter().map(|tx| *tx.hash()).collect();
        for tx in residents {
            mempool.insert(tx);
        }

        let higher = make_tx(300, 1, 4);
        let higher_hash = *higher.hash();
        // Among equal-fee residents, the latest arrival ranks lowest.
        assert_eq!(
            mempool.insert(higher),
            InsertOutcome::Inserted {
                evicted: vec![resident_hashes[2]]
            }
        );
        assert_eq!(
            mempool.top_by_fee(3),
            vec![higher_hash, resident_hashes[0], resident_hashes[1]]
        );
    }

    #[test]
    fn test_zero_capacity_refuses_everything() {
        let mut mempool = Mempool::new(0, Duration::from_secs(300));
        assert_eq!(mempool.insert(make_tx(1000, 1, 1)), InsertOutcome::Rejected);
        assert!(mempool.is_empty());
    }

    #[test]
    fn test_remove() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        let tx = make_tx(1000, 1, 1);
        let hash = *tx.hash();

        mempool.insert(tx);
        assert!(mempool.remove(&hash).is_some());
        assert!(!mempool.contains(&hash));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        assert!(mempool.remove(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_stress_insert_many() {
        let mut mempool = Mempool::new(1000, Duration::from_secs(300));
        for i in 0..200i64 {
            assert!(mempool.insert(make_tx((i + 1) * 10, 1, i)).is_inserted());
        }
        assert_eq!(mempool.len(), 200);
        assert_eq!(mempool.top_by_fee(10).len(), 10);
    }

    #[test]
    fn test_top_by_fee_empty() {
        let mempool = Mempool::new(100, Duration::from_secs(300));
        assert!(mempool.top_by_fee(10).is_empty());
    }

    #[test]
    fn test_top_by_fee_fewer_than_requested() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        mempool.insert(make_tx(100, 1, 1));
        mempool.insert(make_tx(200, 1, 2));
        assert_eq!(mempool.top_by_fee(10).len(), 2);
    }

    #[test]
    fn test_remove_all() {
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        let mut hashes = Vec::new();
        for i in 0..10i64 {
            let tx = make_tx(100, 1, i);
            hashes.push(*tx.hash());
            mempool.insert(tx);
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
        let mut mempool = Mempool::new(100, Duration::from_secs(300));
        mempool.insert(make_tx(0, 1, 1));
        let high = make_tx(1000, 1, 2);
        let high_hash = *high.hash();
        mempool.insert(high);

        let top = mempool.top_by_fee(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], high_hash);
        assert_eq!(mempool.get(&top[0]).unwrap().fee(), 1000);
        assert_eq!(mempool.get(&top[1]).unwrap().fee(), 0);
    }

    #[test]
    fn test_evict_expired() {
        let mut mempool = Mempool::new(100, Duration::from_millis(0));
        mempool.insert(make_tx(100, 1, 1));
        // With a zero max_age every entry is immediately expired.
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(mempool.evict_expired(), 1);
        assert!(mempool.is_empty());
    }
}
