//! Overlay metrics tracked with atomics for lock-free, zero-overhead updates.
//!
//! Metrics are collected in the Rust overlay and periodically synced to C++ core
//! via IPC, where they are fed into libmedida for exposure on the `/metrics` endpoint.
//!
//! Design:
//! - Gauges (point-in-time): AtomicI64, can go up and down
//! - Counters (monotonic): AtomicU64, only go up
//! - Timer summaries: (sum_us, count) pairs of AtomicU64

use serde::Serialize;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Relaxed ordering is sufficient for metrics — we only need eventual visibility.
const ORD: Ordering = Ordering::Relaxed;

/// All overlay metrics, matching the `overlay.*` entries in docs/metrics.md.
///
/// Field names follow the convention: the metric `overlay.foo.bar` maps to
/// field `foo_bar`. Underscores replace dots and hyphens.
pub struct OverlayMetrics {
    // ═══ Gauges (instantaneous values, reported as medida Counters) ═══
    /// overlay.connection.authenticated — number of authenticated (connected) peers
    pub connection_authenticated: AtomicI64,
    /// overlay.connection.pending — pending connections (dialing)
    pub connection_pending: AtomicI64,
    /// overlay.inbound.live — number of live inbound connections
    pub inbound_live: AtomicI64,
    /// overlay.memory.flood-known — entries in the TX dedup cache
    pub memory_flood_known: AtomicI64,

    // Mempool gauges
    /// overlay.mempool.size — transactions in the mempool
    pub mempool_size: AtomicI64,
    /// overlay.mempool.accounts — accounts with pending transactions
    pub mempool_accounts: AtomicI64,
    /// overlay.mempool.heads-classic — classic account heads (nomination candidates)
    pub mempool_heads_classic: AtomicI64,
    /// overlay.mempool.heads-soroban — Soroban account heads
    pub mempool_heads_soroban: AtomicI64,
    /// overlay.mempool.banned-size — banned tx hashes
    pub mempool_banned_size: AtomicI64,
    /// overlay.tx-validation.pending — peer txs parked awaiting Core's verdict
    pub tx_validation_pending: AtomicI64,

    // recv-transaction SimpleTimer equivalents
    /// overlay.recv-transaction.sum — cumulative microseconds processing TXs
    pub recv_transaction_sum_us: AtomicU64,
    /// overlay.recv-transaction.count — number of TX messages received
    pub recv_transaction_count: AtomicU64,
    /// overlay.recv-transaction.max — max microseconds since last reset
    pub recv_transaction_max_us: AtomicU64,

    // ═══ Monotonic counters (reported as medida Meters via delta) ═══
    /// overlay.byte.read — total bytes received from peers
    pub byte_read: AtomicU64,
    /// overlay.byte.write — total bytes sent to peers
    pub byte_write: AtomicU64,
    /// overlay.message.read — total messages received
    pub message_read: AtomicU64,
    /// overlay.message.write — total messages sent
    pub message_write: AtomicU64,
    /// overlay.message.broadcast — total broadcast operations
    pub message_broadcast: AtomicU64,
    /// overlay.message.drop — messages dropped due to backpressure
    pub message_drop: AtomicU64,
    /// overlay.error.read — read errors
    pub error_read: AtomicU64,
    /// overlay.error.write — write errors
    pub error_write: AtomicU64,

    // Flood / pull-mode metrics
    /// overlay.flood.advertised — INV messages sent (TX advertisements)
    pub flood_advertised: AtomicU64,
    /// overlay.flood.demanded — GETDATA messages received
    pub flood_demanded: AtomicU64,
    /// overlay.flood.fulfilled — GETDATA successfully fulfilled
    pub flood_fulfilled: AtomicU64,
    /// overlay.flood.unfulfilled-unknown — GETDATA for unknown TX
    pub flood_unfulfilled_unknown: AtomicU64,
    /// overlay.flood.unique_recv — bytes of unique flooded messages received
    pub flood_unique_recv: AtomicU64,
    /// overlay.flood.duplicate_recv — bytes of duplicate flooded messages received
    pub flood_duplicate_recv: AtomicU64,
    /// overlay.flood.broadcast — per-peer broadcast count
    pub flood_broadcast: AtomicU64,
    /// overlay.flood.abandoned-demands — demands no peer responded to
    pub flood_abandoned_demands: AtomicU64,
    /// overlay.demand.timeout — pull mode peer timeouts
    pub demand_timeout: AtomicU64,

    // Mempool counters
    /// overlay.mempool.inserts — transactions stored as new entries
    pub mempool_inserts: AtomicU64,
    /// overlay.mempool.replaced — same-(account, seq) replacements by fee
    pub mempool_replaced: AtomicU64,
    /// overlay.mempool.rejected-banned — inserts refused: hash banned
    pub mempool_rejected_banned: AtomicU64,
    /// overlay.mempool.rejected-lower-fee — inserts refused: did not beat resident rate
    pub mempool_rejected_lower_fee: AtomicU64,
    /// overlay.mempool.rejected-account-full — inserts refused: per-account cap
    pub mempool_rejected_account_full: AtomicU64,
    /// overlay.mempool.rejected-duplicate — inserts refused: already present
    pub mempool_rejected_duplicate: AtomicU64,
    /// overlay.mempool.evicted-capacity — txs dropped to make room (pool or account cap)
    pub mempool_evicted_capacity: AtomicU64,
    /// overlay.mempool.evicted-expired — txs dropped by age
    pub mempool_evicted_expired: AtomicU64,
    /// overlay.mempool.top-txs-requests — nomination candidate requests served
    pub mempool_top_txs_requests: AtomicU64,
    /// overlay.mempool.top-txs-returned — candidates returned in total
    pub mempool_top_txs_returned: AtomicU64,
    /// overlay.tx-validation.accepted — peer txs Core accepted (inserted + flooded)
    pub tx_validation_accepted: AtomicU64,
    /// overlay.tx-validation.rejected — peer txs Core rejected (banned, not flooded)
    pub tx_validation_rejected: AtomicU64,
    /// overlay.tx-validation.timeout — peer txs dropped: no verdict in time
    pub tx_validation_timeout: AtomicU64,
    /// overlay.tx-validation.dropped-full — peer txs dropped: pending map full
    pub tx_validation_dropped_full: AtomicU64,

    // Connection lifecycle
    /// overlay.inbound.attempt — inbound connection attempts
    pub inbound_attempt: AtomicU64,
    /// overlay.inbound.establish — inbound connections established
    pub inbound_establish: AtomicU64,
    /// overlay.inbound.drop — inbound connections dropped
    pub inbound_drop: AtomicU64,
    /// overlay.outbound.attempt — outbound connection attempts (dial)
    pub outbound_attempt: AtomicU64,
    /// overlay.outbound.establish — outbound connections established
    pub outbound_establish: AtomicU64,
    /// overlay.outbound.drop — outbound connections dropped
    pub outbound_drop: AtomicU64,

    // Send meters (per message type)
    /// overlay.send.scp-message — SCP messages sent
    pub send_scp_message: AtomicU64,
    /// overlay.send.transaction — TX-related messages sent (INV batches)
    pub send_transaction: AtomicU64,
    /// overlay.send.txset — TX set messages sent
    pub send_txset: AtomicU64,

    // Receive timers (per message type, tracked as sum_us + count)
    /// overlay.recv.scp-message — time processing SCP messages
    pub recv_scp_sum_us: AtomicU64,
    pub recv_scp_count: AtomicU64,

    // Timer summaries (sum_us + count, reported as medida Timers)
    /// overlay.fetch.txset — time to fetch a TX set from peers
    pub fetch_txset_sum_us: AtomicU64,
    pub fetch_txset_count: AtomicU64,
    /// overlay.flood.tx-pull-latency — time from first demand to receiving TX
    pub flood_tx_pull_latency_sum_us: AtomicU64,
    pub flood_tx_pull_latency_count: AtomicU64,

    // Histogram summary (sum + count, reported as medida Histogram update)
    /// overlay.flood.tx-batch-size — number of entries per INV batch
    pub flood_tx_batch_size_sum: AtomicU64,
    pub flood_tx_batch_size_count: AtomicU64,
}

impl Default for OverlayMetrics {
    fn default() -> Self {
        Self {
            connection_authenticated: AtomicI64::new(0),
            connection_pending: AtomicI64::new(0),
            inbound_live: AtomicI64::new(0),
            memory_flood_known: AtomicI64::new(0),
            mempool_size: AtomicI64::new(0),
            mempool_accounts: AtomicI64::new(0),
            mempool_heads_classic: AtomicI64::new(0),
            mempool_heads_soroban: AtomicI64::new(0),
            mempool_banned_size: AtomicI64::new(0),
            tx_validation_pending: AtomicI64::new(0),
            recv_transaction_sum_us: AtomicU64::new(0),
            recv_transaction_count: AtomicU64::new(0),
            recv_transaction_max_us: AtomicU64::new(0),
            byte_read: AtomicU64::new(0),
            byte_write: AtomicU64::new(0),
            message_read: AtomicU64::new(0),
            message_write: AtomicU64::new(0),
            message_broadcast: AtomicU64::new(0),
            message_drop: AtomicU64::new(0),
            error_read: AtomicU64::new(0),
            error_write: AtomicU64::new(0),
            flood_advertised: AtomicU64::new(0),
            flood_demanded: AtomicU64::new(0),
            flood_fulfilled: AtomicU64::new(0),
            flood_unfulfilled_unknown: AtomicU64::new(0),
            flood_unique_recv: AtomicU64::new(0),
            flood_duplicate_recv: AtomicU64::new(0),
            flood_broadcast: AtomicU64::new(0),
            flood_abandoned_demands: AtomicU64::new(0),
            demand_timeout: AtomicU64::new(0),
            mempool_inserts: AtomicU64::new(0),
            mempool_replaced: AtomicU64::new(0),
            mempool_rejected_banned: AtomicU64::new(0),
            mempool_rejected_lower_fee: AtomicU64::new(0),
            mempool_rejected_account_full: AtomicU64::new(0),
            mempool_rejected_duplicate: AtomicU64::new(0),
            mempool_evicted_capacity: AtomicU64::new(0),
            mempool_evicted_expired: AtomicU64::new(0),
            mempool_top_txs_requests: AtomicU64::new(0),
            mempool_top_txs_returned: AtomicU64::new(0),
            tx_validation_accepted: AtomicU64::new(0),
            tx_validation_rejected: AtomicU64::new(0),
            tx_validation_timeout: AtomicU64::new(0),
            tx_validation_dropped_full: AtomicU64::new(0),
            inbound_attempt: AtomicU64::new(0),
            inbound_establish: AtomicU64::new(0),
            inbound_drop: AtomicU64::new(0),
            outbound_attempt: AtomicU64::new(0),
            outbound_establish: AtomicU64::new(0),
            outbound_drop: AtomicU64::new(0),
            send_scp_message: AtomicU64::new(0),
            send_transaction: AtomicU64::new(0),
            send_txset: AtomicU64::new(0),
            recv_scp_sum_us: AtomicU64::new(0),
            recv_scp_count: AtomicU64::new(0),
            fetch_txset_sum_us: AtomicU64::new(0),
            fetch_txset_count: AtomicU64::new(0),
            flood_tx_pull_latency_sum_us: AtomicU64::new(0),
            flood_tx_pull_latency_count: AtomicU64::new(0),
            flood_tx_batch_size_sum: AtomicU64::new(0),
            flood_tx_batch_size_count: AtomicU64::new(0),
        }
    }
}

impl OverlayMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a snapshot of all metrics for IPC transmission.
    ///
    /// For the `recv_transaction_max_us`, this atomically swaps it to 0,
    /// implementing the "max since last call" semantics.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            // Gauges
            connection_authenticated: self.connection_authenticated.load(ORD),
            connection_pending: self.connection_pending.load(ORD),
            inbound_live: self.inbound_live.load(ORD),
            memory_flood_known: self.memory_flood_known.load(ORD),
            mempool_size: self.mempool_size.load(ORD),
            mempool_accounts: self.mempool_accounts.load(ORD),
            mempool_heads_classic: self.mempool_heads_classic.load(ORD),
            mempool_heads_soroban: self.mempool_heads_soroban.load(ORD),
            mempool_banned_size: self.mempool_banned_size.load(ORD),
            tx_validation_pending: self.tx_validation_pending.load(ORD),

            // recv-transaction SimpleTimer
            recv_transaction_sum_us: self.recv_transaction_sum_us.load(ORD),
            recv_transaction_count: self.recv_transaction_count.load(ORD),
            recv_transaction_max_us: self.recv_transaction_max_us.swap(0, ORD),

            // Monotonic counters
            byte_read: self.byte_read.load(ORD),
            byte_write: self.byte_write.load(ORD),
            message_read: self.message_read.load(ORD),
            message_write: self.message_write.load(ORD),
            message_broadcast: self.message_broadcast.load(ORD),
            message_drop: self.message_drop.load(ORD),
            error_read: self.error_read.load(ORD),
            error_write: self.error_write.load(ORD),
            flood_advertised: self.flood_advertised.load(ORD),
            flood_demanded: self.flood_demanded.load(ORD),
            flood_fulfilled: self.flood_fulfilled.load(ORD),
            flood_unfulfilled_unknown: self.flood_unfulfilled_unknown.load(ORD),
            flood_unique_recv: self.flood_unique_recv.load(ORD),
            flood_duplicate_recv: self.flood_duplicate_recv.load(ORD),
            flood_broadcast: self.flood_broadcast.load(ORD),
            flood_abandoned_demands: self.flood_abandoned_demands.load(ORD),
            demand_timeout: self.demand_timeout.load(ORD),
            mempool_inserts: self.mempool_inserts.load(ORD),
            mempool_replaced: self.mempool_replaced.load(ORD),
            mempool_rejected_banned: self.mempool_rejected_banned.load(ORD),
            mempool_rejected_lower_fee: self.mempool_rejected_lower_fee.load(ORD),
            mempool_rejected_account_full: self.mempool_rejected_account_full.load(ORD),
            mempool_rejected_duplicate: self.mempool_rejected_duplicate.load(ORD),
            mempool_evicted_capacity: self.mempool_evicted_capacity.load(ORD),
            mempool_evicted_expired: self.mempool_evicted_expired.load(ORD),
            mempool_top_txs_requests: self.mempool_top_txs_requests.load(ORD),
            mempool_top_txs_returned: self.mempool_top_txs_returned.load(ORD),
            tx_validation_accepted: self.tx_validation_accepted.load(ORD),
            tx_validation_rejected: self.tx_validation_rejected.load(ORD),
            tx_validation_timeout: self.tx_validation_timeout.load(ORD),
            tx_validation_dropped_full: self.tx_validation_dropped_full.load(ORD),
            inbound_attempt: self.inbound_attempt.load(ORD),
            inbound_establish: self.inbound_establish.load(ORD),
            inbound_drop: self.inbound_drop.load(ORD),
            outbound_attempt: self.outbound_attempt.load(ORD),
            outbound_establish: self.outbound_establish.load(ORD),
            outbound_drop: self.outbound_drop.load(ORD),
            send_scp_message: self.send_scp_message.load(ORD),
            send_transaction: self.send_transaction.load(ORD),
            send_txset: self.send_txset.load(ORD),
            recv_scp_sum_us: self.recv_scp_sum_us.load(ORD),
            recv_scp_count: self.recv_scp_count.load(ORD),
            fetch_txset_sum_us: self.fetch_txset_sum_us.load(ORD),
            fetch_txset_count: self.fetch_txset_count.load(ORD),
            flood_tx_pull_latency_sum_us: self.flood_tx_pull_latency_sum_us.load(ORD),
            flood_tx_pull_latency_count: self.flood_tx_pull_latency_count.load(ORD),
            flood_tx_batch_size_sum: self.flood_tx_batch_size_sum.load(ORD),
            flood_tx_batch_size_count: self.flood_tx_batch_size_count.load(ORD),
        }
    }

    /// Update the recv_transaction_max_us with compare-and-swap.
    pub fn update_recv_transaction_max(&self, duration_us: u64) {
        let mut current = self.recv_transaction_max_us.load(ORD);
        while duration_us > current {
            match self.recv_transaction_max_us.compare_exchange_weak(
                current,
                duration_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
}

/// Serializable snapshot of all metrics for IPC transmission.
#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    // Gauges
    pub connection_authenticated: i64,
    pub connection_pending: i64,
    pub inbound_live: i64,
    pub memory_flood_known: i64,
    pub mempool_size: i64,
    pub mempool_accounts: i64,
    pub mempool_heads_classic: i64,
    pub mempool_heads_soroban: i64,
    pub mempool_banned_size: i64,
    pub tx_validation_pending: i64,

    // recv-transaction SimpleTimer
    pub recv_transaction_sum_us: u64,
    pub recv_transaction_count: u64,
    pub recv_transaction_max_us: u64,

    // Monotonic counters (C++ computes deltas for medida Meters)
    pub byte_read: u64,
    pub byte_write: u64,
    pub message_read: u64,
    pub message_write: u64,
    pub message_broadcast: u64,
    pub message_drop: u64,
    pub error_read: u64,
    pub error_write: u64,
    pub flood_advertised: u64,
    pub flood_demanded: u64,
    pub flood_fulfilled: u64,
    pub flood_unfulfilled_unknown: u64,
    pub flood_unique_recv: u64,
    pub flood_duplicate_recv: u64,
    pub flood_broadcast: u64,
    pub flood_abandoned_demands: u64,
    pub demand_timeout: u64,
    pub mempool_inserts: u64,
    pub mempool_replaced: u64,
    pub mempool_rejected_banned: u64,
    pub mempool_rejected_lower_fee: u64,
    pub mempool_rejected_account_full: u64,
    pub mempool_rejected_duplicate: u64,
    pub mempool_evicted_capacity: u64,
    pub mempool_evicted_expired: u64,
    pub mempool_top_txs_requests: u64,
    pub mempool_top_txs_returned: u64,
    pub tx_validation_accepted: u64,
    pub tx_validation_rejected: u64,
    pub tx_validation_timeout: u64,
    pub tx_validation_dropped_full: u64,
    pub inbound_attempt: u64,
    pub inbound_establish: u64,
    pub inbound_drop: u64,
    pub outbound_attempt: u64,
    pub outbound_establish: u64,
    pub outbound_drop: u64,
    pub send_scp_message: u64,
    pub send_transaction: u64,
    pub send_txset: u64,
    pub recv_scp_sum_us: u64,
    pub recv_scp_count: u64,
    pub fetch_txset_sum_us: u64,
    pub fetch_txset_count: u64,
    pub flood_tx_pull_latency_sum_us: u64,
    pub flood_tx_pull_latency_count: u64,
    pub flood_tx_batch_size_sum: u64,
    pub flood_tx_batch_size_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metrics_are_zeroed() {
        let m = OverlayMetrics::new();
        assert_eq!(m.connection_authenticated.load(ORD), 0);
        assert_eq!(m.byte_read.load(ORD), 0);
        assert_eq!(m.flood_advertised.load(ORD), 0);
    }

    #[test]
    fn test_snapshot_reads_current_values() {
        let m = OverlayMetrics::new();
        m.byte_read.fetch_add(1000, ORD);
        m.connection_authenticated.store(3, ORD);
        m.flood_advertised.fetch_add(42, ORD);

        let snap = m.snapshot();
        assert_eq!(snap.byte_read, 1000);
        assert_eq!(snap.connection_authenticated, 3);
        assert_eq!(snap.flood_advertised, 42);
    }

    #[test]
    fn test_recv_transaction_max_resets_on_snapshot() {
        let m = OverlayMetrics::new();
        m.update_recv_transaction_max(500);
        m.update_recv_transaction_max(1200);
        m.update_recv_transaction_max(800); // Should not update (800 < 1200)

        let snap = m.snapshot();
        assert_eq!(snap.recv_transaction_max_us, 1200);

        // After snapshot, max should be reset to 0
        let snap2 = m.snapshot();
        assert_eq!(snap2.recv_transaction_max_us, 0);
    }

    #[test]
    fn test_snapshot_serializes_to_json() {
        let m = OverlayMetrics::new();
        m.connection_authenticated.store(5, ORD);
        m.byte_read.fetch_add(2048, ORD);

        let snap = m.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"connection_authenticated\":5"));
        assert!(json.contains("\"byte_read\":2048"));
    }

    #[test]
    fn test_mempool_metrics_in_snapshot() {
        let m = OverlayMetrics::new();
        m.mempool_size.store(7, ORD);
        m.mempool_inserts.fetch_add(9, ORD);
        let snap = m.snapshot();
        assert_eq!(snap.mempool_size, 7);
        assert_eq!(snap.mempool_inserts, 9);
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"mempool_size\":7"));
        assert!(json.contains("\"mempool_heads_classic\":0"));
    }

    #[test]
    fn test_tx_validation_metrics_in_snapshot() {
        let m = OverlayMetrics::new();
        m.tx_validation_pending.store(3, ORD);
        m.tx_validation_accepted.fetch_add(4, ORD);
        m.tx_validation_rejected.fetch_add(5, ORD);
        m.tx_validation_timeout.fetch_add(6, ORD);
        m.tx_validation_dropped_full.fetch_add(7, ORD);
        let snap = m.snapshot();
        assert_eq!(snap.tx_validation_pending, 3);
        assert_eq!(snap.tx_validation_accepted, 4);
        assert_eq!(snap.tx_validation_rejected, 5);
        assert_eq!(snap.tx_validation_timeout, 6);
        assert_eq!(snap.tx_validation_dropped_full, 7);
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"tx_validation_pending\":3"));
        assert!(json.contains("\"tx_validation_dropped_full\":7"));
    }
}
