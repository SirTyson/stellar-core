//! TX body batcher for direct-to-leader flooding.
//!
//! Direct leader routing pushes each transaction's full body to the upcoming
//! leaders. Sending each TX as its own ~200-byte message costs a spawn, a
//! stream lock, a write and a flush (≈ one QUIC packet) per TX — at thousands
//! of TX/s that per-message overhead caps intake long before bandwidth does.
//!
//! This batcher coalesces per-destination TXs and flushes them as ONE stream
//! write of concatenated length-prefixed `Transaction` frames. The receiver's
//! framed-read loop splits them back into individual messages, so the wire
//! format is unchanged and no decode changes are needed.
//!
//! Flush policy (whichever comes first):
//! - batch reaches `max_batch_size` TXs (from Core's
//!   EXPERIMENTAL_TX_BATCH_MAX_SIZE; 0 disables batching entirely), OR
//! - batch reaches `TX_BATCH_MAX_BYTES` of payload, OR
//! - `TX_BATCH_MAX_DELAY` elapsed since the batch's first TX (driven by the
//!   50ms housekeeping tick).

use crate::wire::ValidatedTx;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Max time a TX may wait in a batch before being flushed. Kept small: this
/// delay sits on the submit->leader intake path.
pub const TX_BATCH_MAX_DELAY: Duration = Duration::from_millis(50);

/// Byte cap per flushed write, so one write never grows unboundedly large.
pub const TX_BATCH_MAX_BYTES: usize = 256 * 1024;

#[derive(Default)]
struct PeerTxBatch {
    txs: Vec<Arc<ValidatedTx>>,
    bytes: usize,
    started_at: Option<Instant>,
}

impl PeerTxBatch {
    fn take(&mut self) -> Vec<Arc<ValidatedTx>> {
        self.bytes = 0;
        self.started_at = None;
        std::mem::take(&mut self.txs)
    }
}

/// Per-peer TX body batches.
#[derive(Default)]
pub struct TxBatcher {
    pending: HashMap<PeerId, PeerTxBatch>,
}

impl TxBatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue `tx` for `peer`. Returns a full batch to send NOW when a size
    /// threshold is crossed, None while the batch is still accumulating.
    pub fn add(
        &mut self,
        peer: PeerId,
        tx: Arc<ValidatedTx>,
        max_batch_size: usize,
    ) -> Option<Vec<Arc<ValidatedTx>>> {
        let batch = self.pending.entry(peer).or_default();
        if batch.started_at.is_none() {
            batch.started_at = Some(Instant::now());
        }
        batch.bytes += tx.bytes().len();
        batch.txs.push(tx);
        if batch.txs.len() >= max_batch_size || batch.bytes >= TX_BATCH_MAX_BYTES {
            Some(batch.take())
        } else {
            None
        }
    }

    /// Peers whose batch has exceeded TX_BATCH_MAX_DELAY.
    pub fn expired_peers(&self) -> Vec<PeerId> {
        self.pending
            .iter()
            .filter(|(_, b)| {
                !b.txs.is_empty()
                    && b.started_at
                        .map(|t| t.elapsed() >= TX_BATCH_MAX_DELAY)
                        .unwrap_or(false)
            })
            .map(|(p, _)| *p)
            .collect()
    }

    /// Take whatever is pending for `peer` (empty batches yield None).
    pub fn flush(&mut self, peer: &PeerId) -> Option<Vec<Arc<ValidatedTx>>> {
        let batch = self.pending.get_mut(peer)?;
        if batch.txs.is_empty() {
            return None;
        }
        Some(batch.take())
    }

    /// Drop state for a disconnected peer.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.pending.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tx(seq: i64) -> Arc<ValidatedTx> {
        let bytes = crate::xdr::tests::valid_transaction_xdr(100, seq, 1);
        ValidatedTx::from_core_trusted(bytes, 100, 1).unwrap()
    }

    #[test]
    fn flushes_when_count_threshold_reached() {
        let mut b = TxBatcher::new();
        let peer = PeerId::random();
        assert!(b.add(peer, test_tx(1), 3).is_none());
        assert!(b.add(peer, test_tx(2), 3).is_none());
        let batch = b.add(peer, test_tx(3), 3).expect("full batch");
        assert_eq!(batch.len(), 3);
        // Batch is reset afterwards.
        assert!(b.flush(&peer).is_none());
    }

    #[test]
    fn flush_takes_partial_batch() {
        let mut b = TxBatcher::new();
        let peer = PeerId::random();
        assert!(b.add(peer, test_tx(1), 100).is_none());
        let batch = b.flush(&peer).expect("partial batch");
        assert_eq!(batch.len(), 1);
        assert!(b.flush(&peer).is_none());
    }

    #[test]
    fn batches_are_per_peer() {
        let mut b = TxBatcher::new();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        assert!(b.add(p1, test_tx(1), 2).is_none());
        assert!(b.add(p2, test_tx(2), 2).is_none());
        assert_eq!(b.add(p1, test_tx(3), 2).expect("p1 full").len(), 2);
        assert_eq!(b.flush(&p2).expect("p2 partial").len(), 1);
    }

    #[test]
    fn expired_peers_only_after_delay() {
        let mut b = TxBatcher::new();
        let peer = PeerId::random();
        b.add(peer, test_tx(1), 100);
        assert!(b.expired_peers().is_empty());
        std::thread::sleep(TX_BATCH_MAX_DELAY + Duration::from_millis(10));
        assert_eq!(b.expired_peers(), vec![peer]);
    }
}
