//! Mempool manager that handles transaction storage and TX set building.
//!
//! Network communication is handled by the libp2p QUIC overlay.
//! This module provides:
//! - the account-aware transaction mempool (see [`crate::flood::Mempool`])
//! - Core command handling for mempool operations (submit, nomination
//!   candidates, removal + ban, ledger-close maintenance)

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

use crate::flood::{InsertOutcome, Mempool};
use crate::metrics::OverlayMetrics;
use crate::wire::ValidatedTx;

/// Default mempool capacity (transactions).
pub const DEFAULT_MEMPOOL_CAPACITY: usize = 100_000;

/// Default maximum age of a mempool transaction.
pub const DEFAULT_MEMPOOL_MAX_AGE: Duration = Duration::from_secs(300);

/// Commands from Core to Overlay
#[derive(Debug, Clone)]
pub enum CoreCommand {
    /// Submit a validated transaction for flooding
    SubmitTx(Arc<ValidatedTx>),

    /// Like `SubmitTx`, but reports the [`InsertOutcome`] so the caller can
    /// skip flooding txs the mempool refused (banned, lower fee, ...).
    SubmitTxWithOutcome {
        tx: Arc<ValidatedTx>,
        reply: mpsc::Sender<InsertOutcome>,
    },

    /// Request nomination candidates (account heads, inclusion-fee order).
    ///
    /// `classic_n`/`soroban_n` select per-phase heads via
    /// [`Mempool::top_heads`]. When both are zero, `count` heads across both
    /// phases merged in fee order are returned ([`Mempool::top_by_fee`]) —
    /// the legacy single-window request.
    GetTopTxs {
        count: usize,
        classic_n: usize,
        soroban_n: usize,
        reply: mpsc::Sender<Vec<Arc<ValidatedTx>>>,
    },

    /// Remove transactions from the mempool and ban their hashes until the
    /// close of `ban_until` (default: last closed ledger + `BAN_LEDGERS`).
    /// Used for externalized sets and for txs core found permanently invalid.
    RemoveTxsFromMempool {
        tx_hashes: Vec<[u8; 32]>,
        ban_until: Option<u32>,
        reply: Option<mpsc::Sender<()>>,
    },

    /// A ledger was applied: expire old txs and prune bans.
    LedgerClosed { seq: u32 },
}

/// Mempool manager (no longer handles network connections).
pub struct Overlay {
    /// Commands from Core
    core_commands: mpsc::UnboundedReceiver<CoreCommand>,

    /// TX mempool
    mempool: Arc<RwLock<Mempool>>,
}

impl Overlay {
    /// Create a new mempool manager with default limits and private metrics.
    pub fn new(core_commands: mpsc::UnboundedReceiver<CoreCommand>) -> Self {
        Self::with_mempool(
            core_commands,
            Mempool::new(DEFAULT_MEMPOOL_CAPACITY, DEFAULT_MEMPOOL_MAX_AGE),
        )
    }

    /// Create a new mempool manager with default limits whose mempool reports
    /// into the shared overlay `metrics`.
    pub fn with_metrics(
        core_commands: mpsc::UnboundedReceiver<CoreCommand>,
        metrics: Arc<OverlayMetrics>,
    ) -> Self {
        Self::with_mempool(
            core_commands,
            Mempool::with_options(
                DEFAULT_MEMPOOL_CAPACITY,
                DEFAULT_MEMPOOL_MAX_AGE,
                crate::flood::Mempool::DEFAULT_MAX_TXS_PER_ACCOUNT,
                metrics,
            ),
        )
    }

    /// Create a new mempool manager around a pre-configured mempool.
    pub fn with_mempool(
        core_commands: mpsc::UnboundedReceiver<CoreCommand>,
        mempool: Mempool,
    ) -> Self {
        Self {
            core_commands,
            mempool: Arc::new(RwLock::new(mempool)),
        }
    }

    /// Run the mempool manager.
    pub async fn run(mut self) -> std::io::Result<()> {
        info!("Mempool manager started (libp2p handles networking)");

        while let Some(cmd) = self.core_commands.recv().await {
            self.handle_core_command(cmd).await;
        }

        info!("Mempool manager shutting down");
        Ok(())
    }

    /// Handle a command from Core.
    async fn handle_core_command(&self, cmd: CoreCommand) {
        match cmd {
            CoreCommand::SubmitTx(tx) => {
                let mut mempool = self.mempool.write().await;
                let outcome = mempool.insert(Arc::clone(&tx));
                debug!("[SubmitTx] {:?} -> {:?}", tx, outcome);
            }

            CoreCommand::SubmitTxWithOutcome { tx, reply } => {
                let outcome = {
                    let mut mempool = self.mempool.write().await;
                    mempool.insert(Arc::clone(&tx))
                };
                debug!("[SubmitTx] {:?} -> {:?}", tx, outcome);
                let _ = reply.send(outcome).await;
            }

            CoreCommand::GetTopTxs {
                count,
                classic_n,
                soroban_n,
                reply,
            } => {
                // Collect Arc clones under the read lock, then drop it before
                // the (bounded) reply send so a slow receiver can't hold up
                // mempool writers.
                let txs: Vec<Arc<ValidatedTx>> = {
                    let mempool = self.mempool.read().await;
                    let hashes = if classic_n == 0 && soroban_n == 0 {
                        mempool.top_by_fee(count)
                    } else {
                        mempool.top_heads(classic_n, soroban_n)
                    };
                    hashes
                        .iter()
                        .filter_map(|h| mempool.get(h).map(Arc::clone))
                        .collect()
                };
                let _ = reply.send(txs).await;
            }

            CoreCommand::RemoveTxsFromMempool {
                tx_hashes,
                ban_until,
                reply,
            } => {
                let mut mempool = self.mempool.write().await;
                let until = ban_until.unwrap_or_else(|| mempool.default_ban_until());
                let requested = tx_hashes.len();
                let removed = mempool.remove_and_ban(&tx_hashes, until);
                if requested > 0 {
                    info!(
                        "Removed {} of {} requested TXs from mempool (banned until ledger {}); {} pending",
                        removed,
                        requested,
                        until,
                        mempool.len()
                    );
                }
                drop(mempool);
                // Signal completion if caller is waiting
                if let Some(tx) = reply {
                    let _ = tx.send(()).await;
                }
            }

            CoreCommand::LedgerClosed { seq } => {
                let mut mempool = self.mempool.write().await;
                let (expired, pruned) = mempool.on_ledger_closed(seq);
                if expired > 0 {
                    info!(
                        "Ledger {}: expired {} TXs from mempool ({} bans pruned, {} pending)",
                        seq,
                        expired,
                        pruned,
                        mempool.len()
                    );
                }
            }
        }
    }

    /// Get mempool reference (for testing)
    pub fn mempool(&self) -> &Arc<RwLock<Mempool>> {
        &self.mempool
    }
}

/// Handle for sending commands to the mempool manager.
#[derive(Clone)]
pub struct OverlayHandle {
    cmd_tx: mpsc::UnboundedSender<CoreCommand>,
}

impl OverlayHandle {
    /// Create a new handle.
    pub fn new(cmd_tx: mpsc::UnboundedSender<CoreCommand>) -> Self {
        Self { cmd_tx }
    }

    /// Submit a validated transaction.
    pub fn submit_tx(&self, tx: Arc<ValidatedTx>) {
        let _ = self.cmd_tx.send(CoreCommand::SubmitTx(tx));
    }

    /// Submit a validated transaction and get a receiver for its
    /// [`InsertOutcome`]. The command is enqueued synchronously (FIFO with
    /// every other command); only the outcome is awaited. The receiver yields
    /// `None` if the mempool manager is gone.
    pub fn submit_tx_with_outcome(&self, tx: Arc<ValidatedTx>) -> mpsc::Receiver<InsertOutcome> {
        let (reply, rx) = mpsc::channel(1);
        let _ = self
            .cmd_tx
            .send(CoreCommand::SubmitTxWithOutcome { tx, reply });
        rx
    }

    /// Remove transactions (banning them for the default horizon) without
    /// waiting. The command channel is FIFO, so a `get_top_txs` /
    /// `get_top_heads` issued afterwards still observes the removal.
    pub fn remove_txs(&self, tx_hashes: Vec<[u8; 32]>) {
        let _ = self.cmd_tx.send(CoreCommand::RemoveTxsFromMempool {
            tx_hashes,
            ban_until: None,
            reply: None,
        });
    }

    /// Get the top `count` account heads across both phases in inclusion-fee
    /// order (legacy single window; prefer [`Self::get_top_heads`]).
    ///
    /// Returns `None` if the mempool manager is gone (shutdown); callers must
    /// not answer Core with an empty list in that case.
    pub async fn get_top_txs(&self, count: usize) -> Option<Vec<Arc<ValidatedTx>>> {
        self.request_top_txs(count, 0, 0).await
    }

    /// Get up to `classic_n` classic and `soroban_n` Soroban account heads,
    /// each group in inclusion-fee order (classic first). `None` on shutdown.
    pub async fn get_top_heads(
        &self,
        classic_n: usize,
        soroban_n: usize,
    ) -> Option<Vec<Arc<ValidatedTx>>> {
        self.request_top_txs(0, classic_n, soroban_n).await
    }

    async fn request_top_txs(
        &self,
        count: usize,
        classic_n: usize,
        soroban_n: usize,
    ) -> Option<Vec<Arc<ValidatedTx>>> {
        let (reply_tx, mut reply_rx) = mpsc::channel(1);
        self.cmd_tx
            .send(CoreCommand::GetTopTxs {
                count,
                classic_n,
                soroban_n,
                reply: reply_tx,
            })
            .ok()?;
        reply_rx.recv().await
    }

    /// Remove transactions from the mempool (banning them for the default
    /// horizon) and wait for completion. This prevents race conditions where
    /// GetTopTxs queries stale data.
    pub async fn remove_txs_sync(&self, tx_hashes: Vec<[u8; 32]>) {
        self.remove_txs_inner(tx_hashes, None).await
    }

    /// Remove transactions and ban them until the close of `ban_until`;
    /// waits for completion.
    pub async fn remove_and_ban_sync(&self, tx_hashes: Vec<[u8; 32]>, ban_until: u32) {
        self.remove_txs_inner(tx_hashes, Some(ban_until)).await
    }

    async fn remove_txs_inner(&self, tx_hashes: Vec<[u8; 32]>, ban_until: Option<u32>) {
        let (reply_tx, mut reply_rx) = mpsc::channel(1);
        let _ = self.cmd_tx.send(CoreCommand::RemoveTxsFromMempool {
            tx_hashes,
            ban_until,
            reply: Some(reply_tx),
        });
        let _ = reply_rx.recv().await;
    }

    /// Report an applied ledger (expiry + ban pruning). Processed in order
    /// with the other commands, so a later `get_top_txs` observes it.
    pub fn ledger_closed(&self, seq: u32) {
        let _ = self.cmd_tx.send(CoreCommand::LedgerClosed { seq });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::tests::{soroban_transaction_xdr, transaction_xdr, valid_transaction_xdr};

    fn start(overlay: Overlay) {
        tokio::spawn(async move {
            let _ = overlay.run().await;
        });
    }

    fn tx(acct: u8, seq: i64, fee: i64) -> Arc<ValidatedTx> {
        ValidatedTx::from_core_trusted(transaction_xdr(acct, fee as u32, seq, 1), fee, 1).unwrap()
    }

    fn soroban(acct: u8, seq: i64, fee: i64) -> Arc<ValidatedTx> {
        ValidatedTx::from_core_trusted(soroban_transaction_xdr(acct, fee as u32, seq, 0), fee, 1)
            .unwrap()
    }

    #[tokio::test]
    async fn test_submit_tx_adds_to_mempool() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);

        // Start overlay in background
        let mempool = overlay.mempool.clone();
        start(overlay);

        // Submit a TX
        let tx = ValidatedTx::from_core_trusted(valid_transaction_xdr(100, 1, 1), 100, 1).unwrap();
        handle.submit_tx(tx);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify it's in mempool
        let mp = mempool.read().await;
        assert_eq!(mp.len(), 1);
    }

    #[tokio::test]
    async fn test_get_top_txs() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);
        start(overlay);

        // Submit TXs from distinct accounts with different fees
        let tx1 = tx(1, 1, 100);
        let tx2 = tx(2, 1, 500);
        let tx3 = tx(3, 1, 200);
        let tx2_bytes = tx2.bytes().to_vec();
        handle.submit_tx(tx1);
        handle.submit_tx(tx2);
        handle.submit_tx(tx3);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Get top 2
        let top = handle.get_top_txs(2).await.unwrap();
        assert_eq!(top.len(), 2);
        // First should be highest fee
        assert_eq!(top[0].bytes(), &tx2_bytes[..]);
    }

    #[tokio::test]
    async fn test_get_top_txs_more_than_available() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);
        start(overlay);

        // Submit only 2 TXs
        handle.submit_tx(tx(1, 1, 100));
        handle.submit_tx(tx(2, 1, 200));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Ask for 10
        let top = handle.get_top_txs(10).await.unwrap();

        // Should return only 2
        assert_eq!(top.len(), 2);
    }

    #[tokio::test]
    async fn test_get_top_txs_empty_mempool() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);
        start(overlay);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let top = handle.get_top_txs(10).await.unwrap();
        assert!(top.is_empty());
        let heads = handle.get_top_heads(10, 10).await.unwrap();
        assert!(heads.is_empty());
    }

    #[tokio::test]
    async fn test_tx_ordering_by_fee_per_op() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);
        start(overlay);

        // TX1: 200 fee / 2 ops = 100 per op
        // TX2: 150 fee / 1 op = 150 per op (HIGHER priority)
        // TX3: 300 fee / 4 ops = 75 per op (LOWER priority)
        let tx1 = transaction_xdr(1, 200, 1, 2);
        let tx2 = transaction_xdr(2, 150, 1, 1);
        let tx3 = transaction_xdr(3, 300, 1, 4);
        handle.submit_tx(ValidatedTx::from_core_trusted(tx1.clone(), 200, 2).unwrap());
        handle.submit_tx(ValidatedTx::from_core_trusted(tx2.clone(), 150, 1).unwrap());
        handle.submit_tx(ValidatedTx::from_core_trusted(tx3.clone(), 300, 4).unwrap());
        tokio::time::sleep(Duration::from_millis(50)).await;

        let top = handle.get_top_txs(3).await.unwrap();
        assert_eq!(top.len(), 3);

        // Order should be: TX2 (150/op), TX1 (100/op), TX3 (75/op)
        assert_eq!(top[0].bytes(), &tx2[..]);
        assert_eq!(top[1].bytes(), &tx1[..]);
        assert_eq!(top[2].bytes(), &tx3[..]);
    }

    #[tokio::test]
    async fn get_top_txs_returns_one_per_account() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);
        let mempool = overlay.mempool.clone();
        start(overlay);

        let a1 = tx(1, 1, 1000);
        let a2 = tx(1, 2, 1000);
        let a3 = tx(1, 3, 1000);
        let b1 = tx(2, 1, 10);
        let (a1h, a2h, b1h) = (*a1.hash(), *a2.hash(), *b1.hash());
        for t in [a3, a2, a1, b1] {
            handle.submit_tx(t);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let top = handle.get_top_txs(10).await.unwrap();
        let hashes: Vec<[u8; 32]> = top.iter().map(|t| *t.hash()).collect();
        assert_eq!(hashes, vec![a1h, b1h]);
        assert_eq!(mempool.read().await.len(), 4);

        // Externalized → removed + banned, next seq promoted.
        handle.remove_txs_sync(vec![a1h]).await;
        let top = handle.get_top_txs(10).await.unwrap();
        let hashes: Vec<[u8; 32]> = top.iter().map(|t| *t.hash()).collect();
        assert_eq!(hashes, vec![a2h, b1h]);
        assert!(mempool.read().await.is_banned(&a1h));
    }

    #[tokio::test]
    async fn get_top_heads_splits_phases() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);
        start(overlay);

        let a = tx(1, 1, 500);
        let b = soroban(2, 1, 900);
        let c = tx(3, 1, 100);
        let (ah, bh, ch) = (*a.hash(), *b.hash(), *c.hash());
        for t in [a, b, c] {
            handle.submit_tx(t);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let heads = handle.get_top_heads(5, 5).await.unwrap();
        let hashes: Vec<[u8; 32]> = heads.iter().map(|t| *t.hash()).collect();
        assert_eq!(hashes, vec![ah, ch, bh]);
        let heads = handle.get_top_heads(1, 0).await.unwrap();
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].hash(), &ah);
        let heads = handle.get_top_heads(0, 1).await.unwrap();
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].hash(), &bh);
    }

    #[tokio::test]
    async fn remove_and_ban_then_ledger_close_lifts_the_ban() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);
        start(overlay);

        let t = tx(1, 1, 100);
        let hash = *t.hash();
        handle.submit_tx(t.clone());
        handle.remove_and_ban_sync(vec![hash], 5).await;
        handle.submit_tx(t.clone());
        assert!(handle.get_top_txs(10).await.unwrap().is_empty(), "banned");

        handle.ledger_closed(4);
        handle.submit_tx(t.clone());
        assert!(
            handle.get_top_txs(10).await.unwrap().is_empty(),
            "still banned"
        );

        handle.ledger_closed(5);
        handle.submit_tx(t);
        let top = handle.get_top_txs(10).await.unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].hash(), &hash);
    }

    #[tokio::test]
    async fn default_ban_horizon_follows_last_closed_ledger() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::new(cmd_rx);
        let handle = OverlayHandle::new(cmd_tx);
        start(overlay);

        handle.ledger_closed(100);
        let t = tx(1, 1, 100);
        let hash = *t.hash();
        handle.submit_tx(t.clone());
        handle.remove_txs_sync(vec![hash]).await; // ban until 100 + Mempool::BAN_LEDGERS
        handle.ledger_closed(100 + Mempool::BAN_LEDGERS - 1);
        handle.submit_tx(t.clone());
        assert!(handle.get_top_txs(10).await.unwrap().is_empty());
        handle.ledger_closed(100 + Mempool::BAN_LEDGERS);
        handle.submit_tx(t);
        assert_eq!(handle.get_top_txs(10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn ledger_closed_expires_old_txs() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let overlay = Overlay::with_mempool(cmd_rx, Mempool::new(100, Duration::from_millis(0)));
        let handle = OverlayHandle::new(cmd_tx);
        start(overlay);

        handle.submit_tx(tx(1, 1, 100));
        handle.submit_tx(tx(2, 1, 100));
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(handle.get_top_txs(10).await.unwrap().len(), 2);
        handle.ledger_closed(1);
        assert!(handle.get_top_txs(10).await.unwrap().is_empty());
    }
}
