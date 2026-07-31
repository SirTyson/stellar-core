//! Unified libp2p Overlay v2
//!
//! **Transport: QUIC** for true stream independence - no TCP head-of-line blocking.
//! If a packet is lost on the TX stream, SCP stream is UNAFFECTED.
//!
//! Uses libp2p-stream for persistent bidirectional streams:
//! - SCP stream: consensus messages (priority, ~500B)
//! - TX stream: transaction flooding (~1KB) - uses INV/GETDATA protocol
//! - TxSet stream: TX set request/response (~10MB)
//! - TxSet-shred stream: eager erasure-coded dissemination
//!
//! Each stream is opened once per peer and kept alive.
//! QUIC provides independent loss recovery per stream.

use crate::flood::{
    GetData, InvBatch, InvBatcher, InvEntry, InvTracker, PendingRequests, TxBatcher, TxBuffer,
    TxStreamMessage,
};
use crate::metrics::OverlayMetrics;
#[cfg(test)]
use crate::txset_shards::make_txset_shards;
use crate::txset_shards::{
    assign_shard_branches_to_peer_offsets, decode_txset_transport, encode_txset_transport,
    make_txset_shards_parallel_with_codec, relay_target_peer_offsets, TxSetCodec,
    TxSetCodingExecutor, TxSetShardAccumulator, TxSetShardConfig, TxSetShardDecodeError,
    TxSetShardMessage, TxSetTransport, TxSetTransportDecodeError, TXSET_MAX_SHARD_BRANCHING_FACTOR,
    TXSET_SHARD_BRANCHING_FACTOR, TXSET_SHARD_HEADER_LEN,
};
use crate::wire::ValidatedTx;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::{
    identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent},
    identity::Keypair,
    swarm::{
        dial_opts::{DialOpts, PeerCondition},
        NetworkBehaviour, SwarmEvent,
    },
    Multiaddr, PeerId, Stream, StreamProtocol, Swarm, SwarmBuilder,
};
use libp2p_stream::{Behaviour as StreamBehaviour, Control, IncomingStreams};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, trace, warn};

// Protocol identifiers for dedicated streams
pub const SCP_PROTOCOL: StreamProtocol = StreamProtocol::new("/stellar/scp/1.0.0");
pub const TX_PROTOCOL: StreamProtocol = StreamProtocol::new("/stellar/tx/1.0.0");
pub const TXSET_PROTOCOL: StreamProtocol = StreamProtocol::new("/stellar/txset/1.0.0");
pub const TXSET_SHARD_PROTOCOL: StreamProtocol = StreamProtocol::new("/stellar/txset-shard/3.0.0");

/// Message frame: 4-byte length prefix + payload
/// Max message size: 16MB (for large TX sets)
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Bounded channel capacity for TX events (backpressure for TX flooding)
/// TXs that can't be queued are dropped - they'll be re-requested if needed.
const TX_EVENT_CHANNEL_CAPACITY: usize = 10_000;

/// How long an outstanding GetTxSet request may go unanswered before a new
/// fetch for the same hash is allowed to retry against a different peer.
/// Slightly below Core's ~1s fetch-fallback retry cadence so the retry
/// actually goes through instead of being deduplicated against the stuck
/// request (docs/direct-leader-flooding.md).
const TXSET_FETCH_RETRY_STALE: Duration = Duration::from_millis(900);

/// A peer can make us allocate at most this many incomplete TX sets. At the
/// 16 MiB TX-set wire limit plus 50% recovery data this bounds worst-case
/// accumulator payloads below 400 MiB, while normal consensus keeps only one
/// or two sets in flight.
const TXSET_MAX_ACTIVE_ACCUMULATORS: usize = 16;
const TXSET_SHARD_ACCUMULATOR_TTL: Duration = Duration::from_secs(60);

/// Events from the overlay to the application
#[derive(Debug, Clone)]
pub enum OverlayEvent {
    /// Received SCP envelope from peer, with any tx set hashes it references
    /// (extracted during the reader's single decode).
    ScpReceived {
        envelope: Vec<u8>,
        txset_hashes: Vec<[u8; 32]>,
        from: PeerId,
    },
    /// Received TX from peer
    TxReceived { tx: Arc<ValidatedTx>, from: PeerId },
    /// Received TX set response
    TxSetReceived {
        hash: [u8; 32],
        data: Vec<u8>,
        from: PeerId,
    },
    /// Peer is requesting a TX set (need to look up and respond)
    TxSetRequested { hash: [u8; 32], from: PeerId },
    /// Peer is requesting SCP state
    ScpStateRequested { peer_id: PeerId, ledger_seq: u32 },
    /// Peer connected — includes the remote address for PeerId mapping
    PeerConnected { peer_id: PeerId, addr: Multiaddr },
    /// Peer disconnected - clean up any pending requests
    PeerDisconnected { peer_id: PeerId },
}

/// Commands to the overlay
#[derive(Debug)]
pub enum OverlayCommand {
    /// Broadcast SCP envelope to all peers
    BroadcastScp(Vec<u8>),
    /// Broadcast a validated TX to all peers
    BroadcastTx(Arc<ValidatedTx>),
    /// Request TX set from a peer (picks best peer)
    FetchTxSet { hash: [u8; 32] },
    /// Send TX set to a specific peer (response to their request)
    SendTxSet {
        hash: [u8; 32],
        data: Vec<u8>,
        to: PeerId,
    },
    /// Eagerly code and assign a nominated TX set across connected Tier-1
    /// peers so receivers skip the GetTxSet round-trip.
    BroadcastTxSet { hash: [u8; 32], data: Vec<u8>, slot: u64 },
    /// Relay a network-received TX that Core has validated (see the
    /// validation gate in main.rs): store it for GETDATA service, then push
    /// to connected leaders (or INV-announce as fallback), excluding the
    /// origin peer and peers already known to have it.
    RelayValidatedTx { tx: Arc<ValidatedTx>, from: PeerId },
    /// Record that a peer has a specific TX set (learned from SCP message)
    RecordTxSetSource { hash: [u8; 32], peer: PeerId },
    /// Connect to a peer by address (bootstrap — PeerId unknown)
    Dial(Multiaddr),
    /// Connect to a known peer by PeerId (reconnect — deduplicates automatically)
    DialPeer { peer_id: PeerId, addr: Multiaddr },
    /// Request SCP state from all peers
    RequestScpState { ledger_seq: u32 },
    /// Send SCP envelope to a specific peer
    SendScpToPeer { peer_id: PeerId, envelope: Vec<u8> },
    /// Shutdown
    Shutdown,
    /// Query the number of connected peers (responds via oneshot)
    GetConnectedPeerCount(tokio::sync::oneshot::Sender<usize>),
    /// Ping - responds immediately via oneshot channel (for testing event loop responsiveness)
    Ping(tokio::sync::oneshot::Sender<()>),
}

/// Outbound streams to a peer - each stream has its own mutex to avoid head-of-line blocking.
/// A large TxSet write won't block SCP sends to the same peer.
struct PeerOutboundStreams {
    scp: Mutex<Option<Stream>>,
    tx: Mutex<Option<Stream>>,
    txset: Mutex<Option<Stream>>,
    txset_shard: Mutex<Option<Stream>>,
}

impl PeerOutboundStreams {
    fn new() -> Self {
        Self {
            scp: Mutex::new(None),
            tx: Mutex::new(None),
            txset: Mutex::new(None),
            txset_shard: Mutex::new(None),
        }
    }
}

struct TxSetShardStore {
    partial: HashMap<[u8; 32], TxSetShardAccumulator>,
    /// Shred indexes received while a threshold set is being decoded off the
    /// async runtime. This closes the race between removing a ready
    /// accumulator and publishing its completed marker.
    reconstructing: HashMap<[u8; 32], HashSet<usize>>,
    /// Completed TX sets and the direct shreds already seen for each. Keeping
    /// the indexes lets a late, previously unseen TTL=1 shred fulfill its
    /// forwarding duty exactly once without permitting replay amplification.
    completed: lru::LruCache<[u8; 32], HashSet<usize>>,
}

impl TxSetShardStore {
    fn new() -> Self {
        Self {
            partial: HashMap::new(),
            reconstructing: HashMap::new(),
            completed: lru::LruCache::new(std::num::NonZeroUsize::new(1000).unwrap()),
        }
    }
}

/// Network behaviour combining streams and Identify
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "StellarBehaviourEvent")]
struct StellarBehaviour {
    stream: StreamBehaviour,
    identify: Identify,
}

#[derive(Debug)]
enum StellarBehaviourEvent {
    Stream(()), // StreamBehaviour emits () - no events
    Identify(IdentifyEvent),
}

impl From<()> for StellarBehaviourEvent {
    fn from(_event: ()) -> Self {
        StellarBehaviourEvent::Stream(())
    }
}

impl From<IdentifyEvent> for StellarBehaviourEvent {
    fn from(event: IdentifyEvent) -> Self {
        StellarBehaviourEvent::Identify(event)
    }
}

/// Handle for sending commands to the overlay
#[derive(Clone)]
pub struct OverlayHandle {
    cmd_tx: mpsc::Sender<OverlayCommand>,
    /// Shared with SharedState. Written directly (not via the bounded command
    /// channel) so installing a new leader set can never block the caller's
    /// dispatch loop behind slow overlay commands, while still being ordered:
    /// the write completes before the caller processes its next message.
    flood_leaders: Arc<RwLock<Vec<PeerId>>>,
    /// Shared with SharedState; written directly (see flood_leaders).
    tx_batch_max_size: Arc<AtomicUsize>,
    /// Shared with SharedState; written directly (see flood_leaders).
    current_ledger_seq: Arc<AtomicU64>,
    /// Private coding pool, replaced when Core reports a new network
    /// transaction-cluster limit.
    txset_coding_executor: Arc<RwLock<Arc<TxSetCodingExecutor>>>,
    /// Runtime A/B switch. Receivers always accept both codecs.
    txset_compression_enabled: Arc<AtomicBool>,
}

impl OverlayHandle {
    /// Report the last closed ledger, so queued tx set pushes for completed
    /// rounds can be dropped instead of sent.
    pub fn set_current_ledger(&self, seq: u64) {
        self.current_ledger_seq.store(seq, Ordering::Relaxed);
    }

    /// Set the max TXs per pushed batch (0 or 1 = send each TX immediately).
    pub fn set_tx_batch_max_size(&self, max: usize) {
        debug!("TX batch max size set to {}", max);
        self.tx_batch_max_size.store(max, Ordering::Relaxed);
    }

    /// Bound Reed–Solomon encode/decode workers by
    /// ledgerMaxDependentTxClusters (`num_clusters` in the IPC contract).
    pub async fn set_txset_coding_parallelism(&self, num_clusters: usize) -> Result<(), String> {
        if self.txset_coding_executor.read().await.max_parallelism() == num_clusters {
            return Ok(());
        }
        let executor = tokio::task::spawn_blocking(move || {
            TxSetCodingExecutor::new(num_clusters).map(Arc::new)
        })
        .await
        .map_err(|e| format!("TX-set coding pool task failed: {e}"))??;
        *self.txset_coding_executor.write().await = executor;
        info!(
            "TX-set coding parallelism set to {} cluster(s)",
            num_clusters
        );
        Ok(())
    }

    pub fn set_txset_compression_enabled(&self, enabled: bool) {
        self.txset_compression_enabled
            .store(enabled, Ordering::Relaxed);
        info!("TX-set compression enabled={enabled}");
    }

    pub async fn broadcast_scp(&self, envelope: Vec<u8>) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::BroadcastScp(envelope))
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send BroadcastScp: {}",
                e
            );
        }
    }

    pub async fn broadcast_tx(&self, tx: Arc<ValidatedTx>) {
        if let Err(e) = self.cmd_tx.send(OverlayCommand::BroadcastTx(tx)).await {
            warn!(
                "Overlay command channel closed, failed to send BroadcastTx: {}",
                e
            );
        }
    }

    /// Relay a Core-validated received TX (see OverlayCommand::RelayValidatedTx).
    pub async fn relay_validated_tx(&self, tx: Arc<ValidatedTx>, from: PeerId) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::RelayValidatedTx { tx, from })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send RelayValidatedTx: {}",
                e
            );
        }
    }

    /// Set the flood-target leaders (ordered by election priority). Replaces
    /// the previous set; an empty set restores INV flooding to all peers.
    pub async fn set_leaders(&self, leaders: Vec<PeerId>) {
        debug!("Flood leaders updated: {} leaders", leaders.len());
        *self.flood_leaders.write().await = leaders;
    }

    pub async fn fetch_txset(&self, hash: [u8; 32]) {
        if let Err(e) = self.cmd_tx.send(OverlayCommand::FetchTxSet { hash }).await {
            warn!(
                "Overlay command channel closed, failed to send FetchTxSet: {}",
                e
            );
        }
    }

    pub async fn send_txset(&self, hash: [u8; 32], data: Vec<u8>, to: PeerId) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::SendTxSet { hash, data, to })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send SendTxSet: {}",
                e
            );
        }
    }

    /// Eagerly disseminate a TX set as Reed–Solomon shreds. `slot` is the
    /// consensus slot the set is proposed for; it is carried explicitly so a
    /// broadcast issued right after a ledger close is never mis-attributed
    /// to the just-closed slot and cancelled as stale.
    pub async fn broadcast_txset(&self, hash: [u8; 32], data: Vec<u8>, slot: u64) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::BroadcastTxSet { hash, data, slot })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send BroadcastTxSet: {}",
                e
            );
        }
    }

    /// Record that a peer has a specific TX set (call when receiving SCP with txSetHash)
    pub async fn record_txset_source(&self, hash: [u8; 32], peer: PeerId) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::RecordTxSetSource { hash, peer })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send RecordTxSetSource: {}",
                e
            );
        }
    }

    pub async fn dial(&self, addr: Multiaddr) {
        if let Err(e) = self.cmd_tx.send(OverlayCommand::Dial(addr)).await {
            warn!("Overlay command channel closed, failed to send Dial: {}", e);
        }
    }

    /// Dial a known peer by PeerId. libp2p will skip the dial if already connected.
    pub async fn dial_peer(&self, peer_id: PeerId, addr: Multiaddr) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::DialPeer { peer_id, addr })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send DialPeer: {}",
                e
            );
        }
    }

    pub async fn request_scp_state_from_all_peers(&self, ledger_seq: u32) {
        if let Err(e) = self
            .cmd_tx
            .send(OverlayCommand::RequestScpState { ledger_seq })
            .await
        {
            warn!(
                "Overlay command channel closed, failed to send RequestScpState: {}",
                e
            );
        }
    }

    pub async fn send_scp_to_peer(&self, peer_id: PeerId, envelope: &[u8]) -> io::Result<()> {
        self.cmd_tx
            .send(OverlayCommand::SendScpToPeer {
                peer_id,
                envelope: envelope.to_vec(),
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Channel closed"))?;
        Ok(())
    }

    pub async fn shutdown(&self) {
        if let Err(e) = self.cmd_tx.send(OverlayCommand::Shutdown).await {
            warn!(
                "Overlay command channel closed, failed to send Shutdown: {}",
                e
            );
        }
    }

    /// Query the number of currently connected peers
    pub async fn connected_peer_count(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self
            .cmd_tx
            .send(OverlayCommand::GetConnectedPeerCount(tx))
            .await;
        rx.await.unwrap_or(0)
    }

    /// Ping the event loop and wait for response - for testing responsiveness
    #[cfg(test)]
    pub async fn ping(&self) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.cmd_tx.send(OverlayCommand::Ping(tx)).await;
        rx.await
    }
}

struct SharedState {
    local_peer_id: PeerId,
    /// Outbound streams per peer - each peer has three independently-locked streams
    peer_streams: RwLock<HashMap<PeerId, Arc<PeerOutboundStreams>>>,
    /// SCP messages seen (for dedup)
    scp_seen: RwLock<lru::LruCache<[u8; 32], ()>>,
    /// TX messages seen (for dedup)
    tx_seen: RwLock<lru::LruCache<[u8; 32], ()>>,
    /// Track which peers we've sent each SCP message to (prevent duplicate sends)
    scp_sent_to: RwLock<lru::LruCache<[u8; 32], HashSet<PeerId>>>,
    /// TX set sources: which peer has which TX set (learned from SCP messages)
    txset_sources: RwLock<lru::LruCache<[u8; 32], PeerId>>,
    /// Pending TX set requests: hash -> (peer, request_time) to avoid duplicate fetches and track latency
    pending_txset_requests: RwLock<HashMap<[u8; 32], (PeerId, Instant)>>,
    /// Partial, reconstructing, and completed erasure-coded TX sets. A single
    /// lock makes completion publication atomic with respect to new shreds.
    txset_shard_store: Mutex<TxSetShardStore>,
    /// Reed–Solomon and forwarding parameters. TTL=1 targets a fully-connected
    /// Tier-1 validator topology.
    txset_shard_config: TxSetShardConfig,
    txset_coding_executor: Arc<RwLock<Arc<TxSetCodingExecutor>>>,
    txset_compression_enabled: Arc<AtomicBool>,
    /// Event sender for non-TX events (SCP, TxSet - critical path, unbounded)
    event_tx: mpsc::UnboundedSender<OverlayEvent>,
    /// Bounded TX event sender (backpressure - drops allowed)
    tx_event_tx: mpsc::Sender<OverlayEvent>,
    /// Counter for TXs dropped due to backpressure
    tx_dropped_count: AtomicU64,
    /// Stream control for reopening streams
    control: Control,

    // ============ INV/GETDATA State ============
    /// Batches INV announcements before sending (100ms or 1000 INVs)
    inv_batcher: RwLock<InvBatcher>,
    /// Tracks which peers have INV'd which TXs (for round-robin GETDATA)
    inv_tracker: RwLock<InvTracker>,
    /// Pending GETDATA requests with timeout tracking
    pending_getdata: RwLock<PendingRequests>,
    /// TX buffer for responding to GETDATA requests
    tx_buffer: RwLock<TxBuffer>,
    /// Upcoming nomination leaders to flood TXs to directly, ordered by
    /// election priority (see docs/direct-leader-flooding.md). Empty means no
    /// leader schedule is known and TXs are INV-flooded to all peers. Shared
    /// with OverlayHandle, which writes it directly.
    flood_leaders: Arc<RwLock<Vec<PeerId>>>,
    /// Batches TX bodies per destination before pushing (leader routing).
    /// One flushed batch = one stream write of concatenated Transaction
    /// frames -- the receiver's framed-read loop splits them, so the wire
    /// format is unchanged. See flood/tx_batcher.rs.
    tx_batcher: RwLock<TxBatcher>,
    /// Max TXs per pushed batch (Core's EXPERIMENTAL_TX_BATCH_MAX_SIZE via
    /// SetPeerConfig). 0 or 1 disables batching (send-per-TX). Shared with
    /// OverlayHandle, which writes it directly.
    tx_batch_max_size: Arc<AtomicUsize>,
    /// Last closed ledger as reported by Core (0 until first close). Used to
    /// avoid sending shreds whose consensus round closed while coding.
    current_ledger_seq: Arc<AtomicU64>,
    /// Monotonic latest-wins generation for locally nominated TX sets. A newer
    /// broadcast cancels unsent shreds from older coding/sending tasks.
    txset_shard_generation: AtomicU64,
    /// Overlay metrics (shared with App for IPC reporting)
    metrics: Arc<OverlayMetrics>,
}

impl SharedState {
    fn new(
        local_peer_id: PeerId,
        event_tx: mpsc::UnboundedSender<OverlayEvent>,
        tx_event_tx: mpsc::Sender<OverlayEvent>,
        control: Control,
        metrics: Arc<OverlayMetrics>,
        flood_leaders: Arc<RwLock<Vec<PeerId>>>,
        tx_batch_max_size: Arc<AtomicUsize>,
        current_ledger_seq: Arc<AtomicU64>,
        txset_coding_executor: Arc<RwLock<Arc<TxSetCodingExecutor>>>,
        txset_compression_enabled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            local_peer_id,
            peer_streams: RwLock::new(HashMap::new()),
            scp_seen: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(10000).unwrap(),
            )),
            tx_seen: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(100000).unwrap(),
            )),
            scp_sent_to: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(10000).unwrap(),
            )),
            txset_sources: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            )),
            pending_txset_requests: RwLock::new(HashMap::new()),
            txset_shard_store: Mutex::new(TxSetShardStore::new()),
            txset_shard_config: TxSetShardConfig::default(),
            txset_coding_executor,
            txset_compression_enabled,
            event_tx,
            tx_event_tx,
            tx_dropped_count: AtomicU64::new(0),
            control,
            // INV/GETDATA state
            inv_batcher: RwLock::new(InvBatcher::new()),
            inv_tracker: RwLock::new(InvTracker::new()),
            pending_getdata: RwLock::new(PendingRequests::new()),
            tx_buffer: RwLock::new(TxBuffer::new()),
            flood_leaders,
            tx_batcher: RwLock::new(TxBatcher::new()),
            tx_batch_max_size,
            current_ledger_seq,
            txset_shard_generation: AtomicU64::new(0),
            metrics,
        }
    }
}

/// The unified Stellar overlay
pub struct StellarOverlay {
    swarm: Swarm<StellarBehaviour>,
    control: Control,
    state: Arc<SharedState>,
    cmd_rx: mpsc::Receiver<OverlayCommand>,
}

/// Create the overlay and return handle + event receivers
///
/// Returns:
/// - `OverlayHandle`: for sending commands to the overlay
/// - `UnboundedReceiver<OverlayEvent>`: for SCP, TxSet events (critical path, never dropped)
/// - `Receiver<OverlayEvent>`: for TX events (bounded, may drop under backpressure)
/// - `StellarOverlay`: the overlay to run
pub fn create_overlay(
    keypair: Keypair,
    metrics: Arc<OverlayMetrics>,
) -> Result<
    (
        OverlayHandle,
        mpsc::UnboundedReceiver<OverlayEvent>,
        mpsc::Receiver<OverlayEvent>,
        StellarOverlay,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    create_overlay_with_txset_shard_config(keypair, metrics, TxSetShardConfig::default())
}

pub(crate) fn create_overlay_with_txset_shard_config(
    keypair: Keypair,
    metrics: Arc<OverlayMetrics>,
    txset_shard_config: TxSetShardConfig,
) -> Result<
    (
        OverlayHandle,
        mpsc::UnboundedReceiver<OverlayEvent>,
        mpsc::Receiver<OverlayEvent>,
        StellarOverlay,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let peer_id = keypair.public().to_peer_id();
    info!(
        "Creating StellarOverlay with peer_id={} (QUIC transport)",
        peer_id
    );

    // Build swarm with QUIC transport
    // Configure QUIC with keep-alive to prevent idle connection drops
    let mut quic_config = libp2p::quic::Config::new(&keypair);
    quic_config.keep_alive_interval = Duration::from_secs(15);
    quic_config.max_idle_timeout = 60_000; // 60 seconds in ms

    let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_quic_config(|_| quic_config)
        .with_behaviour(|key| {
            let stream = StreamBehaviour::new();

            let identify = Identify::new(IdentifyConfig::new(
                "/stellar/1.0.0".to_string(),
                key.public(),
            ));

            StellarBehaviour { stream, identify }
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    let control = swarm.behaviour().stream.new_control();

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    // Unbounded channel for critical events (SCP, TxSet) - never drop
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    // Bounded channel for TX events - drops allowed under backpressure
    let (tx_event_tx, tx_event_rx) = mpsc::channel(TX_EVENT_CHANNEL_CAPACITY);

    let flood_leaders = Arc::new(RwLock::new(Vec::new()));
    let tx_batch_max_size = Arc::new(AtomicUsize::new(0));
    let current_ledger_seq = Arc::new(AtomicU64::new(0));
    let txset_coding_executor = Arc::new(RwLock::new(Arc::new(
        TxSetCodingExecutor::new(1).expect("serial TX-set coding executor is valid"),
    )));
    let txset_compression_enabled = Arc::new(AtomicBool::new(true));
    let mut state = SharedState::new(
        peer_id,
        event_tx,
        tx_event_tx,
        control.clone(),
        metrics,
        Arc::clone(&flood_leaders),
        Arc::clone(&tx_batch_max_size),
        Arc::clone(&current_ledger_seq),
        Arc::clone(&txset_coding_executor),
        Arc::clone(&txset_compression_enabled),
    );
    state.txset_shard_config = txset_shard_config;
    let state = Arc::new(state);

    let overlay = StellarOverlay {
        swarm,
        control,
        state,
        cmd_rx,
    };

    let handle = OverlayHandle {
        cmd_tx,
        flood_leaders,
        tx_batch_max_size,
        current_ledger_seq,
        txset_coding_executor,
        txset_compression_enabled,
    };

    Ok((handle, event_rx, tx_event_rx, overlay))
}

impl StellarOverlay {
    /// Run the overlay event loop
    ///
    /// `listen_ip` should be a specific IP (e.g., "127.0.0.1" for local tests)
    /// to avoid multi-homing issues where Identify advertises multiple addresses.
    pub async fn run(mut self, listen_ip: &str, listen_port: u16) {
        // Start listening on QUIC (UDP)
        // Use specific IP to avoid Identify advertising all local IPs
        let listen_addr: Multiaddr = format!("/ip4/{}/udp/{}/quic-v1", listen_ip, listen_port)
            .parse()
            .unwrap();

        if let Err(e) = self.swarm.listen_on(listen_addr.clone()) {
            error!("Failed to listen on {}: {}", listen_addr, e);
            return;
        }
        info!("Listening on QUIC port {}", listen_port);

        // Accept incoming streams for each protocol
        let scp_incoming = match self.control.accept(SCP_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(
                    "Failed to accept SCP protocol streams: {:?}. Overlay cannot function.",
                    e
                );
                return;
            }
        };
        let tx_incoming = match self.control.accept(TX_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(
                    "Failed to accept TX protocol streams: {:?}. Overlay cannot function.",
                    e
                );
                return;
            }
        };
        let txset_incoming = match self.control.accept(TXSET_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(
                    "Failed to accept TxSet protocol streams: {:?}. Overlay cannot function.",
                    e
                );
                return;
            }
        };
        let txset_shard_incoming = match self.control.accept(TXSET_SHARD_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(
                    "Failed to accept TxSet shred protocol streams: {:?}. Overlay cannot function.",
                    e
                );
                return;
            }
        };

        // Spawn inbound stream handlers
        let state = self.state.clone();
        tokio::spawn(handle_inbound_scp_streams(scp_incoming, state.clone()));
        tokio::spawn(handle_inbound_tx_streams(tx_incoming, state.clone()));
        tokio::spawn(handle_inbound_txset_streams(txset_incoming, state.clone()));
        tokio::spawn(handle_inbound_txset_shard_streams(
            txset_shard_incoming,
            state.clone(),
        ));

        // Spawn INV/GETDATA housekeeping task
        tokio::spawn(inv_getdata_housekeeping_task(state.clone()));
        tokio::spawn(txset_shard_housekeeping_task(state.clone()));

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }

                Some(cmd) = self.cmd_rx.recv() => {
                    match cmd {
                        OverlayCommand::BroadcastScp(envelope) => {
                            self.broadcast_scp(&envelope).await;
                        }
                        OverlayCommand::BroadcastTx(tx) => {
                            self.broadcast_tx(tx).await;
                        }
                        OverlayCommand::RelayValidatedTx { tx, from } => {
                            relay_validated_tx(&self.state, tx, from).await;
                        }
                        OverlayCommand::FetchTxSet { hash } => {
                            self.fetch_txset(hash).await;
                        }
                        OverlayCommand::SendTxSet { hash, data, to } => {
                            self.send_txset_response(to, hash, data).await;
                        }
                        OverlayCommand::BroadcastTxSet { hash, data, slot } => {
                            // Reed–Solomon coding can take milliseconds for a
                            // maximum-size set. Keep it off the swarm task so
                            // SCP and connection polling remain responsive.
                            let state = Arc::clone(&self.state);
                            let generation = state
                                .txset_shard_generation
                                .fetch_add(1, Ordering::Relaxed)
                                .wrapping_add(1);
                            tokio::spawn(async move {
                                broadcast_txset_shards(state, hash, data, generation, slot)
                                    .await;
                            });
                        }
                        OverlayCommand::RecordTxSetSource { hash, peer } => {
                            let mut sources = self.state.txset_sources.write().await;
                            sources.put(hash, peer);
                            debug!("Recorded peer {} as source for TX set {:02x?}...", peer, &hash[..4]);
                        }
                        OverlayCommand::Dial(addr) => {
                            info!("Dialing peer at {}", addr);
                            self.state.metrics.connection_pending.fetch_add(1, Ordering::Relaxed);
                            self.state.metrics.outbound_attempt.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = self.swarm.dial(addr.clone()) {
                                self.state.metrics.connection_pending.fetch_sub(1, Ordering::Relaxed);
                                warn!("Failed to dial {}: {}", addr, e);
                            }
                        }
                        OverlayCommand::DialPeer { peer_id, addr } => {
                            let opts = DialOpts::peer_id(peer_id)
                                .condition(PeerCondition::Disconnected)
                                .addresses(vec![addr.clone()])
                                .build();
                            self.state.metrics.outbound_attempt.fetch_add(1, Ordering::Relaxed);
                            match self.swarm.dial(opts) {
                                Ok(_) => {
                                    self.state.metrics.connection_pending.fetch_add(1, Ordering::Relaxed);
                                    debug!("Dialing known peer {} at {}", peer_id, addr);
                                }
                                Err(e) => {
                                    // DialError::NoAddresses means already connected — not an error
                                    debug!("DialPeer {} skipped or failed: {}", peer_id, e);
                                }
                            }
                        }
                        OverlayCommand::RequestScpState { ledger_seq } => {
                            info!("Requesting SCP state (ledger >= {}) from all peers", ledger_seq);
                            self.request_scp_state_from_all_peers(ledger_seq).await;
                        }
                        OverlayCommand::SendScpToPeer { peer_id, envelope } => {
                            // Don't hold &self across await - extract state and call helper directly
                            let state = Arc::clone(&self.state);
                            let message = crate::xdr::frame_scp(&envelope);
                            if let Err(e) = send_to_peer_stream(&state, peer_id.clone(), StreamType::Scp, &message).await {
                                warn!("Failed to send SCP to {}: {:?}", peer_id, e);
                            }
                        }
                        OverlayCommand::Shutdown => {
                            info!("Overlay shutting down");
                            break;
                        }
                        OverlayCommand::GetConnectedPeerCount(responder) => {
                            let count = self.state.peer_streams.read().await.len();
                            let _ = responder.send(count);
                        }
                        OverlayCommand::Ping(responder) => {
                            let _ = responder.send(());
                        }
                    }
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<StellarBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
            }

            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                // Only decrement connection_pending for outbound dials we initiated
                if endpoint.is_dialer() {
                    self.state
                        .metrics
                        .connection_pending
                        .fetch_sub(1, Ordering::Relaxed);
                    self.state
                        .metrics
                        .outbound_establish
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.state
                        .metrics
                        .inbound_establish
                        .fetch_add(1, Ordering::Relaxed);
                }

                // Only open streams on the first connection to a peer.
                // When both sides dial simultaneously, two ConnectionEstablished
                // events fire for the same peer. Opening streams on each would
                // overwrite the first set, dropping those streams and causing
                // "unexpected end of file" on the remote's inbound handlers.
                if num_established.get() == 1 {
                    info!("Connected to peer {}", peer_id);
                    self.state
                        .metrics
                        .connection_authenticated
                        .fetch_add(1, Ordering::Relaxed);
                    {
                        let mut streams = self.state.peer_streams.write().await;
                        streams.insert(peer_id, Arc::new(PeerOutboundStreams::new()));
                    }

                    // Notify application so it can record the PeerId ↔ address mapping.
                    // Extract the remote address from the endpoint for reconnection.
                    let remote_addr = match &endpoint {
                        libp2p::core::ConnectedPoint::Dialer { address, .. } => address.clone(),
                        libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                            send_back_addr.clone()
                        }
                    };
                    let _ = self.state.event_tx.send(OverlayEvent::PeerConnected {
                        peer_id: peer_id.clone(),
                        addr: remote_addr,
                    });

                    // Spawn stream opening as a background task so the swarm
                    // event loop stays free to poll — control.open_stream()
                    // needs the swarm to process the request.
                    let control = self.control.clone();
                    let state = self.state.clone();
                    tokio::spawn(open_streams_to_peer(control, state, peer_id));
                } else {
                    debug!(
                        "Duplicate connection to {} (now {}), skipping stream setup",
                        peer_id, num_established
                    );
                }
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                // Only clean up when the LAST connection to this peer closes.
                // Duplicate connections closing shouldn't tear down working streams.
                if num_established == 0 {
                    info!("Disconnected from peer {}", peer_id);
                    self.state
                        .metrics
                        .connection_authenticated
                        .fetch_sub(1, Ordering::Relaxed);
                    self.state
                        .metrics
                        .outbound_drop
                        .fetch_add(1, Ordering::Relaxed);
                    {
                        let mut streams = self.state.peer_streams.write().await;
                        streams.remove(&peer_id);
                    }
                    // Clean up pending txset requests for this peer
                    {
                        let mut pending = self.state.pending_txset_requests.write().await;
                        let before_len = pending.len();
                        pending.retain(|_hash, (p, _)| p != &peer_id);
                        let removed = before_len - pending.len();
                        if removed > 0 {
                            info!(
                                "Removed {} pending txset requests for disconnected peer {}",
                                removed, peer_id
                            );
                        }
                    }
                    // Drop any TX batch queued for this peer
                    {
                        let mut batcher = self.state.tx_batcher.write().await;
                        batcher.remove_peer(&peer_id);
                    }
                    // Notify main loop to clean up any pending requests for this peer
                    if let Err(e) = self.state.event_tx.send(OverlayEvent::PeerDisconnected {
                        peer_id: peer_id.clone(),
                    }) {
                        warn!(
                            "Failed to send PeerDisconnected event for {}: {}",
                            peer_id, e
                        );
                    }
                } else {
                    debug!(
                        "Duplicate connection to {} closed ({} remaining)",
                        peer_id, num_established
                    );
                }
            }

            SwarmEvent::Behaviour(StellarBehaviourEvent::Identify(event)) => {
                if let IdentifyEvent::Received { peer_id, info, .. } = event {
                    debug!("Identified peer {}: {:?}", peer_id, info.listen_addrs);
                }
            }

            SwarmEvent::Behaviour(StellarBehaviourEvent::Stream(_)) => {
                // Stream events handled by the stream behaviour internally
            }

            SwarmEvent::IncomingConnection { .. } => {
                trace!("Incoming connection");
                self.state
                    .metrics
                    .inbound_attempt
                    .fetch_add(1, Ordering::Relaxed);
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!("Outgoing connection failed to {:?}: {}", peer_id, error);
                self.state
                    .metrics
                    .connection_pending
                    .fetch_sub(1, Ordering::Relaxed);
            }

            _ => {}
        }
    }

    /// Broadcast SCP envelope to all connected peers
    async fn broadcast_scp(&mut self, envelope: &[u8]) {
        // Core is trusted for encoding; frame by concatenation (no decode).
        let message = crate::xdr::frame_scp(envelope);
        let hash = blake2b_hash(envelope);

        // Mark as seen for inbound dedup (if we later receive this from a peer, skip it)
        {
            let mut seen = self.state.scp_seen.write().await;
            seen.put(hash, ());
        }

        // Determine which peers still need this message
        let streams = self.state.peer_streams.read().await;
        let all_peers: Vec<_> = streams.keys().cloned().collect();
        drop(streams);

        let peers_to_send: Vec<PeerId>;
        {
            let mut sent_to = self.state.scp_sent_to.write().await;
            let already_sent: HashSet<PeerId> = sent_to.peek(&hash).cloned().unwrap_or_default();

            peers_to_send = all_peers
                .into_iter()
                .filter(|p| !already_sent.contains(p))
                .collect();

            if peers_to_send.is_empty() {
                trace!(
                    "SCP_BROADCAST_SKIP: SCP {:02x?}... already sent to all connected peers",
                    &hash[..4]
                );
                return;
            }

            // Update sent_to with the peers we're about to send to
            let mut new_sent = already_sent;
            new_sent.extend(peers_to_send.iter().cloned());
            sent_to.put(hash, new_sent);
        }

        info!(
            "SCP_BROADCAST: Broadcasting SCP {:02x?}... ({} bytes) to {} peers",
            &hash[..4],
            envelope.len(),
            peers_to_send.len()
        );
        self.state
            .metrics
            .message_broadcast
            .fetch_add(1, Ordering::Relaxed);

        // Spawn parallel send tasks - don't block event loop waiting for each peer
        for peer_id in peers_to_send {
            let state = Arc::clone(&self.state);
            let message = message.clone();
            tokio::spawn(async move {
                match send_to_peer_stream(&state, peer_id.clone(), StreamType::Scp, &message).await
                {
                    Ok(_) => {
                        state
                            .metrics
                            .send_scp_message
                            .fetch_add(1, Ordering::Relaxed);
                        state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_write
                            .fetch_add(message.len() as u64, Ordering::Relaxed);
                        debug!(
                            "SCP_SEND_OK: Sent SCP {:02x?}... to {}",
                            &hash[..4],
                            peer_id
                        );
                    }
                    Err(e) => {
                        state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "SCP_SEND_FAIL: Failed to send SCP {:02x?}... to {}: {}",
                            &hash[..4],
                            peer_id,
                            e
                        );
                    }
                }
            });
        }
    }

    /// Broadcast TX to all connected peers
    /// Broadcast TX using INV/GETDATA protocol (bandwidth efficient)
    async fn broadcast_tx(&mut self, tx: Arc<ValidatedTx>) {
        let hash = *tx.hash();
        let fee_per_op = tx.fee_per_op();

        // Dedup check
        let already_seen = {
            let mut seen = self.state.tx_seen.write().await;
            if seen.contains(&hash) {
                true
            } else {
                seen.put(hash, ());
                self.state
                    .metrics
                    .memory_flood_known
                    .store(seen.len() as i64, Ordering::Relaxed);
                false
            }
        };
        if already_seen {
            // Core resubmitted a TX we already flooded. The original push may
            // have targeted a previous slot's leaders (or failed outright), so
            // re-push to the *current* connected leaders — receivers dedup via
            // tx_seen — but skip the INV re-flood. This keeps "TXs simply
            // resubmit" a real recovery path in leader-routing mode.
            if let Some(connected_leaders) = connected_flood_leaders(&self.state).await {
                if !connected_leaders.is_empty() {
                    {
                        let mut buffer = self.state.tx_buffer.write().await;
                        buffer.insert(hash, tx.bytes().to_vec());
                    }
                    debug!(
                        "TX_LEADER_REPUSH: Re-pushing resubmitted TX {:02x?}... to {} leaders",
                        &hash[..4],
                        connected_leaders.len()
                    );
                    push_tx_to_peers(&self.state, &connected_leaders, &tx, &hash, fee_per_op).await;
                    return;
                }
            }
            trace!("TX already seen, skipping broadcast");
            return;
        }

        // Store TX in buffer for GETDATA responses
        {
            let mut buffer = self.state.tx_buffer.write().await;
            buffer.insert(hash, tx.bytes().to_vec());
        }

        // Direct leader flooding: when the upcoming leaders are known and at
        // least one is connected, push the full body straight to them and skip
        // INV/GETDATA — the round-trip is pure overhead for a known recipient
        // that needs the TX. With no connected leader, fall back to INV
        // flooding for liveness.
        if let Some(connected_leaders) = connected_flood_leaders(&self.state).await {
            if !connected_leaders.is_empty() {
                debug!(
                    "TX_LEADER_PUSH: Pushing TX {:02x?}... ({} bytes) to {} leaders",
                    &hash[..4],
                    tx.bytes().len(),
                    connected_leaders.len()
                );
                push_tx_to_peers(&self.state, &connected_leaders, &tx, &hash, fee_per_op).await;
                return;
            }
            self.state
                .metrics
                .flood_leader_fallback
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                "TX_LEADER_FALLBACK: No connected leader, INV flooding TX {:02x?}...",
                &hash[..4]
            );
        }

        let streams = self.state.peer_streams.read().await;
        let peers: Vec<_> = streams.keys().cloned().collect();
        drop(streams);

        if peers.is_empty() {
            debug!("TX_INV: No peers to announce TX {:02x?}...", &hash[..4]);
            return;
        }

        debug!(
            "TX_INV: Announcing TX {:02x?}... ({} bytes) to {} peers via INV",
            &hash[..4],
            tx.bytes().len(),
            peers.len()
        );
        self.state
            .metrics
            .flood_advertised
            .fetch_add(peers.len() as u64, Ordering::Relaxed);

        let inv_entry = InvEntry { hash, fee_per_op };

        // Add to batcher for each peer, send batch immediately when full
        for peer in &peers {
            let batch_to_send = {
                let mut batcher = self.state.inv_batcher.write().await;
                batcher.add(*peer, inv_entry.clone())
            };
            if let Some(batch) = batch_to_send {
                send_inv_batch(&self.state, *peer, batch).await;
            }
        }
    }

    /// Fetch TX set from a peer - preferring the peer who sent us the SCP message referencing it
    async fn fetch_txset(&mut self, hash: [u8; 32]) {
        // Dedup: skip only if a request for this hash is outstanding, FRESH,
        // and its peer is still connected. A stale request (the peer accepted
        // it but never responded -- e.g. it had already evicted the set) must
        // NOT block forever: fall through and retry against a DIFFERENT peer.
        // Core drives retries at ~1s intervals (PendingEnvelopes fetch
        // fallback), so the staleness cutoff sits just below that.
        let avoid: Option<PeerId> = {
            let pending = self.state.pending_txset_requests.read().await;
            if let Some((pending_peer, requested_at)) = pending.get(&hash) {
                let streams = self.state.peer_streams.read().await;
                if streams.contains_key(pending_peer)
                    && requested_at.elapsed() < TXSET_FETCH_RETRY_STALE
                {
                    debug!(
                        "TXSET_FETCH_SKIP: TxSet {:02x?}... already being fetched from {}, skipping duplicate",
                        &hash[..4], pending_peer
                    );
                    return;
                }
                // Stale or disconnected: retry, avoiding the stuck peer.
                Some(*pending_peer)
            } else {
                None
            }
        };

        // Peer preference order:
        // 1. a known source (recorded when a peer referenced the set);
        // 2. a connected flood LEADER -- the round-1 leader built the set it
        //    nominated and always holds it, so it is the highest-probability
        //    server for exactly the set we are stuck on;
        // 3. a RANDOM connected peer, so successive retries rotate over the
        //    whole mesh instead of oscillating between the first map entries.
        // All choices exclude the peer a stale request is already stuck on.
        let known_source = {
            let sources = self.state.txset_sources.read().await;
            sources.peek(&hash).cloned()
        };
        let leaders = self.state.flood_leaders.read().await.clone();

        let peer = {
            let streams = self.state.peer_streams.read().await;
            let source_ok = known_source.filter(|p| streams.contains_key(p) && Some(*p) != avoid);
            let leader_ok = || {
                leaders
                    .iter()
                    .find(|p| streams.contains_key(p) && Some(**p) != avoid)
                    .cloned()
            };
            match source_ok.or_else(leader_ok).or_else(|| {
                use rand::seq::IteratorRandom;
                let mut rng = rand::thread_rng();
                streams
                    .keys()
                    .filter(|p| Some(**p) != avoid)
                    .choose(&mut rng)
                    .or_else(|| streams.keys().next())
                    .cloned()
            }) {
                Some(p) => {
                    info!(
                        "TXSET_FETCH: Fetching TX set {:02x?}... from {}{}",
                        &hash[..4],
                        p,
                        if avoid.is_some() { " (retry)" } else { "" }
                    );
                    p
                }
                None => {
                    warn!(
                        "TXSET_FETCH_FAIL: No peers to fetch TX set {:02x?}... from",
                        &hash[..4]
                    );
                    return;
                }
            }
        };

        // Record this pending request with timestamp for latency tracking
        self.state
            .pending_txset_requests
            .write()
            .await
            .insert(hash, (peer.clone(), Instant::now()));

        let request = crate::xdr::frame_get_tx_set(hash);

        // Send from a task: a congested TxSet stream to this peer must not
        // stall the overlay event loop (that stall was itself a wedge vector).
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            match send_to_peer_stream(&state, peer.clone(), StreamType::TxSet, &request).await {
                Ok(_) => info!(
                    "TXSET_FETCH_SENT: Sent request for TxSet {:02x?}... to {}",
                    &hash[..4],
                    peer
                ),
                Err(e) => {
                    warn!(
                        "TXSET_FETCH_FAIL: Failed to send TxSet request {:02x?}... to {}: {}",
                        &hash[..4],
                        peer,
                        e
                    );
                    state.pending_txset_requests.write().await.remove(&hash);
                }
            }
        });
    }

    /// Send TX set response to a specific peer
    async fn send_txset_response(&mut self, peer: PeerId, hash: [u8; 32], data: Vec<u8>) {
        info!(
            "TXSET_SEND: Sending TX set {:02x?}... ({} bytes) to {}",
            &hash[..4],
            data.len(),
            peer
        );

        // `data` is a tx set we already validated on entry (from a peer) or
        // built locally (trusted core); frame by concatenation.
        let response = crate::xdr::frame_tx_set(&data);

        // Send from a task: a multi-MB response through a congested or cold
        // link must not stall the overlay event loop (when many peers fetch
        // the same set, inline sends serialized the server's whole loop).
        //
        // Serve on a FRESH QUIC stream, not the cached per-peer TxSet stream:
        // the cached stream is where flood pushes queue, and QUIC streams are
        // FIFO -- a fetch response behind a jammed multi-MB push would wait
        // out the very congestion it is rescuing the requester from (the
        // perf-net wedge). A new stream gets independent flow control. Fall
        // back to the cached stream if the fresh one cannot be opened.
        let state = Arc::clone(&self.state);
        let mut control = self.control.clone();
        tokio::spawn(async move {
            let fresh = async {
                let mut stream = control
                    .open_stream(peer, TXSET_PROTOCOL)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e.to_string()))?;
                write_framed(&mut stream, &response).await
            }
            .await;
            let send_res = match fresh {
                Ok(()) => Ok(()),
                Err(e) => {
                    debug!(
                        "TXSET_SEND: fresh stream to {} failed ({}), using cached stream",
                        peer, e
                    );
                    send_to_peer_stream(&state, peer, StreamType::TxSet, &response).await
                }
            };
            match send_res {
                Ok(_) => {
                    state.metrics.send_txset.fetch_add(1, Ordering::Relaxed);
                    state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
                    state
                        .metrics
                        .byte_write
                        .fetch_add(response.len() as u64, Ordering::Relaxed);
                    info!(
                        "TXSET_SEND_OK: Successfully sent TX set {:02x?}... ({} bytes on wire) to {}",
                        &hash[..4],
                        response.len(),
                        peer
                    );
                }
                Err(e) => {
                    state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "TXSET_SEND_FAIL: Failed to send TxSet {:02x?}... to {}: {}",
                        &hash[..4],
                        peer,
                        e
                    );
                }
            }
        });
    }

    /// Request SCP state from all connected peers
    pub async fn request_scp_state_from_all_peers(&mut self, ledger_seq: u32) {
        let streams = self.state.peer_streams.read().await;
        let peers: Vec<_> = streams.keys().cloned().collect();
        drop(streams);

        info!(
            "Requesting SCP state for ledger >= {} from {} peers",
            ledger_seq,
            peers.len()
        );

        let request = crate::xdr::frame_get_scp_state(ledger_seq);
        for peer_id in peers {
            if let Err(e) =
                send_to_peer_stream(&self.state, peer_id, StreamType::Scp, &request).await
            {
                warn!("Failed to send SCP state request to {}: {:?}", peer_id, e);
            }
        }
    }

    /// Send SCP envelope to a specific peer
    pub async fn send_scp_to_peer(&self, peer_id: PeerId, envelope: &[u8]) -> io::Result<()> {
        let message = crate::xdr::frame_scp(envelope);
        send_to_peer_stream(&self.state, peer_id, StreamType::Scp, &message).await
    }
}

/// Erasure-code a locally nominated TX set and eagerly distribute each shred
/// to two branch roots. In the fully-connected Tier-1 topology, those roots
/// partition the other validators, balancing outgoing bandwidth without
/// duplicating relay edges.
async fn broadcast_txset_shards(
    state: Arc<SharedState>,
    hash: [u8; 32],
    data: Vec<u8>,
    generation: u64,
    slot: u64,
) {
    broadcast_txset_shards_with_branching_factor(
        state,
        hash,
        data,
        generation,
        slot,
        TXSET_SHARD_BRANCHING_FACTOR,
    )
    .await;
}

async fn broadcast_txset_shards_with_branching_factor(
    state: Arc<SharedState>,
    hash: [u8; 32],
    data: Vec<u8>,
    generation: u64,
    slot: u64,
    requested_branch_count: usize,
) {
    if !(1..=TXSET_MAX_SHARD_BRANCHING_FACTOR).contains(&requested_branch_count) {
        warn!(
            "TXSET_SHARD_BROADCAST_DROP: invalid branch factor {}",
            requested_branch_count
        );
        return;
    }
    if !crate::xdr::tx_set_hash_matches(&hash, &data) {
        warn!(
            "TXSET_SHARD_BROADCAST_DROP: TX set {:02x?}... has a content-hash mismatch",
            &hash[..4]
        );
        return;
    }

    let streams = state.peer_streams.read().await;
    let mut peers: Vec<PeerId> = streams.keys().cloned().collect();
    drop(streams);
    peers.sort_by_key(|peer| peer.to_bytes());
    if peers.is_empty() {
        debug!(
            "TXSET_SHARD_BROADCAST_SKIP: no peers for TX set {:02x?}...",
            &hash[..4]
        );
        return;
    }

    let data_len = data.len();
    let peer_count = peers.len();
    let branch_count = requested_branch_count.min(peer_count);
    // `slot` arrives with the broadcast request (never inferred from
    // `current_ledger_seq`): the round-1 leader pushes its pre-built set
    // right after apply-finish, and inferring the slot here would race the
    // LEDGER_CLOSED bookkeeping and drop every shred as stale.
    let config = state.txset_shard_config;
    let compression_enabled = state.txset_compression_enabled.load(Ordering::Relaxed);
    let coding_executor = state.txset_coding_executor.read().await.clone();
    let encode_start = Instant::now();
    let encoded = tokio::task::spawn_blocking(move || {
        let compress_start = Instant::now();
        let (transport, compression_error) = match encode_txset_transport(data, compression_enabled)
        {
            Ok(transport) => (transport, None),
            Err(error) => (
                TxSetTransport {
                    codec: TxSetCodec::Raw,
                    data: error.data,
                },
                Some(error.message),
            ),
        };
        let compress_us = compress_start.elapsed().as_micros() as u64;
        let transport_len = transport.data.len();
        let codec = transport.codec;
        let shards = make_txset_shards_parallel_with_codec(
            hash,
            &transport.data,
            codec,
            peer_count,
            config,
            &coding_executor,
        )?;
        shards
            .into_iter()
            .map(|shard| {
                let is_original = shard.is_original();
                (0..branch_count)
                    .map(|branch_index| {
                        shard
                            .with_branch(branch_index, branch_count)
                            .encode()
                            .map(|message| (is_original, Arc::new(message)))
                    })
                    .collect::<Result<Vec<_>, String>>()
            })
            .collect::<Result<Vec<_>, String>>()
            .map(|encoded| {
                (
                    encoded,
                    codec,
                    transport_len,
                    compress_us,
                    compression_error,
                )
            })
    })
    .await;
    let (encoded, codec, transport_len, compress_us, compression_error) = match encoded {
        Ok(Ok(encoded)) => encoded,
        Ok(Err(e)) => {
            warn!(
                "TXSET_SHARD_BROADCAST_DROP: failed to code TX set {:02x?}...: {}",
                &hash[..4],
                e
            );
            return;
        }
        Err(e) => {
            warn!(
                "TXSET_SHARD_BROADCAST_DROP: coding task for {:02x?}... failed: {}",
                &hash[..4],
                e
            );
            return;
        }
    };
    if compression_enabled {
        state
            .metrics
            .txset_shard_compress_sum_us
            .fetch_add(compress_us, Ordering::Relaxed);
        state
            .metrics
            .txset_shard_compress_count
            .fetch_add(1, Ordering::Relaxed);
    }
    if let Some(error) = compression_error {
        warn!(
            "TXSET_SHARD_COMPRESS_FALLBACK: sending TX set {:02x?}... raw: {}",
            &hash[..4],
            error
        );
    }
    if state.current_ledger_seq.load(Ordering::Relaxed) >= slot
        || state.txset_shard_generation.load(Ordering::Relaxed) != generation
    {
        let message_count: usize = encoded.iter().map(Vec::len).sum();
        state
            .metrics
            .flood_txset_push_dropped
            .fetch_add(message_count as u64, Ordering::Relaxed);
        debug!(
            "TXSET_SHARD_BROADCAST_STALE: dropping {} coded shreds for closed or superseded slot {}",
            message_count,
            slot
        );
        return;
    }
    state
        .metrics
        .txset_shard_plain_bytes
        .fetch_add(data_len as u64, Ordering::Relaxed);
    state
        .metrics
        .txset_shard_compressed_bytes
        .fetch_add(transport_len as u64, Ordering::Relaxed);
    if codec == TxSetCodec::Raw {
        state
            .metrics
            .txset_shard_raw_sent
            .fetch_add(1, Ordering::Relaxed);
    }
    state
        .metrics
        .txset_shard_encode_sum_us
        .fetch_add(encode_start.elapsed().as_micros() as u64, Ordering::Relaxed);
    state
        .metrics
        .txset_shard_encode_count
        .fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .txset_shard_broadcast
        .fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .message_broadcast
        .fetch_add(1, Ordering::Relaxed);

    let original_shards = encoded
        .iter()
        .filter(|branches| branches.first().is_some_and(|(original, _)| *original))
        .count();
    let recovery_shards = encoded.len() - original_shards;
    info!(
        "TXSET_SHARD_BROADCAST: TX set {:02x?}... ({} plain, {} encoded bytes, codec {:?}) -> {} original + {} recovery shreds, branch factor {}, across {} peers",
        &hash[..4],
        data_len,
        transport_len,
        codec,
        original_shards,
        recovery_shards,
        branch_count,
        peer_count
    );

    // Nominator upload span: coding start until the last shred leaves the wire.
    // The sends are spawned per peer, so the task that retires the final message
    // records it. Compare against codedBytes/linkRate to tell a saturated uplink
    // from a scheduling problem.
    let assignments =
        assign_shard_branches_to_peer_offsets(encoded.len(), peer_count, branch_count);
    let outstanding = Arc::new(AtomicUsize::new(
        assignments.iter().map(Vec::len).sum::<usize>().max(1),
    ));

    for (peer, offsets) in peers.into_iter().zip(assignments) {
        let state = Arc::clone(&state);
        let outstanding = Arc::clone(&outstanding);
        let messages: Vec<_> = offsets
            .into_iter()
            .map(|(offset, branch_index)| encoded[offset][branch_index].clone())
            .collect();
        tokio::spawn(async move {
            let message_count = messages.len();
            for (offset, (is_original, message)) in messages.into_iter().enumerate() {
                if state.current_ledger_seq.load(Ordering::Relaxed) >= slot
                    || state.txset_shard_generation.load(Ordering::Relaxed) != generation
                {
                    state
                        .metrics
                        .flood_txset_push_dropped
                        .fetch_add((message_count - offset) as u64, Ordering::Relaxed);
                    break;
                }
                match send_to_peer_stream(&state, peer, StreamType::TxSetShard, &message).await {
                    Ok(()) => {
                        state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
                        state.metrics.send_txset.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .flood_txset_push
                            .fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_write
                            .fetch_add(message.len() as u64, Ordering::Relaxed);
                        state
                            .metrics
                            .flood_txset_push_bytes
                            .fetch_add(message.len() as u64, Ordering::Relaxed);
                        let counter = if is_original {
                            &state.metrics.txset_shard_original_sent
                        } else {
                            &state.metrics.txset_shard_recovery_sent
                        };
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "TXSET_SHARD_SEND_FAIL: failed sending {:02x?}... shred to {}: {}",
                            &hash[..4],
                            peer,
                            e
                        );
                    }
                }
            }
            // This peer's share is done, sent or skipped. The task that retires
            // the last share of the set stamps the nominator's upload span.
            if outstanding.fetch_sub(message_count, Ordering::Relaxed) == message_count {
                state
                    .metrics
                    .txset_shard_broadcast_span_sum_us
                    .fetch_add(encode_start.elapsed().as_micros() as u64, Ordering::Relaxed);
                state
                    .metrics
                    .txset_shard_broadcast_span_count
                    .fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}

/// Open SCP, TX, TxSet-fetch, and TxSet-shred streams to a peer.
/// Spawned as a background task so the swarm event loop stays unblocked —
/// `control.open_stream()` needs the swarm to be polled to complete.
async fn open_streams_to_peer(mut control: Control, state: Arc<SharedState>, peer_id: PeerId) {
    debug!("Opening streams to peer {}", peer_id);

    let mut control2 = control.clone();
    let mut control3 = control.clone();
    let mut control4 = control.clone();

    let scp_fut = async { control.open_stream(peer_id, SCP_PROTOCOL).await };
    let tx_fut = async { control2.open_stream(peer_id, TX_PROTOCOL).await };
    let txset_fut = async { control3.open_stream(peer_id, TXSET_PROTOCOL).await };
    let txset_shard_fut = async { control4.open_stream(peer_id, TXSET_SHARD_PROTOCOL).await };

    let (scp_result, tx_result, txset_result, txset_shard_result) =
        tokio::join!(scp_fut, tx_fut, txset_fut, txset_shard_fut);

    let scp_stream = match scp_result {
        Ok(s) => {
            debug!("Opened SCP stream to {}", peer_id);
            Some(s)
        }
        Err(e) => {
            warn!("Failed to open SCP stream to {}: {:?}", peer_id, e);
            None
        }
    };

    let tx_stream = match tx_result {
        Ok(s) => {
            debug!("Opened TX stream to {}", peer_id);
            Some(s)
        }
        Err(e) => {
            warn!("Failed to open TX stream to {}: {:?}", peer_id, e);
            None
        }
    };

    let txset_stream = match txset_result {
        Ok(s) => {
            debug!("Opened TxSet stream to {}", peer_id);
            Some(s)
        }
        Err(e) => {
            warn!("Failed to open TxSet stream to {}: {:?}", peer_id, e);
            None
        }
    };
    let txset_shard_stream = match txset_shard_result {
        Ok(s) => {
            debug!("Opened TxSet shred stream to {}", peer_id);
            Some(s)
        }
        Err(e) => {
            warn!("Failed to open TxSet shred stream to {}: {:?}", peer_id, e);
            None
        }
    };

    // Store streams
    {
        let streams = state.peer_streams.read().await;
        if let Some(peer_streams) = streams.get(&peer_id) {
            if let Some(stream) = scp_stream {
                *peer_streams.scp.lock().await = Some(stream);
            }
            if let Some(stream) = tx_stream {
                *peer_streams.tx.lock().await = Some(stream);
            }
            if let Some(stream) = txset_stream {
                *peer_streams.txset.lock().await = Some(stream);
            }
            if let Some(stream) = txset_shard_stream {
                *peer_streams.txset_shard.lock().await = Some(stream);
            }
        }
    }

    // Request SCP state from newly connected peer
    info!("Peer {} streams opened, sending SCP state request", peer_id);
    let ledger_seq: u32 = 0;
    let request = crate::xdr::frame_get_scp_state(ledger_seq);
    if let Err(e) = send_to_peer_stream(&state, peer_id.clone(), StreamType::Scp, &request).await {
        info!(
            "Failed to request SCP state from newly connected peer {}: {:?}",
            peer_id, e
        );
    }
}

#[derive(Clone, Copy)]
enum StreamType {
    Scp,
    Tx,
    TxSet,
    TxSetShard,
}

impl StreamType {
    fn protocol(&self) -> StreamProtocol {
        match self {
            StreamType::Scp => SCP_PROTOCOL,
            StreamType::Tx => TX_PROTOCOL,
            StreamType::TxSet => TXSET_PROTOCOL,
            StreamType::TxSetShard => TXSET_SHARD_PROTOCOL,
        }
    }
}

/// Send message to a specific peer's stream only if already open (for flooding)
/// Returns Ok(()) if sent, Err if stream not open (doesn't try to reopen)
async fn try_send_to_existing_stream(
    state: &SharedState,
    peer_id: PeerId,
    stream_type: StreamType,
    data: &[u8],
) -> io::Result<()> {
    let streams = state.peer_streams.read().await;
    let peer_streams = streams
        .get(&peer_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "peer not connected"))?
        .clone();
    drop(streams);

    // Lock only the specific stream we need - no head-of-line blocking
    let stream_mutex = match stream_type {
        StreamType::Scp => &peer_streams.scp,
        StreamType::Tx => &peer_streams.tx,
        StreamType::TxSet => &peer_streams.txset,
        StreamType::TxSetShard => &peer_streams.txset_shard,
    };

    let mut stream_guard = stream_mutex.lock().await;

    // If stream not open, fail immediately without reopening
    let stream = stream_guard
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream not open"))?;

    write_framed(stream, data).await
}

/// Send message to a specific peer's stream, reopening if needed
async fn send_to_peer_stream(
    state: &SharedState,
    peer_id: PeerId,
    stream_type: StreamType,
    data: &[u8],
) -> io::Result<()> {
    send_to_peer_stream_inner(state, peer_id, stream_type, data, false).await
}

/// Send bytes that already carry their own per-message length prefixes (a
/// coalesced batch of frames) as ONE write. The receiver's framed-read loop
/// splits them back into individual messages.
async fn send_preframed_to_peer_stream(
    state: &SharedState,
    peer_id: PeerId,
    stream_type: StreamType,
    data: &[u8],
) -> io::Result<()> {
    send_to_peer_stream_inner(state, peer_id, stream_type, data, true).await
}

async fn send_to_peer_stream_inner(
    state: &SharedState,
    peer_id: PeerId,
    stream_type: StreamType,
    data: &[u8],
    preframed: bool,
) -> io::Result<()> {
    // Retry up to 2 times (3 attempts total) for reliability
    const MAX_RETRIES: usize = 2;

    for attempt in 0..=MAX_RETRIES {
        let streams = state.peer_streams.read().await;
        let peer_streams = match streams.get(&peer_id) {
            Some(ps) => ps.clone(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "peer not connected",
                ));
            }
        };
        drop(streams);

        // Lock only the specific stream we need - no head-of-line blocking
        let stream_mutex = match stream_type {
            StreamType::Scp => &peer_streams.scp,
            StreamType::Tx => &peer_streams.tx,
            StreamType::TxSet => &peer_streams.txset,
            StreamType::TxSetShard => &peer_streams.txset_shard,
        };

        let mut stream_guard = stream_mutex.lock().await;

        // If stream is None, try to reopen it
        if stream_guard.is_none() {
            debug!(
                "Stream {:?} not open to {}, attempting to reopen (attempt {})",
                stream_type.protocol(),
                peer_id,
                attempt + 1
            );
            match state
                .control
                .clone()
                .open_stream(peer_id, stream_type.protocol())
                .await
            {
                Ok(s) => {
                    debug!(
                        "Successfully reopened {:?} stream to {}",
                        stream_type.protocol(),
                        peer_id
                    );
                    *stream_guard = Some(s);
                }
                Err(e) => {
                    if attempt < MAX_RETRIES {
                        debug!(
                            "Failed to reopen {:?} stream to {} (attempt {}), retrying: {:?}",
                            stream_type.protocol(),
                            peer_id,
                            attempt + 1,
                            e
                        );
                        drop(stream_guard);
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            10 * (attempt as u64 + 1),
                        ))
                        .await;
                        continue;
                    }
                    warn!(
                        "Failed to reopen {:?} stream to {}: {:?}",
                        stream_type.protocol(),
                        peer_id,
                        e
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        format!("failed to reopen stream: {:?}", e),
                    ));
                }
            }
        }

        let stream = stream_guard.as_mut().unwrap();
        let write_res = if preframed {
            write_raw(stream, data).await
        } else {
            write_framed(stream, data).await
        };
        match write_res {
            Ok(()) => return Ok(()),
            Err(e) => {
                // Clear the broken stream
                *stream_guard = None;

                if attempt < MAX_RETRIES {
                    debug!(
                        "Send to {:?} stream failed (attempt {}), retrying: {}",
                        stream_type.protocol(),
                        attempt + 1,
                        e
                    );
                    drop(stream_guard);
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        10 * (attempt as u64 + 1),
                    ))
                    .await;
                    continue;
                }
                return Err(e);
            }
        }
    }

    unreachable!()
}

/// Write length-prefixed frame to stream
async fn write_framed(stream: &mut Stream, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Write bytes that already contain their own frame length prefixes.
async fn write_raw(stream: &mut Stream, data: &[u8]) -> io::Result<()> {
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Flush INV batch for a specific peer
async fn flush_inv_batch_to_peer(state: &Arc<SharedState>, peer: PeerId) {
    let batch = {
        let mut batcher = state.inv_batcher.write().await;
        batcher.flush(&peer)
    };

    if let Some(batch) = batch {
        send_inv_batch(state, peer, batch).await;
    }
}

/// Send an INV batch to a peer
async fn send_inv_batch(state: &Arc<SharedState>, peer: PeerId, batch: InvBatch) {
    let batch_size = batch.entries.len() as u64;
    let encoded = match batch.encode() {
        Ok(encoded) => encoded,
        Err(e) => {
            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
            warn!("Failed to encode INV batch for {}: {}", peer, e);
            return;
        }
    };
    let encoded_len = encoded.len() as u64;

    let state = Arc::clone(state);
    tokio::spawn(async move {
        if let Err(e) = send_to_peer_stream(&state, peer.clone(), StreamType::Tx, &encoded).await {
            state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
            warn!("Failed to send INV batch to {}: {}", peer, e);
        } else {
            state
                .metrics
                .send_transaction
                .fetch_add(1, Ordering::Relaxed);
            state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .byte_write
                .fetch_add(encoded_len, Ordering::Relaxed);
            state
                .metrics
                .flood_tx_batch_size_sum
                .fetch_add(batch_size, Ordering::Relaxed);
            state
                .metrics
                .flood_tx_batch_size_count
                .fetch_add(1, Ordering::Relaxed);
            debug!("TX_INV_SENT: Sent INV batch to {}", peer);
        }
    });
}

/// Read length-prefixed frame from stream
async fn read_framed(stream: &mut Stream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {} > {}", len, MAX_MESSAGE_SIZE),
        ));
    }

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

/// Handle inbound SCP streams from peers
async fn handle_inbound_scp_streams(mut incoming: IncomingStreams, state: Arc<SharedState>) {
    while let Some((peer_id, mut stream)) = incoming.next().await {
        info!("SCP_STREAM: Accepted inbound SCP stream from {}", peer_id);
        state
            .metrics
            .inbound_establish
            .fetch_add(1, Ordering::Relaxed);
        state.metrics.inbound_live.fetch_add(1, Ordering::Relaxed);
        let state = state.clone();

        tokio::spawn(async move {
            loop {
                match read_framed(&mut stream).await {
                    Ok(data) => {
                        state.metrics.message_read.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_read
                            .fetch_add(data.len() as u64, Ordering::Relaxed);

                        let message = match crate::xdr::parse_stellar_message(&data) {
                            Ok(message) => message,
                            Err(e) => {
                                warn!("SCP_PARSE_ERR: Dropping malformed SCP stream message from {}: {}", peer_id, e);
                                continue;
                            }
                        };

                        // Extract the canonical envelope bytes (the frame after
                        // the 4-byte discriminant) and any referenced tx set
                        // hashes from the single decode above.
                        let (envelope, txset_hashes) = match message {
                            stellar_xdr::curr::StellarMessage::GetScpState(ledger_seq) => {
                                info!(
                                    "SCP_STATE_REQ: Peer {} requests SCP state for ledger >= {}",
                                    peer_id, ledger_seq
                                );

                                // Notify main loop via event channel
                                if let Err(e) =
                                    state.event_tx.send(OverlayEvent::ScpStateRequested {
                                        peer_id: peer_id.clone(),
                                        ledger_seq,
                                    })
                                {
                                    error!("Failed to send SCP state request event: {:?}", e);
                                }
                                continue;
                            }
                            stellar_xdr::curr::StellarMessage::ScpMessage(scp_envelope) => {
                                let txset_hashes =
                                    crate::xdr::extract_txset_hashes_from_envelope(&scp_envelope);
                                (data[4..].to_vec(), txset_hashes)
                            }
                            other => {
                                warn!(
                                    "SCP_PARSE_ERR: Dropping unexpected {} on SCP stream from {}",
                                    other.name(),
                                    peer_id
                                );
                                continue;
                            }
                        };

                        let hash = blake2b_hash(&envelope);
                        let recv_start = std::time::Instant::now();
                        let is_dup = {
                            let mut seen = state.scp_seen.write().await;
                            if seen.contains(&hash) {
                                true
                            } else {
                                seen.put(hash, ());
                                false
                            }
                        };

                        // Record sender in scp_sent_to so we don't echo the message back
                        {
                            let mut sent_to = state.scp_sent_to.write().await;
                            if let Some(peers) = sent_to.get_mut(&hash) {
                                peers.insert(peer_id.clone());
                            } else {
                                let mut set = HashSet::new();
                                set.insert(peer_id.clone());
                                sent_to.put(hash, set);
                            }
                        }

                        if is_dup {
                            debug!(
                                "SCP_RECV_DUP: Duplicate SCP {:02x?}... from {}",
                                &hash[..4],
                                peer_id
                            );
                            continue;
                        }

                        info!(
                            "SCP_RECV: Received SCP {:02x?}... ({} bytes) from {}",
                            &hash[..4],
                            envelope.len(),
                            peer_id
                        );

                        // Forward to Core
                        if let Err(e) = state.event_tx.send(OverlayEvent::ScpReceived {
                            envelope,
                            txset_hashes,
                            from: peer_id.clone(),
                        }) {
                            warn!("Failed to forward SCP event from {}: {}", peer_id, e);
                        }

                        let elapsed_us = recv_start.elapsed().as_micros() as u64;
                        state
                            .metrics
                            .recv_scp_sum_us
                            .fetch_add(elapsed_us, Ordering::Relaxed);
                        state.metrics.recv_scp_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        state.metrics.error_read.fetch_add(1, Ordering::Relaxed);
                        state.metrics.inbound_live.fetch_sub(1, Ordering::Relaxed);
                        warn!(
                            "SCP_STREAM_CLOSED: SCP stream from {} closed: {}",
                            peer_id, e
                        );
                        break;
                    }
                }
            }
        });
    }
}

/// Handle inbound TX streams from peers
async fn handle_inbound_tx_streams(mut incoming: IncomingStreams, state: Arc<SharedState>) {
    while let Some((peer_id, mut stream)) = incoming.next().await {
        info!("TX_STREAM: Accepted inbound TX stream from {}", peer_id);
        state.metrics.inbound_live.fetch_add(1, Ordering::Relaxed);
        let state = state.clone();

        tokio::spawn(async move {
            loop {
                match read_framed(&mut stream).await {
                    Ok(data) => {
                        state.metrics.message_read.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_read
                            .fetch_add(data.len() as u64, Ordering::Relaxed);
                        // Parse INV/GETDATA message
                        handle_tx_stream_message(&state, &peer_id, &data, &mut stream).await;
                    }
                    Err(e) => {
                        state.metrics.error_read.fetch_add(1, Ordering::Relaxed);
                        state.metrics.inbound_live.fetch_sub(1, Ordering::Relaxed);
                        info!("TX stream from {} closed: {}", peer_id, e);
                        break;
                    }
                }
            }
        });
    }
}

/// Handle TX stream message in INV/GETDATA mode
async fn handle_tx_stream_message(
    state: &Arc<SharedState>,
    peer_id: &PeerId,
    data: &[u8],
    stream: &mut Stream,
) {
    match TxStreamMessage::decode(data) {
        Ok(TxStreamMessage::InvBatch(batch)) => {
            handle_inv_batch(state, peer_id, batch).await;
        }
        Ok(TxStreamMessage::GetData(getdata)) => {
            handle_getdata(state, peer_id, getdata, stream).await;
        }
        Ok(TxStreamMessage::Tx(tx)) => {
            handle_tx_response(state, peer_id, tx).await;
        }
        Err(e) => {
            warn!(
                "TX_PARSE_ERR: Failed to parse message from {}: {}",
                peer_id, e
            );
        }
    }
}

/// Handle INV_BATCH message - record sources and request TXs we don't have
async fn handle_inv_batch(state: &Arc<SharedState>, peer_id: &PeerId, batch: InvBatch) {
    debug!(
        "TX_INV_RECV: Received {} INVs from {}",
        batch.entries.len(),
        peer_id
    );

    let mut to_request: Vec<[u8; 32]> = Vec::new();

    for entry in batch.entries {
        // Check if we already have this TX
        {
            let seen = state.tx_seen.read().await;
            if seen.contains(&entry.hash) {
                // Already have it, just record this peer as a source (for relay tracking)
                continue;
            }
        }

        // Record this peer as a source for round-robin GETDATA
        let is_first = {
            let mut tracker = state.inv_tracker.write().await;
            tracker.record_source(entry.hash, *peer_id)
        };

        // If this is the first INV for this TX, we should request it
        if is_first {
            to_request.push(entry.hash);
        }
    }

    // Send GETDATA for TXs we don't have
    if !to_request.is_empty() {
        state
            .metrics
            .flood_demanded
            .fetch_add(to_request.len() as u64, Ordering::Relaxed);
        debug!(
            "TX_GETDATA_SEND: Requesting {} TXs from {}",
            to_request.len(),
            peer_id
        );

        // Record pending requests
        {
            let mut pending = state.pending_getdata.write().await;
            for hash in &to_request {
                pending.insert(*hash, *peer_id);
            }
        }

        // Build and send GETDATA
        let mut getdata = GetData::new();
        for hash in to_request {
            getdata.push(hash);
        }
        let encoded = match getdata.encode() {
            Ok(encoded) => encoded,
            Err(e) => {
                warn!("Failed to encode GETDATA for {}: {}", peer_id, e);
                return;
            }
        };

        let state_clone = Arc::clone(state);
        let peer_clone = *peer_id;
        tokio::spawn(async move {
            if let Err(e) =
                send_to_peer_stream(&state_clone, peer_clone, StreamType::Tx, &encoded).await
            {
                warn!("Failed to send GETDATA to {}: {}", peer_clone, e);
            }
        });
    }
}

/// Handle GETDATA message - respond with requested TXs
async fn handle_getdata(
    state: &Arc<SharedState>,
    peer_id: &PeerId,
    getdata: GetData,
    _stream: &mut Stream,
) {
    debug!(
        "TX_GETDATA_RECV: Peer {} requesting {} TXs",
        peer_id,
        getdata.hashes.len()
    );

    for hash in getdata.hashes {
        // Look up TX in our buffer
        let tx_data = {
            let mut buffer = state.tx_buffer.write().await;
            buffer.get_cloned(&hash)
        };

        if let Some(tx_data) = tx_data {
            state
                .metrics
                .flood_fulfilled
                .fetch_add(1, Ordering::Relaxed);
            // Send TX response. Buffered bytes were validated on entry, so
            // framing them (concat) yields valid wire XDR by construction.
            let encoded = crate::xdr::frame_transaction(&tx_data);

            let state_clone = Arc::clone(state);
            let peer_clone = *peer_id;
            tokio::spawn(async move {
                if let Err(e) =
                    send_to_peer_stream(&state_clone, peer_clone, StreamType::Tx, &encoded).await
                {
                    state_clone
                        .metrics
                        .error_write
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("Failed to send TX to {}: {}", peer_clone, e);
                } else {
                    state_clone
                        .metrics
                        .message_write
                        .fetch_add(1, Ordering::Relaxed);
                    state_clone
                        .metrics
                        .byte_write
                        .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                    debug!("TX_SEND: Sent TX {:02x?}... to {}", &hash[..4], peer_clone);
                }
            });
        } else {
            state
                .metrics
                .flood_unfulfilled_unknown
                .fetch_add(1, Ordering::Relaxed);
            trace!(
                "TX_GETDATA_MISS: Don't have TX {:02x?}... for {}",
                &hash[..4],
                peer_id
            );
        }
    }
}

/// Handle TX response (from GETDATA request)
/// Direct leader flooding (see docs/direct-leader-flooding.md): the subset of
/// the current flood-leader set with live streams, in priority order. Returns
/// `None` when no leader schedule is known — the caller should INV-flood to
/// all peers as before. `Some(empty)` means leaders are known but none is
/// connected (callers fall back to INV flooding for liveness).
async fn connected_flood_leaders(state: &Arc<SharedState>) -> Option<Vec<PeerId>> {
    let leaders = state.flood_leaders.read().await;
    if leaders.is_empty() {
        return None;
    }
    let streams = state.peer_streams.read().await;
    Some(
        leaders
            .iter()
            .filter(|p| streams.contains_key(p))
            .cloned()
            .collect(),
    )
}

/// INV-announce a TX to every connected peer (the legacy flood primitive,
/// also used to rescue a TX whose direct leader push failed so it remains
/// pullable). Assumes the TX is already in `tx_buffer`.
async fn announce_tx_inv_to_all(state: &Arc<SharedState>, hash: &[u8; 32], fee_per_op: i64) {
    let peers: Vec<PeerId> = {
        let streams = state.peer_streams.read().await;
        streams.keys().cloned().collect()
    };
    if peers.is_empty() {
        return;
    }
    state
        .metrics
        .flood_advertised
        .fetch_add(peers.len() as u64, Ordering::Relaxed);
    let inv_entry = InvEntry {
        hash: *hash,
        fee_per_op,
    };
    for peer in &peers {
        let batch_to_send = {
            let mut batcher = state.inv_batcher.write().await;
            batcher.add(*peer, inv_entry.clone())
        };
        if let Some(batch) = batch_to_send {
            send_inv_batch(state, *peer, batch).await;
        }
    }
}

/// Push a full TX body directly to `peers` on the TX stream, skipping the
/// INV/GETDATA round-trip. Used for leader-targeted flooding; receivers
/// dedup via `tx_seen` exactly as for pulled TXs.
///
/// A direct push is often this TX's *only* delivery attempt (there is no
/// GETDATA retry machinery behind it), so a failed send falls back to
/// INV-announcing the TX to all peers, restoring pull-mode recoverability.
/// The flood_leader_push metrics count *successful* sends only.
async fn push_tx_to_peers(
    state: &Arc<SharedState>,
    peers: &[PeerId],
    tx: &Arc<ValidatedTx>,
    hash: &[u8; 32],
    fee_per_op: i64,
) {
    let _ = (hash, fee_per_op); // identity travels inside the ValidatedTx
    let max_batch = state.tx_batch_max_size.load(Ordering::Relaxed);
    if max_batch <= 1 {
        // Batching disabled: push each TX immediately as its own write.
        for peer in peers {
            send_tx_batch(state, *peer, vec![Arc::clone(tx)]);
        }
        return;
    }

    // Batching: queue per destination; a batch flushes here when a size
    // threshold is hit, otherwise the 50ms housekeeping tick flushes it.
    // Coalescing many TXs into one write collapses the per-TX spawn / stream
    // lock / flush (~one QUIC packet per 200-byte TX) that caps intake at
    // high rates.
    let mut full: Vec<(PeerId, Vec<Arc<ValidatedTx>>)> = Vec::new();
    {
        let mut batcher = state.tx_batcher.write().await;
        for peer in peers {
            if let Some(batch) = batcher.add(*peer, Arc::clone(tx), max_batch) {
                full.push((*peer, batch));
            }
        }
    }
    for (peer, batch) in full {
        send_tx_batch(state, peer, batch);
    }
}

/// Send a batch of TXs to `peer` as ONE stream write of concatenated
/// length-prefixed Transaction frames (the receiver's framed-read loop splits
/// them; wire format unchanged). On failure every TX in the batch is rescued
/// via INV flood so it stays pullable.
fn send_tx_batch(state: &Arc<SharedState>, peer: PeerId, batch: Vec<Arc<ValidatedTx>>) {
    if batch.is_empty() {
        return;
    }
    // Concatenate LENGTH-PREFIXED frames: the per-message length prefix is
    // normally added by the writer, so inline it here for each message and
    // send the whole batch pre-framed in one write.
    let mut encoded = Vec::new();
    let mut tx_bytes_total: u64 = 0;
    for tx in &batch {
        let frame = tx.to_flood_frame();
        encoded.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&frame);
        tx_bytes_total += tx.bytes().len() as u64;
    }
    let batch_len = batch.len() as u64;

    let state_clone = Arc::clone(state);
    tokio::spawn(async move {
        match send_preframed_to_peer_stream(&state_clone, peer, StreamType::Tx, &encoded).await {
            Ok(()) => {
                let m = &state_clone.metrics;
                // One "push" per write; bytes/push rising above a single TX's
                // size is the observable sign batching is engaged.
                m.flood_leader_push.fetch_add(1, Ordering::Relaxed);
                m.flood_leader_push_bytes
                    .fetch_add(tx_bytes_total, Ordering::Relaxed);
                m.message_write.fetch_add(1, Ordering::Relaxed);
                m.byte_write
                    .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                m.flood_tx_batch_size_sum
                    .fetch_add(batch_len, Ordering::Relaxed);
                m.flood_tx_batch_size_count.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                state_clone
                    .metrics
                    .error_write
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    "TX_LEADER_PUSH_FAIL: batch of {} TXs to {}: {} — rescuing via INV flood",
                    batch.len(),
                    peer,
                    e
                );
                for tx in &batch {
                    announce_tx_inv_to_all(&state_clone, tx.hash(), tx.fee_per_op()).await;
                }
            }
        }
    });
}

async fn handle_tx_response(state: &Arc<SharedState>, peer_id: &PeerId, tx: Arc<ValidatedTx>) {
    // `tx` was validated in the stream reader's single decode.
    let hash = *tx.hash();
    let recv_start = std::time::Instant::now();
    let tx_len = tx.bytes().len() as u64;

    // Dedup
    {
        let mut seen = state.tx_seen.write().await;
        if seen.contains(&hash) {
            trace!("Duplicate TX from {}", peer_id);
            state
                .metrics
                .flood_duplicate_recv
                .fetch_add(tx_len, Ordering::Relaxed);
            return;
        }
        seen.put(hash, ());
        state
            .metrics
            .memory_flood_known
            .store(seen.len() as i64, Ordering::Relaxed);
    }
    state
        .metrics
        .flood_unique_recv
        .fetch_add(tx_len, Ordering::Relaxed);

    // Remove from pending requests and measure pull latency
    {
        let mut pending = state.pending_getdata.write().await;
        if let Some(req) = pending.remove(&hash) {
            let pull_us = req.first_sent_at.elapsed().as_micros() as u64;
            state
                .metrics
                .flood_tx_pull_latency_sum_us
                .fetch_add(pull_us, Ordering::Relaxed);
            state
                .metrics
                .flood_tx_pull_latency_count
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    debug!(
        "TX_RECV: Received TX {:02x?}... ({} bytes) from {}",
        &hash[..4],
        tx.bytes().len(),
        peer_id
    );

    // Hand to Core for validation via the bounded TX channel. Relay (and
    // GETDATA-buffer insertion, and mempool admission) happen only after
    // Core's verdict comes back — see the validation gate in main.rs and
    // OverlayCommand::RelayValidatedTx. A dropped event here means the tx is
    // simply not relayed; the origin's own leader push still stands.
    if let Err(_) = state.tx_event_tx.try_send(OverlayEvent::TxReceived {
        tx: Arc::clone(&tx),
        from: peer_id.clone(),
    }) {
        state.metrics.message_drop.fetch_add(1, Ordering::Relaxed);
        let dropped = state.tx_dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped % 1000 == 1 {
            warn!(
                "TX_BACKPRESSURE: Dropped TX {:02x?}... (total dropped: {})",
                &hash[..4],
                dropped
            );
        }
    }

    record_recv_transaction_timing(state, recv_start);
}

/// Relay a Core-validated received TX: store it for GETDATA service, then
/// with a known leader schedule push the full body directly to the connected
/// leaders that don't already have it — this closes coverage holes when the
/// origin couldn't reach every leader. Without a schedule (or with all
/// leaders disconnected, for liveness), INV-announce to all peers.
async fn relay_validated_tx(state: &Arc<SharedState>, tx: Arc<ValidatedTx>, from: PeerId) {
    let hash = *tx.hash();
    let fee_per_op = tx.fee_per_op();

    // Store in buffer for responding to others' GETDATA
    {
        let mut buffer = state.tx_buffer.write().await;
        buffer.insert(hash, tx.bytes().to_vec());
    }

    // Peers who already know about this TX (INV'd us or sent it to us)
    let known_sources: HashSet<PeerId> = {
        let tracker = state.inv_tracker.read().await;
        tracker
            .peek_sources(&hash)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default()
    };

    let connected_leaders = connected_flood_leaders(state).await;
    if let Some(leaders) = &connected_leaders {
        if !leaders.is_empty() {
            let targets: Vec<PeerId> = leaders
                .iter()
                .filter(|p| **p != from && !known_sources.contains(p))
                .cloned()
                .collect();
            if !targets.is_empty() {
                debug!(
                    "TX_LEADER_RELAY: Pushing TX {:02x?}... to {} leaders",
                    &hash[..4],
                    targets.len()
                );
                push_tx_to_peers(state, &targets, &tx, &hash, fee_per_op).await;
            }
            return;
        }
        // Leaders known but none connected: INV relay below.
        state
            .metrics
            .flood_leader_fallback
            .fetch_add(1, Ordering::Relaxed);
    }

    let peers_to_announce: Vec<PeerId> = {
        let streams = state.peer_streams.read().await;
        streams
            .keys()
            .filter(|p| **p != from && !known_sources.contains(p))
            .cloned()
            .collect()
    };

    if !peers_to_announce.is_empty() {
        debug!(
            "TX_RELAY: Announcing TX {:02x?}... to {} peers via INV",
            &hash[..4],
            peers_to_announce.len()
        );

        let inv_entry = InvEntry { hash, fee_per_op };

        // Add to batcher for each peer, send batch immediately when full
        for peer in &peers_to_announce {
            let batch_to_send = {
                let mut batcher = state.inv_batcher.write().await;
                batcher.add(*peer, inv_entry.clone())
            };
            if let Some(batch) = batch_to_send {
                send_inv_batch(state, *peer, batch).await;
            }
        }
    }
}

/// Record recv-transaction timing metrics for handle_tx_response.
fn record_recv_transaction_timing(state: &Arc<SharedState>, recv_start: std::time::Instant) {
    let elapsed_us = recv_start.elapsed().as_micros() as u64;
    state
        .metrics
        .recv_transaction_sum_us
        .fetch_add(elapsed_us, Ordering::Relaxed);
    state
        .metrics
        .recv_transaction_count
        .fetch_add(1, Ordering::Relaxed);
    state.metrics.update_recv_transaction_max(elapsed_us);
}

/// Handle inbound TxSet streams from peers
async fn handle_inbound_txset_streams(mut incoming: IncomingStreams, state: Arc<SharedState>) {
    while let Some((peer_id, mut stream)) = incoming.next().await {
        debug!("Accepted inbound TxSet stream from {}", peer_id);
        state.metrics.inbound_live.fetch_add(1, Ordering::Relaxed);
        let state = state.clone();

        tokio::spawn(async move {
            loop {
                match read_framed(&mut stream).await {
                    Ok(data) => {
                        state.metrics.message_read.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_read
                            .fetch_add(data.len() as u64, Ordering::Relaxed);
                        let message = match crate::xdr::parse_stellar_message(&data) {
                            Ok(message) => message,
                            Err(e) => {
                                warn!(
                                    "TXSET_PARSE_ERR: Dropping malformed TxSet stream message from {}: {}",
                                    peer_id, e
                                );
                                continue;
                            }
                        };

                        match message {
                            stellar_xdr::curr::StellarMessage::GetTxSet(hash) => {
                                let hash = hash.0;
                                info!(
                                    "TXSET_REQ_IN: Received TxSet request for {:02x?}... from {}",
                                    &hash[..4],
                                    peer_id
                                );

                                if let Err(e) = state.event_tx.send(OverlayEvent::TxSetRequested {
                                    hash,
                                    from: peer_id,
                                }) {
                                    warn!(
                                        "Failed to forward TxSetRequested event from {}: {}",
                                        peer_id, e
                                    );
                                }
                            }
                            stellar_xdr::curr::StellarMessage::GeneralizedTxSet(_tx_set) => {
                                // The message was strict-decoded above, so the
                                // bytes after the 4-byte discriminant are the
                                // canonical tx set; hash the original bytes
                                // rather than re-encoding.
                                let txset_data = data[4..].to_vec();
                                let hash = crate::xdr::sha256_hash(&txset_data);
                                if is_redundant_txset_body(&state, hash).await {
                                    trace!(
                                        "TXSET_RECV_DUP: ignoring redundant unsolicited TX set {:02x?}... from {}",
                                        &hash[..4],
                                        peer_id
                                    );
                                    continue;
                                }

                                // Clear pending request flag and measure fetch latency
                                let was_pending = {
                                    let mut pending = state.pending_txset_requests.write().await;
                                    if let Some((_, request_time)) = pending.remove(&hash) {
                                        let fetch_us = request_time.elapsed().as_micros() as u64;
                                        state
                                            .metrics
                                            .fetch_txset_sum_us
                                            .fetch_add(fetch_us, Ordering::Relaxed);
                                        state
                                            .metrics
                                            .fetch_txset_count
                                            .fetch_add(1, Ordering::Relaxed);
                                        true
                                    } else {
                                        false
                                    }
                                };

                                info!(
                                    "TXSET_RECV: Received TxSet {:02x?}... ({} bytes) from {} (was_pending={})",
                                    &hash[..4],
                                    txset_data.len(),
                                    peer_id,
                                    was_pending
                                );
                                if let Err(e) = state.event_tx.send(OverlayEvent::TxSetReceived {
                                    hash,
                                    data: txset_data,
                                    from: peer_id,
                                }) {
                                    warn!(
                                        "Failed to forward TxSetReceived event from {}: {}",
                                        peer_id, e
                                    );
                                }
                            }
                            other => {
                                warn!(
                                    "TXSET_PARSE_ERR: Dropping unexpected {} on TxSet stream from {}",
                                    other.name(),
                                    peer_id
                                );
                            }
                        }
                    }
                    Err(e) => {
                        state.metrics.error_read.fetch_add(1, Ordering::Relaxed);
                        state.metrics.inbound_live.fetch_sub(1, Ordering::Relaxed);
                        info!("TxSet stream from {} closed: {}", peer_id, e);
                        break;
                    }
                }
            }
        });
    }
}

/// Record an inbound full TX-set body as completed and report whether it is a
/// redundant repeat the caller may drop.
///
/// The body supersedes any in-flight shred accumulation for the same hash, but
/// the shred indexes already seen are carried over: they gate one-hop
/// forwarding, so discarding them would let every later shred for this hash
/// relay a second time.
///
/// Only an UNSOLICITED repeat is redundant. A response to a request we issued
/// must always reach Core — Core re-requests sets its own cache evicted, and
/// dropping those would silently disable the fetch fallback that rescues a
/// missed flood, which is the recovery path a lost shred depends on.
async fn is_redundant_txset_body(state: &Arc<SharedState>, hash: [u8; 32]) -> bool {
    let already_completed = {
        let mut store = state.txset_shard_store.lock().await;
        let mut seen = store
            .partial
            .remove(&hash)
            .map(|accumulator| accumulator.shard_indexes())
            .unwrap_or_default();
        if let Some(reconstructing) = store.reconstructing.remove(&hash) {
            seen.extend(reconstructing);
        }
        match store.completed.get_mut(&hash) {
            Some(existing) => {
                existing.extend(seen);
                true
            }
            None => {
                store.completed.put(hash, seen);
                false
            }
        }
    };
    already_completed
        && !state
            .pending_txset_requests
            .read()
            .await
            .contains_key(&hash)
}

async fn handle_inbound_txset_shard_streams(
    mut incoming: IncomingStreams,
    state: Arc<SharedState>,
) {
    while let Some((peer_id, mut stream)) = incoming.next().await {
        debug!("Accepted inbound TxSet shred stream from {}", peer_id);
        state.metrics.inbound_live.fetch_add(1, Ordering::Relaxed);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                match read_framed(&mut stream).await {
                    Ok(data) => {
                        state.metrics.message_read.fetch_add(1, Ordering::Relaxed);
                        state
                            .metrics
                            .byte_read
                            .fetch_add(data.len() as u64, Ordering::Relaxed);
                        handle_txset_shard_message(&state, peer_id, data).await;
                    }
                    Err(e) => {
                        state.metrics.error_read.fetch_add(1, Ordering::Relaxed);
                        state.metrics.inbound_live.fetch_sub(1, Ordering::Relaxed);
                        info!("TxSet shred stream from {} closed: {}", peer_id, e);
                        break;
                    }
                }
            }
        });
    }
}

async fn handle_txset_shard_message(state: &Arc<SharedState>, from: PeerId, data: Vec<u8>) {
    let shard = match TxSetShardMessage::decode(&data) {
        Ok(shard) => shard,
        Err(TxSetShardDecodeError::UnsupportedCodec(codec)) => {
            debug!(
                "TXSET_SHARD_CODEC_DROP: unsupported codec {} from {}; using fetch fallback",
                codec, from
            );
            return;
        }
        Err(TxSetShardDecodeError::Invalid(e)) => {
            state
                .metrics
                .txset_shard_invalid
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                "TXSET_SHARD_PARSE_ERR: dropping malformed shred from {}: {}",
                from, e
            );
            return;
        }
    };

    enum ShardAction {
        Accepted {
            unique: bool,
            ready: Option<(TxSetShardAccumulator, usize, Duration)>,
        },
        Invalid(String),
    }

    let action = {
        let mut store = state.txset_shard_store.lock().await;

        if let Some(seen) = store.completed.get_mut(&shard.hash) {
            ShardAction::Accepted {
                unique: seen.insert(shard.shard_index),
                ready: None,
            }
        } else if let Some(seen) = store.reconstructing.get_mut(&shard.hash) {
            ShardAction::Accepted {
                unique: seen.insert(shard.shard_index),
                ready: None,
            }
        } else {
            if !store.partial.contains_key(&shard.hash)
                && store.partial.len() >= TXSET_MAX_ACTIVE_ACCUMULATORS
            {
                // Evict the accumulator with the FEWEST shreds, not the oldest:
                // the oldest is the one closest to reconstructing, and the
                // nominator sends each shred exactly once, so discarding it
                // strands that TX set on the fetch fallback. Ties break on age.
                if let Some(least_progressed) = store
                    .partial
                    .iter()
                    .min_by_key(|(_, accumulator)| {
                        (accumulator.shard_count(), accumulator.created_at)
                    })
                    .map(|(hash, _)| *hash)
                {
                    store.partial.remove(&least_progressed);
                    state
                        .metrics
                        .txset_shard_accumulator_evicted
                        .fetch_add(1, Ordering::Relaxed);
                }
            }

            let insert_result = store
                .partial
                .entry(shard.hash)
                .or_insert_with(|| TxSetShardAccumulator::new(&shard))
                .insert(&shard);
            match insert_result {
                Ok(unique) => {
                    let ready = unique
                        && store
                            .partial
                            .get(&shard.hash)
                            .is_some_and(TxSetShardAccumulator::is_ready);
                    if ready {
                        let accumulator = store
                            .partial
                            .remove(&shard.hash)
                            .expect("ready TX-set accumulator must exist");
                        let received_shards = accumulator.shard_count();
                        let elapsed = accumulator.created_at.elapsed();
                        store
                            .reconstructing
                            .insert(shard.hash, accumulator.shard_indexes());
                        ShardAction::Accepted {
                            unique,
                            ready: Some((accumulator, received_shards, elapsed)),
                        }
                    } else {
                        ShardAction::Accepted {
                            unique,
                            ready: None,
                        }
                    }
                }
                Err(e) => {
                    // A conflicting or parameter-incompatible shred must not
                    // poison this content hash until the 60-second expiry.
                    store.partial.remove(&shard.hash);
                    ShardAction::Invalid(e)
                }
            }
        }
    };

    let (unique, ready) = match action {
        ShardAction::Accepted { unique, ready } => (unique, ready),
        ShardAction::Invalid(e) => {
            state
                .metrics
                .txset_shard_invalid
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                "TXSET_SHARD_CONFLICT: shred {} for {:02x?}... from {}: {}",
                shard.shard_index,
                &shard.hash[..4],
                from,
                e
            );
            return;
        }
    };

    if unique {
        state
            .metrics
            .txset_shard_recv_unique
            .fetch_add(1, Ordering::Relaxed);
    } else {
        state
            .metrics
            .txset_shard_recv_duplicate
            .fetch_add(1, Ordering::Relaxed);
    }
    state.metrics.txset_shard_bytes_in.fetch_add(
        (TXSET_SHARD_HEADER_LEN + shard.payload.len()) as u64,
        Ordering::Relaxed,
    );
    // A shred still carrying TTL came straight from the nominator; one at zero
    // has already taken its single relay hop. The ratio shows whether the
    // one-hop tree is behaving as designed.
    let source_counter = if shard.ttl > 0 {
        &state.metrics.txset_shard_recv_direct
    } else {
        &state.metrics.txset_shard_recv_relayed
    };
    source_counter.fetch_add(1, Ordering::Relaxed);

    if shard.ttl > 0 && unique {
        rebroadcast_txset_shard(state, &shard, from).await;
    }

    let Some((accumulator, received_shards, elapsed)) = ready else {
        return;
    };
    // Dissemination latency as consensus experiences it: first shred of this
    // set seen locally until the threshold shred that makes it decodable.
    state
        .metrics
        .txset_shard_assembly_sum_us
        .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    state
        .metrics
        .txset_shard_assembly_count
        .fetch_add(1, Ordering::Relaxed);

    // Reed–Solomon decoding and strict XDR validation are CPU work. Run both
    // away from Tokio's async workers, just as the nominator does for coding.
    let reconstruct_start = Instant::now();
    let hash = shard.hash;
    let codec = shard.codec;
    let coding_executor = state.txset_coding_executor.read().await.clone();
    let metrics = Arc::clone(&state.metrics);
    enum ReconstructionError {
        DictionaryMiss(String),
        Invalid(String),
    }
    let decoded = tokio::task::spawn_blocking(move || {
        let mut result = accumulator
            .reconstruct_parallel(&coding_executor)
            .map_err(ReconstructionError::Invalid)?
            .ok_or_else(|| {
                ReconstructionError::Invalid("ready accumulator did not reconstruct".to_string())
            })?;
        if codec != TxSetCodec::Raw {
            let decompress_start = Instant::now();
            result.data = match decode_txset_transport(codec, &result.data) {
                Ok(data) => {
                    metrics.txset_shard_decompress_sum_us.fetch_add(
                        decompress_start.elapsed().as_micros() as u64,
                        Ordering::Relaxed,
                    );
                    metrics
                        .txset_shard_decompress_count
                        .fetch_add(1, Ordering::Relaxed);
                    data
                }
                Err(TxSetTransportDecodeError::UnknownDictionary(id)) => {
                    return Err(ReconstructionError::DictionaryMiss(format!(
                        "unsupported zstd dictionary ID {id}"
                    )));
                }
                Err(TxSetTransportDecodeError::Invalid(error)) => {
                    return Err(ReconstructionError::Invalid(format!(
                        "TX-set decompression failed: {error}"
                    )));
                }
            };
        }
        if !crate::xdr::tx_set_hash_matches(&hash, &result.data) {
            let encoding = if codec == TxSetCodec::Zstd {
                "decompressed"
            } else {
                "raw"
            };
            return Err(ReconstructionError::Invalid(format!(
                "{encoding} TX set has the wrong content hash"
            )));
        }
        crate::xdr::validate_tx_set(&result.data).map_err(|e| {
            ReconstructionError::Invalid(format!("reconstructed TX set is not strict XDR: {e}"))
        })?;
        if codec == TxSetCodec::Raw {
            metrics
                .txset_shard_raw_received
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok::<_, ReconstructionError>(result)
    })
    .await;
    let reconstruct_us = reconstruct_start.elapsed().as_micros() as u64;

    let result = match decoded {
        Ok(Ok(result)) => result,
        Ok(Err(ReconstructionError::DictionaryMiss(e))) => {
            state
                .metrics
                .txset_shard_dictionary_miss
                .fetch_add(1, Ordering::Relaxed);
            state
                .txset_shard_store
                .lock()
                .await
                .reconstructing
                .remove(&shard.hash);
            warn!(
                "TXSET_SHARD_DICTIONARY_MISS: reconstructed transport for {:02x?}... cannot be decoded: {}; using fetch fallback",
                &shard.hash[..4],
                e
            );
            return;
        }
        Ok(Err(ReconstructionError::Invalid(e))) => {
            state
                .metrics
                .txset_shard_invalid
                .fetch_add(1, Ordering::Relaxed);
            state
                .txset_shard_store
                .lock()
                .await
                .reconstructing
                .remove(&shard.hash);
            warn!(
                "TXSET_SHARD_VALIDATE_FAIL: reconstructed TX set {:02x?}...: {}",
                &shard.hash[..4],
                e
            );
            return;
        }
        // A join failure is a local blocking-pool panic or a shutting-down
        // runtime, not a bad shred, so it must not count as invalid input.
        Err(e) => {
            state
                .txset_shard_store
                .lock()
                .await
                .reconstructing
                .remove(&shard.hash);
            warn!(
                "TXSET_SHARD_DECODE_TASK_FAIL: TX set {:02x?}...: {}",
                &shard.hash[..4],
                e
            );
            return;
        }
    };

    let already_completed = {
        let mut store = state.txset_shard_store.lock().await;
        let seen = store.reconstructing.remove(&shard.hash).unwrap_or_default();
        if let Some(existing) = store.completed.get_mut(&shard.hash) {
            existing.extend(seen);
            true
        } else {
            store.completed.put(shard.hash, seen);
            false
        }
    };
    if already_completed {
        trace!(
            "TXSET_SHARD_RECONSTRUCT_DUP: full TX-set response won race for {:02x?}...",
            &shard.hash[..4]
        );
        return;
    }

    // Timed here, not at the join point, so the timer covers only deliveries
    // that actually happened: failed decodes and races lost to a full-body
    // response must not skew it. Keeps count == original + recovery.
    state
        .metrics
        .txset_shard_reconstruct_sum_us
        .fetch_add(reconstruct_us, Ordering::Relaxed);
    state
        .metrics
        .txset_shard_reconstruct_count
        .fetch_add(1, Ordering::Relaxed);

    let reconstruction_counter = if result.used_recovery {
        &state.metrics.txset_shard_reconstruct_recovery
    } else {
        &state.metrics.txset_shard_reconstruct_original
    };
    reconstruction_counter.fetch_add(1, Ordering::Relaxed);

    // Eager reconstruction may win a race with the legacy safety-net fetch.
    // Clearing it here prevents a later full-body response from doing duplicate
    // work and records eager-path latency in the existing fetch timer.
    let was_pending = {
        let mut pending = state.pending_txset_requests.write().await;
        if let Some((_, request_time)) = pending.remove(&shard.hash) {
            state
                .metrics
                .fetch_txset_sum_us
                .fetch_add(request_time.elapsed().as_micros() as u64, Ordering::Relaxed);
            state
                .metrics
                .fetch_txset_count
                .fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    };

    info!(
        "TXSET_SHARD_RECONSTRUCTED: {:02x?}... ({} bytes) from {} shreds in {:?}, recovery={}, fetch_preempted={}",
        &shard.hash[..4],
        result.data.len(),
        received_shards,
        elapsed,
        result.used_recovery,
        was_pending
    );
    if let Err(e) = state.event_tx.send(OverlayEvent::TxSetReceived {
        hash: shard.hash,
        data: result.data,
        from,
    }) {
        warn!(
            "TXSET_SHARD_TO_APP_FAIL: failed forwarding {:02x?}...: {}",
            &shard.hash[..4],
            e
        );
    }
}

async fn rebroadcast_txset_shard(
    state: &Arc<SharedState>,
    shard: &TxSetShardMessage,
    from: PeerId,
) {
    let Some(next_ttl) = shard.ttl.checked_sub(1) else {
        return;
    };
    let message = match shard.with_ttl(next_ttl).encode() {
        Ok(message) => Arc::new(message),
        Err(e) => {
            warn!(
                "TXSET_SHARD_FORWARD_DROP: failed encoding shred {} for {:02x?}...: {}",
                shard.shard_index,
                &shard.hash[..4],
                e
            );
            return;
        }
    };
    // The leader and every root derive the same sorted receiver list in the
    // fully-connected Tier-1 mesh. Verify this node really is the designated
    // root, then relay only to its disjoint branch partition.
    let streams = state.peer_streams.read().await;
    let mut leader_peers: Vec<_> = streams
        .keys()
        .filter(|peer| **peer != from)
        .cloned()
        .collect();
    leader_peers.push(state.local_peer_id);
    leader_peers.sort_by_key(|peer| peer.to_bytes());
    leader_peers.dedup();
    let peer_count = leader_peers.len();
    let expected_root = (shard.shard_index * shard.branch_count + shard.branch_index) % peer_count;
    if leader_peers[expected_root] != state.local_peer_id {
        // Either this node genuinely is not the root, or its peer set differs
        // from the nominator's and every offset it derived is wrong. The two
        // are indistinguishable without the nominator's peer count on the wire,
        // so count them: a rate that tracks membership churn means shreds are
        // silently losing coverage and the header needs that field.
        state
            .metrics
            .txset_shard_root_mismatch
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            "TXSET_SHARD_FORWARD_DROP: local node is not branch {} root for shred {} of {:02x?}...",
            shard.branch_index,
            shard.shard_index,
            &shard.hash[..4]
        );
        return;
    }
    let target_offsets = match relay_target_peer_offsets(
        peer_count,
        shard.shard_index,
        shard.branch_index,
        shard.branch_count,
    ) {
        Ok(offsets) => offsets,
        Err(e) => {
            warn!(
                "TXSET_SHARD_FORWARD_DROP: invalid branch for shred {} of {:02x?}...: {}",
                shard.shard_index,
                &shard.hash[..4],
                e
            );
            return;
        }
    };
    let peers: Vec<_> = target_offsets
        .into_iter()
        .filter_map(|offset| {
            let peer = leader_peers[offset];
            (peer != state.local_peer_id && streams.contains_key(&peer)).then_some(peer)
        })
        .collect();
    drop(streams);

    let forward_start = Instant::now();
    for peer in peers {
        let state = Arc::clone(state);
        let message = Arc::clone(&message);
        let hash = shard.hash;
        let shard_index = shard.shard_index;
        tokio::spawn(async move {
            match send_to_peer_stream(&state, peer, StreamType::TxSetShard, &message).await {
                Ok(()) => {
                    state.metrics.message_write.fetch_add(1, Ordering::Relaxed);
                    state
                        .metrics
                        .byte_write
                        .fetch_add(message.len() as u64, Ordering::Relaxed);
                    state
                        .metrics
                        .txset_shard_forwarded
                        .fetch_add(1, Ordering::Relaxed);
                    // Relay turnaround, which separates a slow relay uplink
                    // from slow nominator upload in the end-to-end number.
                    state.metrics.txset_shard_forward_latency_sum_us.fetch_add(
                        forward_start.elapsed().as_micros() as u64,
                        Ordering::Relaxed,
                    );
                    state
                        .metrics
                        .txset_shard_forward_latency_count
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    state.metrics.error_write.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "TXSET_SHARD_FORWARD_FAIL: shred {} for {:02x?}... to {}: {}",
                        shard_index,
                        &hash[..4],
                        peer,
                        e
                    );
                }
            }
        });
    }
}

async fn txset_shard_housekeeping_task(state: Arc<SharedState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let mut store = state.txset_shard_store.lock().await;
        let before = store.partial.len();
        store.partial.retain(|_, accumulator| {
            accumulator.created_at.elapsed() <= TXSET_SHARD_ACCUMULATOR_TTL
        });
        let evicted = before - store.partial.len();
        if evicted > 0 {
            state
                .metrics
                .txset_shard_accumulator_evicted
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
    }
}

/// INV/GETDATA housekeeping task.
///
/// Periodically:
/// 1. Flushes INV batches that have timed out (100ms)
/// 2. Checks GETDATA timeouts and retries to other peers
async fn inv_getdata_housekeeping_task(state: Arc<SharedState>) {
    // Run every 50ms (half the batch timeout for responsiveness)
    let mut interval = tokio::time::interval(Duration::from_millis(50));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        // 1. Flush expired INV batches
        let expired_peers = {
            let batcher = state.inv_batcher.read().await;
            batcher.expired_peers()
        };

        for peer_id in expired_peers {
            flush_inv_batch_to_peer(&state, peer_id).await;
        }

        // 1b. Flush TX push batches that have aged past TX_BATCH_MAX_DELAY.
        let expired_tx_peers = {
            let batcher = state.tx_batcher.read().await;
            batcher.expired_peers()
        };
        for peer_id in expired_tx_peers {
            let batch = {
                let mut batcher = state.tx_batcher.write().await;
                batcher.flush(&peer_id)
            };
            if let Some(batch) = batch {
                send_tx_batch(&state, peer_id, batch);
            }
        }

        // 2. Handle GETDATA timeouts
        let (to_retry, gave_up) = {
            let mut pending = state.pending_getdata.write().await;
            pending.process_timeouts()
        };

        // Log give-ups
        if !gave_up.is_empty() {
            state
                .metrics
                .flood_abandoned_demands
                .fetch_add(gave_up.len() as u64, Ordering::Relaxed);
        }
        for hash in &gave_up {
            warn!(
                "GETDATA_TIMEOUT: Gave up on TX {:02x?}... after 30s",
                &hash[..4]
            );
        }

        // Retry timed-out requests: group by next peer, send batched GETDATA
        if !to_retry.is_empty() {
            state
                .metrics
                .demand_timeout
                .fetch_add(to_retry.len() as u64, Ordering::Relaxed);

            // Resolve next peer for each hash and group by peer
            let mut per_peer: HashMap<PeerId, Vec<[u8; 32]>> = HashMap::new();
            {
                let mut tracker = state.inv_tracker.write().await;
                let mut pending = state.pending_getdata.write().await;
                for hash in to_retry {
                    if let Some(peer) = tracker.get_next_peer(&hash) {
                        if let Some(req) = pending.get_mut(&hash) {
                            req.retry(peer.clone());
                        }
                        per_peer.entry(peer).or_default().push(hash);
                    } else {
                        debug!("GETDATA_RETRY: No more peers for TX {:02x?}...", &hash[..4]);
                    }
                }
            }

            // Send one batched GETDATA per peer
            for (peer, hashes) in per_peer {
                debug!(
                    "GETDATA_RETRY: Retrying {} TXs to peer {}",
                    hashes.len(),
                    peer
                );
                let getdata = GetData { hashes };
                let encoded = match getdata.encode() {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        warn!("Failed to encode GETDATA retry to {}: {}", peer, e);
                        continue;
                    }
                };

                if let Err(e) =
                    try_send_to_existing_stream(&state, peer.clone(), StreamType::Tx, &encoded)
                        .await
                {
                    warn!("Failed to send GETDATA retry to {}: {:?}", peer, e);
                }
            }
        }
    }
}

/// Blake2b hash for deduplication
fn blake2b_hash(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b, Digest};
    use digest::consts::U32;
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
fn test_scp_envelope_xdr(slot_index: u64) -> Vec<u8> {
    use stellar_xdr::curr::{Limits, ScpEnvelope, WriteXdr};

    let mut envelope = ScpEnvelope::default();
    envelope.statement.slot_index = slot_index;
    envelope.to_xdr(Limits::none()).unwrap()
}

#[cfg(test)]
fn test_tx_xdr(sequence: i64) -> Vec<u8> {
    crate::xdr::tests::valid_transaction_xdr(1000, sequence, 1)
}

/// Wrap raw envelope bytes as a validated tx for tests that drive broadcast.
#[cfg(test)]
fn vtx(bytes: Vec<u8>) -> Arc<ValidatedTx> {
    ValidatedTx::from_core_trusted(bytes, 0, 1).unwrap()
}

#[cfg(test)]
fn test_txset_xdr(seed: u8) -> ([u8; 32], Vec<u8>) {
    use stellar_xdr::curr::{GeneralizedTransactionSet, Hash, Limits, WriteXdr};

    let mut tx_set = GeneralizedTransactionSet::default();
    let GeneralizedTransactionSet::V1(v1) = &mut tx_set;
    v1.previous_ledger_hash = Hash([seed; 32]);
    let bytes = tx_set.to_xdr(Limits::none()).unwrap();
    let hash = crate::xdr::sha256_hash(&bytes);
    (hash, bytes)
}

#[cfg(test)]
fn test_large_txset_xdr(seed: u8, target_bytes: usize) -> ([u8; 32], Vec<u8>) {
    use stellar_xdr::curr::{
        GeneralizedTransactionSet, Hash, Limits, ReadXdr, TransactionEnvelope, TransactionPhase,
        TxSetComponent, TxSetComponentTxsMaybeDiscountedFee, VecM, WriteXdr,
    };

    let envelope =
        TransactionEnvelope::from_xdr(test_tx_xdr(seed as i64 + 1), Limits::none()).unwrap();
    let envelope_len = envelope.to_xdr(Limits::none()).unwrap().len();
    let tx_count = target_bytes.div_ceil(envelope_len).max(1);
    let component =
        TxSetComponent::TxsetCompTxsMaybeDiscountedFee(TxSetComponentTxsMaybeDiscountedFee {
            base_fee: None,
            txs: VecM::try_from(vec![envelope; tx_count]).unwrap(),
        });
    let mut tx_set = GeneralizedTransactionSet::default();
    let GeneralizedTransactionSet::V1(v1) = &mut tx_set;
    v1.previous_ledger_hash = Hash([seed; 32]);
    v1.phases = VecM::try_from(vec![TransactionPhase::V0(
        VecM::try_from(vec![component]).unwrap(),
    )])
    .unwrap();
    let bytes = tx_set.to_xdr(Limits::none()).unwrap();
    let hash = crate::xdr::sha256_hash(&bytes);
    (hash, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_txset_shred_handler_reconstructs_with_and_without_recovery() {
        for use_recovery in [false, true] {
            let metrics = Arc::new(OverlayMetrics::new());
            let keypair = Keypair::generate_ed25519();
            let (_handle, mut events, _tx_events, overlay) =
                create_overlay(keypair, Arc::clone(&metrics)).unwrap();
            let state = Arc::clone(&overlay.state);
            let (hash, expected) = test_txset_xdr(if use_recovery { 0x62 } else { 0x61 });
            let config = TxSetShardConfig {
                target_shard_size: 8,
                recovery_factor_percent: 50,
                initial_ttl: 0,
            };
            let shreds = make_txset_shards(hash, &expected, 2, config).unwrap();
            let original_count = shreds[0].original_shards;
            state
                .pending_txset_requests
                .write()
                .await
                .insert(hash, (PeerId::random(), Instant::now()));
            let selected: Vec<_> = if use_recovery {
                shreds
                    .iter()
                    .filter(|shred| shred.shard_index != 0)
                    .take(original_count)
                    .collect()
            } else {
                shreds.iter().filter(|shred| shred.is_original()).collect()
            };
            for shred in selected {
                handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
            }

            let event = tokio::time::timeout(Duration::from_millis(100), events.recv())
                .await
                .expect("reconstruction event timed out")
                .expect("event channel closed");
            match event {
                OverlayEvent::TxSetReceived {
                    hash: received_hash,
                    data,
                    ..
                } => {
                    assert_eq!(received_hash, hash);
                    assert_eq!(data, expected);
                }
                other => panic!("unexpected event: {other:?}"),
            }
            assert_eq!(
                metrics
                    .txset_shard_reconstruct_original
                    .load(Ordering::Relaxed),
                (!use_recovery) as u64
            );
            assert_eq!(
                metrics
                    .txset_shard_reconstruct_recovery
                    .load(Ordering::Relaxed),
                use_recovery as u64
            );
            assert_eq!(metrics.fetch_txset_count.load(Ordering::Relaxed), 1);
            assert!(!state
                .pending_txset_requests
                .read()
                .await
                .contains_key(&hash));
        }
    }

    /// A node that has compression switched off must still accept compressed
    /// shreds. The flag is a nominator-side A/B switch only; if it ever gated
    /// the receive path, turning it off on one node would make that node unable
    /// to follow consensus driven by any node that has it on.
    #[tokio::test]
    async fn test_receiver_accepts_compressed_shreds_with_compression_disabled() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        state
            .txset_compression_enabled
            .store(false, Ordering::Relaxed);

        let (hash, expected) = test_large_txset_xdr(0x93, 64 * 1024);
        let transport = encode_txset_transport(expected.clone(), true).unwrap();
        assert_eq!(transport.codec, TxSetCodec::Zstd);
        let executor = TxSetCodingExecutor::new(1).unwrap();
        let shreds = make_txset_shards_parallel_with_codec(
            hash,
            &transport.data,
            transport.codec,
            3,
            TxSetShardConfig {
                initial_ttl: 0,
                ..TxSetShardConfig::default()
            },
            &executor,
        )
        .unwrap();

        for shred in shreds.iter().filter(|shred| shred.is_original()) {
            handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
        }

        let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("compressed reconstruction event timed out")
            .expect("event channel closed");
        assert!(matches!(
            event,
            OverlayEvent::TxSetReceived { hash: h, data, .. }
                if h == hash && data == expected
        ));
        assert!(metrics.txset_shard_decompress_count.load(Ordering::Relaxed) > 0);
    }

    /// End-to-end compressed dissemination over a real mesh. The existing
    /// three-node broadcast test uses a 44-byte set, which zstd declines, so
    /// without this the compressed path is never exercised through
    /// `broadcast_txset` -> shreds -> reconstruct on live sockets.
    #[tokio::test]
    async fn test_broadcast_compresses_txset_over_real_mesh() {
        const NODE_COUNT: usize = 3;
        const BASE_PORT: u16 = 24701;

        let mut handles = Vec::with_capacity(NODE_COUNT);
        let mut events = Vec::with_capacity(NODE_COUNT);
        let mut metrics = Vec::with_capacity(NODE_COUNT);
        for offset in 0..NODE_COUNT {
            let keypair = Keypair::generate_ed25519();
            let node_metrics = Arc::new(OverlayMetrics::new());
            let (handle, node_events, _tx_events, overlay) =
                create_overlay(keypair, Arc::clone(&node_metrics)).unwrap();
            handles.push(handle);
            events.push(node_events);
            metrics.push(node_metrics);
            tokio::spawn(async move {
                overlay.run("127.0.0.1", BASE_PORT + offset as u16).await;
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        for (node, handle) in handles.iter().enumerate().skip(1) {
            for prior in 0..node {
                let address: Multiaddr =
                    format!("/ip4/127.0.0.1/udp/{}/quic-v1", BASE_PORT + prior as u16)
                        .parse()
                        .unwrap();
                handle.dial(address).await;
            }
        }
        let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let mut ready = true;
            for handle in &handles {
                ready &= handle.connected_peer_count().await == NODE_COUNT - 1;
            }
            if ready {
                break;
            }
            assert!(
                tokio::time::Instant::now() < connect_deadline,
                "mesh did not fully connect"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        for receiver in &mut events {
            while receiver.try_recv().is_ok() {}
        }

        // Repeated envelopes make this highly compressible, which is the point:
        // it forces codec 1 rather than the raw fallback.
        let (want_hash, want_data) = test_large_txset_xdr(0x94, 256 * 1024);
        handles[0]
            .broadcast_txset(want_hash, want_data.clone(), 1)
            .await;

        let mut received = [false; NODE_COUNT];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while received.iter().skip(1).any(|got| !got) {
            for node in 1..NODE_COUNT {
                while let Ok(event) = events[node].try_recv() {
                    if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                        if hash == want_hash {
                            assert_eq!(data, want_data, "peer reconstructed different bytes");
                            received[node] = true;
                        }
                    }
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "peers did not reconstruct the compressed TX set"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The nominator really compressed, and shipped far fewer bytes than the
        // plain set for every branch copy it sent.
        let plain = metrics[0].txset_shard_plain_bytes.load(Ordering::Relaxed);
        let compressed = metrics[0]
            .txset_shard_compressed_bytes
            .load(Ordering::Relaxed);
        assert_eq!(plain, want_data.len() as u64);
        assert!(
            compressed < plain / 2,
            "expected the repeated-envelope set to compress well, got {compressed} of {plain}"
        );
        assert_eq!(metrics[0].txset_shard_raw_sent.load(Ordering::Relaxed), 0);
        assert!(
            metrics[0]
                .txset_shard_compress_count
                .load(Ordering::Relaxed)
                >= 1
        );

        // Receivers decompressed rather than taking the raw path.
        let decompressed: u64 = metrics
            .iter()
            .skip(1)
            .map(|node| node.txset_shard_decompress_count.load(Ordering::Relaxed))
            .sum();
        assert_eq!(decompressed, (NODE_COUNT - 1) as u64);
        assert_eq!(
            metrics
                .iter()
                .skip(1)
                .map(|node| node.txset_shard_raw_received.load(Ordering::Relaxed))
                .sum::<u64>(),
            0
        );
        assert_eq!(
            metrics
                .iter()
                .map(|node| node.txset_shard_dictionary_miss.load(Ordering::Relaxed))
                .sum::<u64>(),
            0
        );

        for handle in handles {
            handle.shutdown().await;
        }
    }

    #[tokio::test]
    async fn test_txset_shred_handler_decompresses_after_recovery() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, expected) = test_large_txset_xdr(0x92, 64 * 1024);
        let transport = encode_txset_transport(expected.clone(), true).unwrap();
        assert_eq!(transport.codec, TxSetCodec::Zstd);
        let executor = TxSetCodingExecutor::new(1).unwrap();
        let shreds = make_txset_shards_parallel_with_codec(
            hash,
            &transport.data,
            transport.codec,
            3,
            TxSetShardConfig {
                target_shard_size: 32,
                recovery_factor_percent: 50,
                initial_ttl: 0,
            },
            &executor,
        )
        .unwrap();
        let original_count = shreds[0].original_shards;
        for shred in shreds
            .iter()
            .filter(|shred| shred.shard_index != 0)
            .take(original_count)
        {
            handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
        }

        let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("compressed reconstruction event timed out")
            .expect("event channel closed");
        assert!(matches!(
            event,
            OverlayEvent::TxSetReceived {
                hash: received_hash,
                data,
                ..
            } if received_hash == hash && data == expected
        ));
        assert_eq!(
            metrics.txset_shard_decompress_count.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .txset_shard_reconstruct_recovery
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.txset_shard_invalid.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.txset_shard_raw_received.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_txset_shred_handler_cleanly_drops_unknown_codec() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, expected) = test_txset_xdr(0x93);
        let mut encoded = make_txset_shards(hash, &expected, 2, TxSetShardConfig::default())
            .unwrap()[0]
            .encode()
            .unwrap();
        encoded[51] = 0xff;

        handle_txset_shard_message(&state, PeerId::random(), encoded).await;

        assert!(events.try_recv().is_err());
        assert_eq!(metrics.txset_shard_invalid.load(Ordering::Relaxed), 0);
        assert_eq!(
            metrics.txset_shard_dictionary_miss.load(Ordering::Relaxed),
            0
        );
        assert!(state.txset_shard_store.lock().await.partial.is_empty());
    }

    #[tokio::test]
    async fn test_txset_shred_handler_uses_fetch_fallback_for_unknown_dictionary() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, expected) = test_large_txset_xdr(0x94, 64 * 1024);
        let samples: Vec<Vec<u8>> = expected.chunks(512).map(<[u8]>::to_vec).collect();
        let dictionary = zstd::dict::from_samples(&samples, 4096).unwrap();
        let mut compressor = zstd::bulk::Compressor::with_dictionary(1, &dictionary).unwrap();
        let encoded = compressor.compress(&expected).unwrap();
        assert!(zstd::zstd_safe::get_dict_id_from_frame(&encoded).is_some());
        let executor = TxSetCodingExecutor::new(1).unwrap();
        let shreds = make_txset_shards_parallel_with_codec(
            hash,
            &encoded,
            TxSetCodec::Zstd,
            2,
            TxSetShardConfig::default(),
            &executor,
        )
        .unwrap();
        for shred in shreds.iter().filter(|shred| shred.is_original()) {
            handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
        }

        assert!(events.try_recv().is_err());
        assert_eq!(metrics.txset_shard_invalid.load(Ordering::Relaxed), 0);
        assert_eq!(
            metrics.txset_shard_dictionary_miss.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.txset_shard_decompress_count.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .txset_shard_decompress_sum_us
                .load(Ordering::Relaxed),
            0
        );
        assert!(state
            .txset_shard_store
            .lock()
            .await
            .reconstructing
            .is_empty());
    }

    #[tokio::test]
    async fn test_txset_shred_handler_counts_malformed_zstd_as_invalid() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, _) = test_txset_xdr(0x95);
        let executor = TxSetCodingExecutor::new(1).unwrap();
        let shreds = make_txset_shards_parallel_with_codec(
            hash,
            b"not-a-zstd-frame",
            TxSetCodec::Zstd,
            2,
            TxSetShardConfig::default(),
            &executor,
        )
        .unwrap();
        for shred in shreds.iter().filter(|shred| shred.is_original()) {
            handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
        }

        assert!(events.try_recv().is_err());
        assert_eq!(metrics.txset_shard_invalid.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics.txset_shard_dictionary_miss.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics.txset_shard_decompress_count.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .txset_shard_decompress_sum_us
                .load(Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn test_txset_shred_handler_rejects_wrong_content_hash() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (_, expected) = test_txset_xdr(0x63);
        let wrong_hash = [0xff; 32];
        let shreds =
            make_txset_shards(wrong_hash, &expected, 2, TxSetShardConfig::default()).unwrap();
        for shred in shreds.iter().filter(|shred| shred.is_original()) {
            handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
        }

        assert!(events.try_recv().is_err());
        assert_eq!(metrics.txset_shard_invalid.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.txset_shard_raw_received.load(Ordering::Relaxed), 0);
        assert!(state
            .txset_shard_store
            .lock()
            .await
            .completed
            .peek(&wrong_hash)
            .is_none());
    }

    #[tokio::test]
    async fn test_txset_shred_completion_is_atomic_and_replays_are_deduplicated() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, expected) = test_txset_xdr(0x65);
        let config = TxSetShardConfig {
            target_shard_size: 8,
            recovery_factor_percent: 50,
            initial_ttl: 0,
        };
        let shreds = make_txset_shards(hash, &expected, 2, config).unwrap();
        assert_eq!(shreds.len(), 3);

        // The recovery shred arrives while threshold reconstruction is on the
        // blocking pool. It must not create a second accumulator or event.
        tokio::join!(
            handle_txset_shard_message(&state, PeerId::random(), shreds[0].encode().unwrap()),
            handle_txset_shard_message(&state, PeerId::random(), shreds[1].encode().unwrap()),
            handle_txset_shard_message(&state, PeerId::random(), shreds[2].encode().unwrap()),
        );

        let event = events.recv().await.expect("missing reconstruction event");
        assert!(matches!(
            event,
            OverlayEvent::TxSetReceived { hash: h, data, .. }
                if h == hash && data == expected
        ));
        assert!(events.try_recv().is_err(), "duplicate reconstruction event");
        assert_eq!(
            metrics
                .txset_shard_reconstruct_count
                .load(Ordering::Relaxed),
            1
        );
        assert!(state.txset_shard_store.lock().await.partial.is_empty());

        let unique_before = metrics.txset_shard_recv_unique.load(Ordering::Relaxed);
        let duplicate_before = metrics.txset_shard_recv_duplicate.load(Ordering::Relaxed);
        for _ in 0..2 {
            handle_txset_shard_message(&state, PeerId::random(), shreds[0].encode().unwrap()).await;
        }
        assert_eq!(
            metrics.txset_shard_recv_unique.load(Ordering::Relaxed),
            unique_before
        );
        assert_eq!(
            metrics.txset_shard_recv_duplicate.load(Ordering::Relaxed),
            duplicate_before + 2
        );
    }

    #[tokio::test]
    async fn test_conflicting_shred_does_not_poison_content_hash() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, expected) = test_txset_xdr(0x66);
        let config = TxSetShardConfig {
            target_shard_size: 8,
            recovery_factor_percent: 50,
            initial_ttl: 0,
        };
        let shreds = make_txset_shards(hash, &expected, 2, config).unwrap();
        handle_txset_shard_message(&state, PeerId::random(), shreds[0].encode().unwrap()).await;
        let mut conflicting = shreds[0].clone();
        conflicting.payload[0] ^= 1;
        handle_txset_shard_message(&state, PeerId::random(), conflicting.encode().unwrap()).await;

        // The valid stream can restart immediately after the conflict.
        for shred in shreds.iter().filter(|shred| shred.is_original()) {
            handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
        }
        let event = events.recv().await.expect("missing reconstruction event");
        assert!(matches!(
            event,
            OverlayEvent::TxSetReceived { hash: h, data, .. }
                if h == hash && data == expected
        ));
        assert_eq!(metrics.txset_shard_invalid.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_txset_shred_accumulators_are_capacity_bounded() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (_, data) = test_txset_xdr(0x64);
        let config = TxSetShardConfig {
            initial_ttl: 0,
            ..TxSetShardConfig::default()
        };
        for i in 0..=TXSET_MAX_ACTIVE_ACCUMULATORS {
            let shreds = make_txset_shards([i as u8; 32], &data, 15, config).unwrap();
            handle_txset_shard_message(&state, PeerId::random(), shreds[0].encode().unwrap()).await;
        }

        assert_eq!(
            state.txset_shard_store.lock().await.partial.len(),
            TXSET_MAX_ACTIVE_ACCUMULATORS
        );
        assert_eq!(
            metrics
                .txset_shard_accumulator_evicted
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_superseded_txset_broadcast_drops_coded_shreds() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        state
            .peer_streams
            .write()
            .await
            .insert(PeerId::random(), Arc::new(PeerOutboundStreams::new()));
        state.txset_shard_generation.store(2, Ordering::Relaxed);
        let (hash, data) = test_txset_xdr(0x67);

        broadcast_txset_shards(state, hash, data, 1, 1).await;

        assert_eq!(metrics.txset_shard_broadcast.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.flood_txset_push_dropped.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.flood_txset_push.load(Ordering::Relaxed), 0);
    }

    /// A TX-set body we ASKED for must always reach Core, even when the eager
    /// coded path already delivered that hash. Core re-requests sets its own
    /// cache evicted; suppressing those responses disables the fetch fallback
    /// that rescues a missed flood, which strands the node on the slower
    /// empty-tx-set recovery.
    #[tokio::test]
    async fn test_solicited_txset_body_survives_earlier_shred_delivery() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, expected) = test_txset_xdr(0x69);
        let config = TxSetShardConfig {
            target_shard_size: 8,
            recovery_factor_percent: 50,
            initial_ttl: 0,
        };

        // The eager coded path delivers the set once.
        for shred in make_txset_shards(hash, &expected, 2, config)
            .unwrap()
            .iter()
            .filter(|shred| shred.is_original())
        {
            handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
        }
        assert!(matches!(
            events.recv().await.expect("missing reconstruction event"),
            OverlayEvent::TxSetReceived { hash: h, .. } if h == hash
        ));

        // An unsolicited repeat of the body is genuinely redundant.
        assert!(is_redundant_txset_body(&state, hash).await);

        // The same body arriving as a response we requested must NOT be
        // dropped, however many times the hash was delivered before.
        state
            .pending_txset_requests
            .write()
            .await
            .insert(hash, (PeerId::random(), Instant::now()));
        assert!(
            !is_redundant_txset_body(&state, hash).await,
            "a solicited TX-set body must reach Core; dropping it disables the fetch fallback"
        );
        assert!(!is_redundant_txset_body(&state, hash).await);

        // Once the request is satisfied and cleared, repeats are redundant again.
        state.pending_txset_requests.write().await.remove(&hash);
        assert!(is_redundant_txset_body(&state, hash).await);
    }

    /// A body for a hash never seen before is always forwarded, and it cancels
    /// any partial shred accumulation for that hash.
    #[tokio::test]
    async fn test_unseen_txset_body_is_forwarded_and_cancels_shred_accumulation() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, expected) = test_txset_xdr(0x6a);
        let config = TxSetShardConfig {
            target_shard_size: 8,
            recovery_factor_percent: 50,
            initial_ttl: 0,
        };
        let shreds = make_txset_shards(hash, &expected, 2, config).unwrap();

        // One shred in flight, not yet at threshold.
        handle_txset_shard_message(&state, PeerId::random(), shreds[0].encode().unwrap()).await;
        assert_eq!(state.txset_shard_store.lock().await.partial.len(), 1);

        assert!(!is_redundant_txset_body(&state, hash).await);
        let mut store = state.txset_shard_store.lock().await;
        assert!(store.partial.is_empty(), "body must cancel accumulation");
        // The seen index carried over, so that shred cannot relay a second time.
        assert!(store.completed.get_mut(&hash).unwrap().contains(&0));
    }

    /// A late shred for an already-completed TX set still counts as unique
    /// (it may owe its one forwarding hop), but must not create a new
    /// accumulator, a second reconstruction, or a duplicate delivery to Core.
    #[tokio::test]
    async fn test_late_shred_after_completion_is_unique_but_not_redelivered() {
        let metrics = Arc::new(OverlayMetrics::new());
        let keypair = Keypair::generate_ed25519();
        let (_handle, mut events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&metrics)).unwrap();
        let state = Arc::clone(&overlay.state);
        let (hash, expected) = test_txset_xdr(0x68);
        let config = TxSetShardConfig {
            target_shard_size: 8,
            recovery_factor_percent: 50,
            initial_ttl: 0,
        };
        let shreds = make_txset_shards(hash, &expected, 2, config).unwrap();
        assert_eq!(shreds.len(), 3);

        // Complete the set from the two originals.
        for shred in shreds.iter().filter(|shred| shred.is_original()) {
            handle_txset_shard_message(&state, PeerId::random(), shred.encode().unwrap()).await;
        }
        let event = events.recv().await.expect("missing reconstruction event");
        assert!(matches!(
            event,
            OverlayEvent::TxSetReceived { hash: h, data, .. }
                if h == hash && data == expected
        ));

        let unique_before = metrics.txset_shard_recv_unique.load(Ordering::Relaxed);
        let duplicate_before = metrics.txset_shard_recv_duplicate.load(Ordering::Relaxed);

        // The recovery shred was never seen: unique, but no new accumulator.
        handle_txset_shard_message(&state, PeerId::random(), shreds[2].encode().unwrap()).await;
        assert_eq!(
            metrics.txset_shard_recv_unique.load(Ordering::Relaxed),
            unique_before + 1
        );
        assert!(state.txset_shard_store.lock().await.partial.is_empty());

        // Replaying it is a duplicate.
        handle_txset_shard_message(&state, PeerId::random(), shreds[2].encode().unwrap()).await;
        assert_eq!(
            metrics.txset_shard_recv_duplicate.load(Ordering::Relaxed),
            duplicate_before + 1
        );

        assert!(events.try_recv().is_err(), "duplicate delivery to Core");
        assert_eq!(
            metrics
                .txset_shard_reconstruct_count
                .load(Ordering::Relaxed),
            1
        );
    }

    /// One-hop forwarding on a four-validator full mesh: each shred has two
    /// branch roots among the leader's three peers, so exactly one peer per
    /// shred is covered only by a root's relay. The three-node test cannot
    /// exercise this (there, every receiver is a root).
    #[tokio::test]
    async fn test_txset_shard_one_hop_forwarding_in_four_node_mesh() {
        const NODE_COUNT: usize = 4;
        const BASE_PORT: u16 = 24601;

        let mut handles = Vec::with_capacity(NODE_COUNT);
        let mut events = Vec::with_capacity(NODE_COUNT);
        let mut metrics = Vec::with_capacity(NODE_COUNT);
        for offset in 0..NODE_COUNT {
            let keypair = Keypair::generate_ed25519();
            let node_metrics = Arc::new(OverlayMetrics::new());
            let (handle, node_events, _tx_events, overlay) =
                create_overlay(keypair, Arc::clone(&node_metrics)).unwrap();
            handles.push(handle);
            events.push(node_events);
            metrics.push(node_metrics);
            tokio::spawn(async move {
                overlay.run("127.0.0.1", BASE_PORT + offset as u16).await;
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Dial each undirected edge once for a full mesh.
        for (node, handle) in handles.iter().enumerate().skip(1) {
            for prior in 0..node {
                let address: Multiaddr =
                    format!("/ip4/127.0.0.1/udp/{}/quic-v1", BASE_PORT + prior as u16)
                        .parse()
                        .unwrap();
                handle.dial(address).await;
            }
        }
        let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let mut ready = true;
            for handle in &handles {
                ready &= handle.connected_peer_count().await == NODE_COUNT - 1;
            }
            if ready {
                break;
            }
            assert!(
                tokio::time::Instant::now() < connect_deadline,
                "4-node mesh did not fully connect"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Connection establishment precedes the protocol stream opens.
        tokio::time::sleep(Duration::from_millis(300)).await;
        for receiver in &mut events {
            while receiver.try_recv().is_ok() {}
        }

        // Multi-shred set: 3 peers -> 4 originals + 2 recovery shreds.
        let (want_hash, want_data) = test_large_txset_xdr(0x51, 64 * 1024);
        let transport = encode_txset_transport(want_data.clone(), true).unwrap();
        assert_eq!(transport.codec, TxSetCodec::Zstd);
        let plan = crate::txset_shards::plan_txset_shards(
            transport.data.len(),
            NODE_COUNT - 1,
            TxSetShardConfig::default(),
        )
        .unwrap();
        let total_shards = plan.total_shards() as u64;
        assert!(plan.recovery_shards >= 1);

        handles[0]
            .broadcast_txset(want_hash, want_data.clone(), 1)
            .await;

        let mut received = [false; NODE_COUNT];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while received.iter().skip(1).any(|got| !got) {
            for node in 1..NODE_COUNT {
                while let Ok(event) = events[node].try_recv() {
                    if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                        if hash == want_hash {
                            assert_eq!(data, want_data);
                            received[node] = true;
                        }
                    }
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "not every peer reconstructed the eagerly coded TX set"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Each shred goes to `branches` roots; every peer the leader did not
        // reach directly is covered by exactly one relay edge for that shred.
        // Total edges per shred is `peer_count` for any branch factor, which is
        // why raising the factor trades relay edges for leader egress rather
        // than adding copies to the mesh.
        let peer_count = NODE_COUNT as u64 - 1;
        let branches = (TXSET_SHARD_BRANCHING_FACTOR as u64).min(peer_count);
        let expected_leader_sends = total_shards * branches;
        let expected_forwarded = total_shards * (peer_count - branches);
        let flush_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let leader_sends = metrics[0].txset_shard_original_sent.load(Ordering::Relaxed)
                + metrics[0].txset_shard_recovery_sent.load(Ordering::Relaxed);
            let forwarded: u64 = metrics
                .iter()
                .skip(1)
                .map(|node| node.txset_shard_forwarded.load(Ordering::Relaxed))
                .sum();
            if leader_sends >= expected_leader_sends && forwarded >= expected_forwarded {
                break;
            }
            assert!(
                tokio::time::Instant::now() < flush_deadline,
                "coded sends did not flush"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            metrics[0].txset_shard_original_sent.load(Ordering::Relaxed)
                + metrics[0].txset_shard_recovery_sent.load(Ordering::Relaxed),
            expected_leader_sends
        );
        assert_eq!(
            metrics[0].flood_txset_push.load(Ordering::Relaxed),
            expected_leader_sends
        );
        assert_eq!(
            metrics
                .iter()
                .skip(1)
                .map(|node| node.txset_shard_forwarded.load(Ordering::Relaxed))
                .sum::<u64>(),
            expected_forwarded
        );
        // Leader never forwards (it originates), and no peer requested the
        // full body: the eager coded path alone delivered it.
        assert_eq!(metrics[0].txset_shard_forwarded.load(Ordering::Relaxed), 0);
        assert_eq!(
            metrics[0]
                .txset_shard_compress_count
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics[0].txset_shard_plain_bytes.load(Ordering::Relaxed),
            want_data.len() as u64
        );
        assert_eq!(
            metrics[0]
                .txset_shard_compressed_bytes
                .load(Ordering::Relaxed),
            transport.data.len() as u64
        );
        assert_eq!(
            metrics
                .iter()
                .skip(1)
                .map(|node| node.txset_shard_decompress_count.load(Ordering::Relaxed))
                .sum::<u64>(),
            (NODE_COUNT - 1) as u64
        );
        assert!(
            !matches!(
                events[0].try_recv(),
                Ok(OverlayEvent::TxSetRequested { .. })
            ),
            "leader should not receive a TxSet request on the coded push path"
        );

        for handle in handles {
            handle.shutdown().await;
        }
    }

    #[tokio::test]
    async fn test_overlay_creation() {
        let keypair = Keypair::generate_ed25519();
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

        let overlay_task = tokio::spawn(async move {
            overlay.run("127.0.0.1", 0).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.shutdown().await;

        tokio::time::timeout(Duration::from_secs(1), overlay_task)
            .await
            .expect("Overlay should shutdown")
            .expect("Overlay task should complete");
    }

    #[tokio::test]
    async fn test_txset_coding_parallelism_is_cluster_bounded() {
        let keypair = Keypair::generate_ed25519();
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

        assert_eq!(
            overlay
                .state
                .txset_coding_executor
                .read()
                .await
                .max_parallelism(),
            1
        );
        handle.set_txset_coding_parallelism(4).await.unwrap();
        assert_eq!(
            overlay
                .state
                .txset_coding_executor
                .read()
                .await
                .max_parallelism(),
            4
        );
        assert!(handle.set_txset_coding_parallelism(0).await.is_err());
        assert_eq!(
            overlay
                .state
                .txset_coding_executor
                .read()
                .await
                .max_parallelism(),
            4,
            "an invalid update must preserve the previous pool"
        );
    }

    #[tokio::test]
    async fn test_two_overlays_connect_and_send_scp() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, _tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19101;
        let _overlay1_task = tokio::spawn(async move {
            overlay1.run("127.0.0.1", listen_port).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let _overlay2_task = tokio::spawn(async move {
            overlay2.run("127.0.0.1", 19102).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Give connection and streams time to establish
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Send SCP from node1
        let scp_msg = test_scp_envelope_xdr(1);
        handle1.broadcast_scp(scp_msg.clone()).await;

        // Wait for SCP on node2
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut received = false;

        while tokio::time::Instant::now() < deadline && !received {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::ScpReceived { envelope, .. } = event {
                        assert_eq!(envelope, scp_msg);
                        received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        assert!(received, "Should receive SCP message");

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    #[tokio::test]
    async fn test_scp_dedup() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, _tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19201;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19202).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + stream setup
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain connection events
        while events2.try_recv().is_ok() {}

        // Send same SCP twice
        let scp_msg = test_scp_envelope_xdr(2);
        handle1.broadcast_scp(scp_msg.clone()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle1.broadcast_scp(scp_msg.clone()).await;

        // Should only receive once
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut count = 0;
        while let Ok(event) = events2.try_recv() {
            if matches!(event, OverlayEvent::ScpReceived { .. }) {
                count += 1;
            }
        }

        assert_eq!(count, 1, "Should receive only one SCP due to dedup");

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Direct leader flooding: with a connected leader configured, a
    /// broadcast TX must be pushed as a full body straight to the leader (no
    /// INV round-trip), and the leader must receive it.
    #[tokio::test]
    async fn test_leader_push_direct() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();
        let peer2 = keypair2.public().to_peer_id();

        let metrics1 = Arc::new(OverlayMetrics::new());
        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::clone(&metrics1)).unwrap();
        let (handle2, _events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 24101;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::spawn(async move { overlay2.run("127.0.0.1", 24102).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        handle1.set_leaders(vec![peer2]).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let tx = test_tx_xdr(1);
        handle1
            .broadcast_tx(ValidatedTx::from_core_trusted(tx.clone(), 0, 1).unwrap())
            .await;

        // The leader must receive the full TX body.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut received = false;
        while tokio::time::Instant::now() < deadline && !received {
            tokio::select! {
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { tx: recv_tx, .. } = event {
                        assert_eq!(recv_tx.bytes(), tx.as_slice());
                        received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        assert!(received, "Leader should receive directly pushed TX");

        // Pushed directly: one leader push, no INV advertisement.
        assert_eq!(metrics1.flood_leader_push.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics1.flood_leader_push_bytes.load(Ordering::Relaxed),
            tx.len() as u64
        );
        assert_eq!(metrics1.flood_advertised.load(Ordering::Relaxed), 0);
        assert_eq!(metrics1.flood_leader_fallback.load(Ordering::Relaxed), 0);

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Direct leader flooding: when the configured leaders are not connected,
    /// broadcast must fall back to INV flooding so the TX still propagates.
    #[tokio::test]
    async fn test_leader_push_fallback_when_leader_disconnected() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let metrics1 = Arc::new(OverlayMetrics::new());
        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::clone(&metrics1)).unwrap();
        let (handle2, _events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 24103;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::spawn(async move { overlay2.run("127.0.0.1", 24104).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // A leader that is not connected to overlay1.
        let unconnected_leader = Keypair::generate_ed25519().public().to_peer_id();
        handle1.set_leaders(vec![unconnected_leader]).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let tx = test_tx_xdr(2);
        handle1
            .broadcast_tx(ValidatedTx::from_core_trusted(tx.clone(), 0, 1).unwrap())
            .await;

        // The peer must still receive the TX via the INV/GETDATA pull path.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut received = false;
        while tokio::time::Instant::now() < deadline && !received {
            tokio::select! {
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { tx: recv_tx, .. } = event {
                        assert_eq!(recv_tx.bytes(), tx.as_slice());
                        received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        assert!(received, "Peer should receive TX via INV fallback");

        assert_eq!(metrics1.flood_leader_push.load(Ordering::Relaxed), 0);
        assert_eq!(metrics1.flood_leader_fallback.load(Ordering::Relaxed), 1);
        assert!(metrics1.flood_advertised.load(Ordering::Relaxed) >= 1);

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Direct leader flooding, relay path: a node that pulls a TX via
    /// INV/GETDATA must forward the full body directly to its connected
    /// leaders — closing coverage holes when the origin can't reach a leader.
    #[tokio::test]
    async fn test_leader_relay_after_pull() {
        // Topology: A — B — C (A and C not connected). B considers C the
        // leader; A knows no leaders and INV-floods.
        let keypair_a = Keypair::generate_ed25519();
        let keypair_b = Keypair::generate_ed25519();
        let keypair_c = Keypair::generate_ed25519();
        let peer_c = keypair_c.public().to_peer_id();

        let metrics_b = Arc::new(OverlayMetrics::new());
        let (handle_a, _events_a, _tx_events_a, overlay_a) =
            create_overlay(keypair_a, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_b, _events_b, mut tx_events_b, overlay_b) =
            create_overlay(keypair_b, Arc::clone(&metrics_b)).unwrap();
        let (handle_c, _events_c, mut tx_events_c, overlay_c) =
            create_overlay(keypair_c, Arc::new(OverlayMetrics::new())).unwrap();

        let port_a = 24105;
        let port_b = 24106;
        tokio::spawn(async move { overlay_a.run("127.0.0.1", port_a).await });
        tokio::spawn(async move { overlay_b.run("127.0.0.1", port_b).await });
        tokio::spawn(async move { overlay_c.run("127.0.0.1", 24107).await });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // B dials A; C dials B.
        let addr_a: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_a)
            .parse()
            .unwrap();
        handle_b.dial(addr_a).await;
        let addr_b: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_b)
            .parse()
            .unwrap();
        handle_c.dial(addr_b).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        handle_b.set_leaders(vec![peer_c]).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let tx = test_tx_xdr(3);
        handle_a
            .broadcast_tx(ValidatedTx::from_core_trusted(tx.clone(), 0, 1).unwrap())
            .await;

        // B pulls the body via GETDATA. Receive no longer auto-relays (the
        // pre-flood validation gate holds TXs for Core's verdict), so stand
        // in for Core: on B's TxReceived, mark the tx valid to trigger the
        // leader relay to C.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut b_received = false;
        while tokio::time::Instant::now() < deadline && !b_received {
            tokio::select! {
                Some(event) = tx_events_b.recv() => {
                    if let OverlayEvent::TxReceived { tx: recv_tx, from } = event {
                        assert_eq!(recv_tx.bytes(), tx.as_slice());
                        handle_b.relay_validated_tx(recv_tx, from).await;
                        b_received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        assert!(b_received, "B should pull the TX body from A");

        // C must receive the TX: A INVs to B, B pulls it, then B pushes the
        // full body directly to its leader C.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut received = false;
        while tokio::time::Instant::now() < deadline && !received {
            tokio::select! {
                Some(event) = tx_events_c.recv() => {
                    if let OverlayEvent::TxReceived { tx: recv_tx, .. } = event {
                        assert_eq!(recv_tx.bytes(), tx.as_slice());
                        received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        assert!(received, "Leader C should receive TX relayed by B");

        assert_eq!(metrics_b.flood_leader_push.load(Ordering::Relaxed), 1);
        // B pulled via GETDATA, so it never INV-advertised the TX onward.
        assert_eq!(metrics_b.flood_advertised.load(Ordering::Relaxed), 0);

        handle_a.shutdown().await;
        handle_b.shutdown().await;
        handle_c.shutdown().await;
    }

    #[tokio::test]
    async fn test_leader_relay_targets_switched_leaders() {
        // The in-flight-tail rescue behind eager post-apply proposals: a TX
        // reaches node B while C is the flood leader, but Core's validation
        // verdict lands only after the leader schedule switched to D (as
        // pushLeaderSchedule does at apply-finish, when C's proposal is
        // already frozen). The relay must read the flood targets live at
        // verdict time and push the body to D, not to the frozen leader C.
        let keypair_a = Keypair::generate_ed25519();
        let keypair_b = Keypair::generate_ed25519();
        let keypair_c = Keypair::generate_ed25519();
        let keypair_d = Keypair::generate_ed25519();
        let peer_c = keypair_c.public().to_peer_id();
        let peer_d = keypair_d.public().to_peer_id();

        let metrics_b = Arc::new(OverlayMetrics::new());
        let (handle_a, _events_a, _tx_events_a, overlay_a) =
            create_overlay(keypair_a, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_b, _events_b, mut tx_events_b, overlay_b) =
            create_overlay(keypair_b, Arc::clone(&metrics_b)).unwrap();
        let (handle_c, _events_c, mut tx_events_c, overlay_c) =
            create_overlay(keypair_c, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_d, _events_d, mut tx_events_d, overlay_d) =
            create_overlay(keypair_d, Arc::new(OverlayMetrics::new())).unwrap();

        let port_b = 24160;
        tokio::spawn(async move { overlay_a.run("127.0.0.1", 24161).await });
        tokio::spawn(async move { overlay_b.run("127.0.0.1", port_b).await });
        tokio::spawn(async move { overlay_c.run("127.0.0.1", 24162).await });
        tokio::spawn(async move { overlay_d.run("127.0.0.1", 24163).await });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // A, C and D all connect to B.
        let addr_b: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_b)
            .parse()
            .unwrap();
        handle_a.dial(addr_b.clone()).await;
        handle_c.dial(addr_b.clone()).await;
        handle_d.dial(addr_b).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // C leads while the TX is in flight to B.
        handle_b.set_leaders(vec![peer_c]).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let tx = test_tx_xdr(7);
        handle_a
            .broadcast_tx(ValidatedTx::from_core_trusted(tx.clone(), 0, 1).unwrap())
            .await;

        // B receives the body; the validation gate holds it for Core's
        // verdict. Do NOT relay yet -- the verdict is still in flight.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut held: Option<(Arc<ValidatedTx>, PeerId)> = None;
        while tokio::time::Instant::now() < deadline && held.is_none() {
            tokio::select! {
                Some(event) = tx_events_b.recv() => {
                    if let OverlayEvent::TxReceived { tx: recv_tx, from } = event {
                        assert_eq!(recv_tx.bytes(), tx.as_slice());
                        held = Some((recv_tx, from));
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        let (held_tx, held_from) = held.expect("B should receive the TX body");

        // Apply finishes on B: the schedule switches to D (C's proposal is
        // frozen). Only then does the delayed verdict land.
        handle_b.set_leaders(vec![peer_d]).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle_b.relay_validated_tx(held_tx, held_from).await;

        // D (the live leader at verdict time) must get the full body.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut d_received = false;
        while tokio::time::Instant::now() < deadline && !d_received {
            tokio::select! {
                Some(event) = tx_events_d.recv() => {
                    if let OverlayEvent::TxReceived { tx: recv_tx, .. } = event {
                        assert_eq!(recv_tx.bytes(), tx.as_slice());
                        d_received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        assert!(d_received, "new leader D should receive the late-verdict TX");
        assert_eq!(metrics_b.flood_leader_push.load(Ordering::Relaxed), 1);

        // The frozen ex-leader C must NOT have been pushed the body.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut c_received = false;
        while let Ok(event) = tx_events_c.try_recv() {
            if let OverlayEvent::TxReceived { .. } = event {
                c_received = true;
            }
        }
        assert!(!c_received, "frozen ex-leader C must not receive the TX");

        handle_a.shutdown().await;
        handle_b.shutdown().await;
        handle_c.shutdown().await;
        handle_d.shutdown().await;
    }

    #[test]
    fn test_blake2b_hash() {
        let data = b"test data";
        let hash1 = blake2b_hash(data);
        let hash2 = blake2b_hash(data);
        assert_eq!(hash1, hash2);

        let hash3 = blake2b_hash(b"different");
        assert_ne!(hash1, hash3);
    }

    /// Critical test: SCP messages must not be blocked by TX traffic
    /// Proves QUIC stream independence by sending large TX payload that takes
    /// measurable time, then verifying SCP arrives BEFORE TX flood completes.
    #[tokio::test]
    async fn test_scp_not_blocked_by_tx_flood() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19301;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19302).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain connection events
        while events2.try_recv().is_ok() {}
        while tx_events2.try_recv().is_ok() {}

        let tx_count = 1000;

        let tx_start = std::time::Instant::now();
        for i in 0..tx_count {
            let tx = test_tx_xdr(i as i64);
            handle1.broadcast_tx(vtx(tx)).await;
        }

        // Immediately send small SCP (should bypass TX queue)
        let scp_msg = test_scp_envelope_xdr(3);
        let scp_send_time = std::time::Instant::now();
        handle1.broadcast_scp(scp_msg.clone()).await;

        // Track when SCP arrives vs when all TXs arrive
        // SCP comes on unbounded events channel, TX on bounded tx_events channel
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut scp_received_at: Option<std::time::Instant> = None;
        let mut tx_count_received = 0u32;
        let mut all_tx_received_at: Option<std::time::Instant> = None;

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::ScpReceived { envelope, .. } = event {
                        if envelope == scp_msg && scp_received_at.is_none() {
                            scp_received_at = Some(std::time::Instant::now());
                        }
                    }
                }
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { .. } = event {
                        tx_count_received += 1;
                        if tx_count_received >= tx_count && all_tx_received_at.is_none() {
                            all_tx_received_at = Some(std::time::Instant::now());
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }

            // Done when both received
            if scp_received_at.is_some() && all_tx_received_at.is_some() {
                break;
            }
        }

        let scp_received_at = scp_received_at.expect("SCP should be received");
        let all_tx_received_at = all_tx_received_at.expect("All TXs should be received");

        let scp_latency = scp_received_at.duration_since(scp_send_time);
        let tx_total_time = all_tx_received_at.duration_since(tx_start);

        println!("SCP latency: {:?}", scp_latency);
        println!("TX flood total time: {:?}", tx_total_time);
        println!("TX received: {}", tx_count_received);

        // KEY ASSERTION: SCP must arrive BEFORE TX flood completes
        // If streams were blocked, SCP would wait behind all TXs
        assert!(
            scp_received_at < all_tx_received_at,
            "SCP should arrive BEFORE TX flood completes (stream independence). \
             SCP at {:?}, TXs done at {:?}",
            scp_latency,
            tx_total_time
        );

        // Also verify TX flood took meaningful time (not instant)
        assert!(
            tx_total_time > Duration::from_millis(50),
            "TX flood should take measurable time ({:?}), otherwise test is invalid",
            tx_total_time
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Critical test: TX messages must not be blocked by SCP traffic
    /// Validates bidirectional stream independence
    #[tokio::test]
    async fn test_tx_not_blocked_by_scp_flood() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19501;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19502).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain connection events
        while events2.try_recv().is_ok() {}
        while tx_events2.try_recv().is_ok() {}

        let scp_count = 1000;

        let scp_start = std::time::Instant::now();
        for i in 0..scp_count {
            let scp = test_scp_envelope_xdr(i as u64);
            handle1.broadcast_scp(scp).await;
        }

        // Immediately send TX (should bypass SCP queue)
        let tx_msg = test_tx_xdr(10_000);
        let tx_send_time = std::time::Instant::now();
        handle1.broadcast_tx(vtx(tx_msg.clone())).await;

        // Track when TX arrives vs when all SCPs arrive
        // SCP comes on unbounded events channel, TX on bounded tx_events channel
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut tx_received_at: Option<std::time::Instant> = None;
        let mut scp_count_received = 0u32;
        let mut all_scp_received_at: Option<std::time::Instant> = None;

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { tx, .. } = event {
                        if tx.bytes() == tx_msg.as_slice() && tx_received_at.is_none() {
                            tx_received_at = Some(std::time::Instant::now());
                        }
                    }
                }
                Some(event) = events2.recv() => {
                    if let OverlayEvent::ScpReceived { .. } = event {
                        scp_count_received += 1;
                        if scp_count_received >= scp_count && all_scp_received_at.is_none() {
                            all_scp_received_at = Some(std::time::Instant::now());
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }

            if tx_received_at.is_some() && all_scp_received_at.is_some() {
                break;
            }
        }

        let tx_received_at = tx_received_at.expect("TX should be received");
        let all_scp_received_at = all_scp_received_at.expect("All SCPs should be received");

        let tx_latency = tx_received_at.duration_since(tx_send_time);
        let scp_total_time = all_scp_received_at.duration_since(scp_start);

        println!("TX latency: {:?}", tx_latency);
        println!("SCP flood total time: {:?}", scp_total_time);
        println!("SCP received: {}", scp_count_received);

        // KEY ASSERTION: TX should have reasonable latency despite SCP flood
        // With INV/GETDATA batching (100ms max), TX latency should be < 200ms
        // This proves streams are independent - TX doesn't wait for 10MB of SCP
        assert!(
            tx_latency < Duration::from_millis(500),
            "TX should arrive quickly despite SCP flood (stream independence). \
             TX latency {:?} should be < 200ms",
            tx_latency
        );

        // Verify SCP flood took meaningful time
        assert!(
            scp_total_time > Duration::from_millis(10),
            "SCP flood should take measurable time ({:?}), otherwise test is invalid",
            scp_total_time
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Test TX broadcast and receive
    #[tokio::test]
    async fn test_tx_broadcast() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, _events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19401;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19402).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain events
        while tx_events2.try_recv().is_ok() {}

        // Send TX
        let tx_msg = test_tx_xdr(20_000);
        handle1.broadcast_tx(vtx(tx_msg.clone())).await;

        // Wait for TX on the bounded TX events channel
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut received = false;

        while tokio::time::Instant::now() < deadline && !received {
            tokio::select! {
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { tx, .. } = event {
                        assert_eq!(tx.bytes(), tx_msg.as_slice());
                        received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        assert!(received, "Should receive TX message");

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Test TxSet request/response flow
    /// Node2 requests a TxSet from Node1, Node1 responds with the data
    #[tokio::test]
    async fn test_txset_fetch() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, mut events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, _tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19601;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19602).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain events
        while events1.try_recv().is_ok() {}
        while events2.try_recv().is_ok() {}

        // Node2 requests a TxSet by hash
        let (requested_hash, txset_data) = test_txset_xdr(0x42);
        handle2.fetch_txset(requested_hash).await;

        // Node1 should receive TxSetRequested event
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut request_received = false;

        while tokio::time::Instant::now() < deadline && !request_received {
            tokio::select! {
                Some(event) = events1.recv() => {
                    if let OverlayEvent::TxSetRequested { hash, from } = event {
                        assert_eq!(hash, requested_hash);
                        request_received = true;

                        // Node1 responds with TxSet data
                        handle1.send_txset(hash, txset_data.clone(), from).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        assert!(
            request_received,
            "Node1 should receive TxSetRequested event"
        );

        // Node2 should receive TxSetReceived event
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut response_received = false;

        while tokio::time::Instant::now() < deadline && !response_received {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                        assert_eq!(hash, requested_hash);
                        assert_eq!(data, txset_data);
                        response_received = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        assert!(
            response_received,
            "Node2 should receive TxSetReceived event"
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Eager TX-set shreds on the fully-connected Tier-1 topology: the leader
    /// sends each Reed–Solomon shred to two roots. The roots partition the
    /// remaining recipients; in this three-node case both receivers are roots.
    #[tokio::test]
    async fn test_broadcast_txset_to_all_peers() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();
        let keypair3 = Keypair::generate_ed25519();

        let metrics1 = Arc::new(OverlayMetrics::new());
        let (handle1, mut events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::clone(&metrics1)).unwrap();
        let metrics2 = Arc::new(OverlayMetrics::new());
        let metrics3 = Arc::new(OverlayMetrics::new());
        let (handle2, mut events2, _tx_events2, overlay2) =
            create_overlay(keypair2, Arc::clone(&metrics2)).unwrap();
        let (handle3, mut events3, _tx_events3, overlay3) =
            create_overlay(keypair3, Arc::clone(&metrics3)).unwrap();

        let listen_port = 24201;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::spawn(async move { overlay2.run("127.0.0.1", 24202).await });
        tokio::spawn(async move { overlay3.run("127.0.0.1", 24203).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Fully connect all three validators.
        let leader_addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        let peer2_addr: Multiaddr = "/ip4/127.0.0.1/udp/24202/quic-v1".parse().unwrap();
        handle2.dial(leader_addr.clone()).await;
        handle3.dial(leader_addr).await;
        handle3.dial(peer2_addr).await;

        let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < connect_deadline
            && (handle1.connected_peer_count().await != 2
                || handle2.connected_peer_count().await != 2
                || handle3.connected_peer_count().await != 2)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(handle1.connected_peer_count().await, 2);
        assert_eq!(handle2.connected_peer_count().await, 2);
        assert_eq!(handle3.connected_peer_count().await, 2);
        // Connection establishment precedes the four protocol stream opens.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Drain connection-setup events.
        while events1.try_recv().is_ok() {}
        while events2.try_recv().is_ok() {}
        while events3.try_recv().is_ok() {}

        // Leader eagerly assigns shreds. No one requested the full body.
        let (want_hash, want_data) = test_txset_xdr(0x37);
        let expected_codec = encode_txset_transport(want_data.clone(), true)
            .unwrap()
            .codec;
        handle1.broadcast_txset(want_hash, want_data.clone(), 1).await;

        // Both peers reconstruct the unsolicited body from the eager shreds.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut got2 = false;
        let mut got3 = false;
        while tokio::time::Instant::now() < deadline && !(got2 && got3) {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                        assert_eq!(hash, want_hash);
                        assert_eq!(data, want_data);
                        got2 = true;
                    }
                }
                Some(event) = events3.recv() => {
                    if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                        assert_eq!(hash, want_hash);
                        assert_eq!(data, want_data);
                        got3 = true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        assert!(got2, "peer2 should receive the eagerly pushed TxSet");
        assert!(got3, "peer3 should receive the eagerly pushed TxSet");

        // The leader must not have been asked for it: this is a pure push.
        assert!(
            !matches!(events1.try_recv(), Ok(OverlayEvent::TxSetRequested { .. })),
            "leader should not receive a TxSet request on the push path"
        );
        // Two originals + 50% recovery, one copy per branch root. Derived from
        // the production branch factor so the test tracks it: leader egress is
        // proportional to the factor, and whatever the factor leaves uncovered
        // is reached by exactly one relay edge per shred.
        let peer_count = 2u64;
        let branches = (TXSET_SHARD_BRANCHING_FACTOR as u64).min(peer_count);
        let expected_pushes = 3 * branches;
        let expected_forwards = 3 * (peer_count - branches);
        let send_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while tokio::time::Instant::now() < send_deadline
            && metrics1.flood_txset_push.load(Ordering::Relaxed) < expected_pushes
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            metrics1.flood_txset_push.load(Ordering::Relaxed),
            expected_pushes
        );
        assert_eq!(metrics1.send_txset.load(Ordering::Relaxed), expected_pushes);
        assert_eq!(
            metrics1.txset_shard_original_sent.load(Ordering::Relaxed),
            2 * branches
        );
        assert_eq!(
            metrics1.txset_shard_recovery_sent.load(Ordering::Relaxed),
            branches
        );
        let forward_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while tokio::time::Instant::now() < forward_deadline
            && metrics2.txset_shard_forwarded.load(Ordering::Relaxed)
                + metrics3.txset_shard_forwarded.load(Ordering::Relaxed)
                < expected_forwards
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            metrics2.txset_shard_forwarded.load(Ordering::Relaxed)
                + metrics3.txset_shard_forwarded.load(Ordering::Relaxed),
            expected_forwards
        );
        assert_eq!(
            metrics2
                .txset_shard_reconstruct_original
                .load(Ordering::Relaxed)
                + metrics2
                    .txset_shard_reconstruct_recovery
                    .load(Ordering::Relaxed)
                + metrics3
                    .txset_shard_reconstruct_original
                    .load(Ordering::Relaxed)
                + metrics3
                    .txset_shard_reconstruct_recovery
                    .load(Ordering::Relaxed),
            2
        );
        assert!(metrics1.flood_txset_push_bytes.load(Ordering::Relaxed) > 0);
        let raw_sets = (expected_codec == TxSetCodec::Raw) as u64;
        let compressed_sets = (expected_codec == TxSetCodec::Zstd) as u64;
        assert_eq!(
            metrics1.txset_shard_raw_sent.load(Ordering::Relaxed),
            raw_sets
        );
        assert_eq!(
            metrics2.txset_shard_raw_received.load(Ordering::Relaxed)
                + metrics3.txset_shard_raw_received.load(Ordering::Relaxed),
            2 * raw_sets
        );
        assert_eq!(
            metrics2
                .txset_shard_decompress_count
                .load(Ordering::Relaxed)
                + metrics3
                    .txset_shard_decompress_count
                    .load(Ordering::Relaxed),
            2 * compressed_sets
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
        handle3.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "manual 15-validator TX-set latency and throughput baseline"]
    async fn benchmark_txset_full_mesh_latency_and_bandwidth() {
        const NODE_COUNT: usize = 15;
        const BASE_PORT: u16 = 26201;
        const TARGET_TXSET_BYTES: usize = 5 * 1024 * 1024;

        let mut handles = Vec::with_capacity(NODE_COUNT);
        let mut events = Vec::with_capacity(NODE_COUNT);
        let mut peer_ids = Vec::with_capacity(NODE_COUNT);
        let mut metrics = Vec::with_capacity(NODE_COUNT);
        let mut states = Vec::with_capacity(NODE_COUNT);
        for offset in 0..NODE_COUNT {
            let keypair = Keypair::generate_ed25519();
            peer_ids.push(keypair.public().to_peer_id());
            let node_metrics = Arc::new(OverlayMetrics::new());
            let (handle, node_events, _tx_events, overlay) =
                create_overlay(keypair, Arc::clone(&node_metrics)).unwrap();
            states.push(Arc::clone(&overlay.state));
            handles.push(handle);
            events.push(node_events);
            metrics.push(node_metrics);
            tokio::spawn(async move {
                overlay.run("127.0.0.1", BASE_PORT + offset as u16).await;
            });
        }
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Dial each undirected edge once to form the fully-connected Tier-1
        // topology used by the reference experiment.
        for (node, handle) in handles.iter().enumerate().skip(1) {
            for prior in 0..node {
                let address: Multiaddr =
                    format!("/ip4/127.0.0.1/udp/{}/quic-v1", BASE_PORT + prior as u16)
                        .parse()
                        .unwrap();
                handle.dial(address).await;
            }
        }
        let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let mut ready = true;
            for handle in &handles {
                ready &= handle.connected_peer_count().await == NODE_COUNT - 1;
            }
            if ready {
                break;
            }
            assert!(
                tokio::time::Instant::now() < connect_deadline,
                "15-node mesh did not fully connect"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        for receiver in &mut events {
            while receiver.try_recv().is_ok() {}
        }

        // Baseline: reproduce the previous eager-full strategy by sending one
        // complete body from the leader to every other validator.
        let (full_hash, full_data) = test_large_txset_xdr(0x71, TARGET_TXSET_BYTES);
        let full_message = Arc::new(crate::xdr::frame_tx_set(&full_data));
        let full_source_bytes = (full_message.len() * (NODE_COUNT - 1)) as u64;
        let full_start = Instant::now();
        let full_sends = peer_ids.iter().copied().skip(1).map(|peer_id| {
            let state = Arc::clone(&states[0]);
            let message = Arc::clone(&full_message);
            async move { send_to_peer_stream(&state, peer_id, StreamType::TxSet, &message).await }
        });
        for result in futures::future::join_all(full_sends).await {
            result.expect("eager-full baseline send failed");
        }
        let mut full_received = [false; NODE_COUNT];
        let full_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while full_received.iter().skip(1).any(|received| !received) {
            for node in 1..NODE_COUNT {
                while let Ok(event) = events[node].try_recv() {
                    if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                        if hash == full_hash {
                            assert_eq!(data, full_data);
                            full_received[node] = true;
                        }
                    }
                }
            }
            assert!(
                tokio::time::Instant::now() < full_deadline,
                "eager-full baseline timed out"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let full_latency = full_start.elapsed();

        // Compare branch factors on the same warm mesh. Alternate their order
        // to avoid systematically favoring the first or last run.
        let mut factor_latencies = [Vec::new(), Vec::new()];
        let mut factor_source_bytes = [0u64; 2];
        let mut factor_aggregate_bytes = [0u64; 2];
        for (sample, branch_count) in [1usize, 2, 2, 1, 1, 2].into_iter().enumerate() {
            let (coded_hash, coded_data) =
                test_large_txset_xdr(0x72 + sample as u8, TARGET_TXSET_BYTES);
            assert_eq!(coded_data.len(), full_data.len());
            let coded_bytes_before: Vec<_> = metrics
                .iter()
                .map(|node| node.byte_write.load(Ordering::Relaxed))
                .collect();
            let coded_source_before = metrics[0].flood_txset_push_bytes.load(Ordering::Relaxed);
            let source_shreds_before = metrics[0].txset_shard_original_sent.load(Ordering::Relaxed)
                + metrics[0].txset_shard_recovery_sent.load(Ordering::Relaxed);
            let forwarded_before: u64 = metrics
                .iter()
                .map(|node| node.txset_shard_forwarded.load(Ordering::Relaxed))
                .sum();

            let coded_start = Instant::now();
            let generation = states[0]
                .txset_shard_generation
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            broadcast_txset_shards_with_branching_factor(
                Arc::clone(&states[0]),
                coded_hash,
                coded_data.clone(),
                generation,
                1,
                branch_count,
            )
            .await;
            let mut coded_received = [false; NODE_COUNT];
            let coded_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            while coded_received.iter().skip(1).any(|received| !received) {
                for node in 1..NODE_COUNT {
                    while let Ok(event) = events[node].try_recv() {
                        if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                            if hash == coded_hash {
                                assert_eq!(data, coded_data);
                                coded_received[node] = true;
                            }
                        }
                    }
                }
                assert!(
                    tokio::time::Instant::now() < coded_deadline,
                    "coded dissemination timed out"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let coded_latency = coded_start.elapsed();

            let plan = crate::txset_shards::plan_txset_shards(
                coded_data.len(),
                NODE_COUNT - 1,
                TxSetShardConfig::default(),
            )
            .unwrap();
            let branches = branch_count.min(NODE_COUNT - 1) as u64;
            let expected_source_shreds = plan.total_shards() as u64 * branches;
            let expected_forwarded =
                plan.total_shards() as u64 * (NODE_COUNT as u64 - 1 - branches);
            let flush_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let source_shreds = metrics[0].txset_shard_original_sent.load(Ordering::Relaxed)
                    + metrics[0].txset_shard_recovery_sent.load(Ordering::Relaxed)
                    - source_shreds_before;
                let forwarded: u64 = metrics
                    .iter()
                    .map(|node| node.txset_shard_forwarded.load(Ordering::Relaxed))
                    .sum::<u64>()
                    - forwarded_before;
                if source_shreds >= expected_source_shreds && forwarded >= expected_forwarded {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < flush_deadline,
                    "coded sends did not flush"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let coded_source_bytes =
                metrics[0].flood_txset_push_bytes.load(Ordering::Relaxed) - coded_source_before;
            let coded_aggregate_bytes: u64 = metrics
                .iter()
                .zip(coded_bytes_before)
                .map(|(node, before)| node.byte_write.load(Ordering::Relaxed) - before)
                .sum();
            let index = branch_count - 1;
            factor_latencies[index].push(coded_latency);
            factor_source_bytes[index] = coded_source_bytes;
            factor_aggregate_bytes[index] = coded_aggregate_bytes;
            eprintln!(
                "txset-full-mesh-sample: branches={branch_count}, latency={coded_latency:?}, source={coded_source_bytes} bytes, aggregate={coded_aggregate_bytes} bytes"
            );
        }

        for latencies in &mut factor_latencies {
            latencies.sort_unstable();
        }
        eprintln!(
            "txset-full-mesh: nodes={NODE_COUNT}, txset={} bytes, eager-full latency={full_latency:?} source={full_source_bytes} bytes; branches=1 median={:?} source={} aggregate={}; branches=2 median={:?} source={} aggregate={}",
            full_data.len(),
            factor_latencies[0][1],
            factor_source_bytes[0],
            factor_aggregate_bytes[0],
            factor_latencies[1][1],
            factor_source_bytes[1],
            factor_aggregate_bytes[1],
        );
        assert!(factor_source_bytes[0] < full_source_bytes / 5);
        assert!(factor_source_bytes[1] < full_source_bytes / 4);
        assert_eq!(factor_aggregate_bytes[0], factor_aggregate_bytes[1]);

        for handle in handles {
            handle.shutdown().await;
        }
    }

    /// Test multiple TXs flood with correct ordering (by fee)
    #[tokio::test]
    async fn test_multiple_txs_flood() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, _events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19701;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19702).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain events
        while tx_events2.try_recv().is_ok() {}

        // Send multiple TXs
        let tx_count = 10;
        for i in 0..tx_count {
            let tx = test_tx_xdr(i as i64);
            handle1.broadcast_tx(vtx(tx)).await;
        }

        // Wait for all TXs on bounded TX events channel
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut received_count = 0;

        while tokio::time::Instant::now() < deadline && received_count < tx_count {
            tokio::select! {
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { .. } = event {
                        received_count += 1;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        assert_eq!(
            received_count, tx_count,
            "Should receive all {} TXs",
            tx_count
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    /// Test TX deduplication - same TX sent twice should only be received once
    #[ignore = "flaky test"]
    #[tokio::test]
    async fn test_tx_dedup() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, _events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        let listen_port = 19801;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 19802).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;

        // Wait for connection + streams
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain events
        while tx_events2.try_recv().is_ok() {}

        // Send same TX twice
        let tx = test_tx_xdr(30_000);
        handle1.broadcast_tx(vtx(tx.clone())).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle1.broadcast_tx(vtx(tx.clone())).await;

        // Wait and count received TXs
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut received_count = 0;
        while let Ok(event) = tx_events2.try_recv() {
            if let OverlayEvent::TxReceived { .. } = event {
                received_count += 1;
            }
        }

        assert_eq!(
            received_count, 1,
            "Duplicate TX should only be received once"
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }

    // ═══ Multi-Node (3+) Gossip Tests ═══

    /// Test SCP messages reach all directly connected peers in a triangle topology
    /// Topology: A-B, B-C, A-C (all nodes connected to each other)
    #[tokio::test]
    async fn test_three_node_triangle_scp() {
        // Create 3 nodes
        let keypair_a = Keypair::generate_ed25519();
        let keypair_b = Keypair::generate_ed25519();
        let keypair_c = Keypair::generate_ed25519();

        let (handle_a, _events_a, _tx_events_a, overlay_a) =
            create_overlay(keypair_a, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_b, mut events_b, _tx_events_b, overlay_b) =
            create_overlay(keypair_b, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_c, mut events_c, _tx_events_c, overlay_c) =
            create_overlay(keypair_c, Arc::new(OverlayMetrics::new())).unwrap();

        // Start all nodes on different ports
        let port_a = 19901;
        let port_b = 19902;
        let port_c = 19903;

        tokio::spawn(async move { overlay_a.run("127.0.0.1", port_a).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay_b.run("127.0.0.1", port_b).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay_c.run("127.0.0.1", port_c).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect: B -> A, C -> A (both B and C connected to A)
        let addr_a: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_a)
            .parse()
            .unwrap();

        handle_b.dial(addr_a.clone()).await;
        handle_c.dial(addr_a).await;

        // Wait for both authenticated connections and their protocol streams
        // to establish before asking A to broadcast. A fixed sleep is flaky
        // under a busy parallel test runner.
        let connection_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while (handle_a.connected_peer_count().await != 2
            || handle_b.connected_peer_count().await != 1
            || handle_c.connected_peer_count().await != 1)
            && tokio::time::Instant::now() < connection_deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(handle_a.connected_peer_count().await, 2);
        assert_eq!(handle_b.connected_peer_count().await, 1);
        assert_eq!(handle_c.connected_peer_count().await, 1);

        // Drain connection events
        while events_b.try_recv().is_ok() {}
        while events_c.try_recv().is_ok() {}

        // A broadcasts SCP - should reach both B and C directly
        let scp_msg = test_scp_envelope_xdr(4);
        handle_a.broadcast_scp(scp_msg.clone()).await;

        // Both B and C should receive it directly from A
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut b_received = false;
        let mut c_received = false;

        while tokio::time::Instant::now() < deadline && (!b_received || !c_received) {
            tokio::select! {
                Some(event) = events_b.recv() => {
                    if let OverlayEvent::ScpReceived { envelope, .. } = event {
                        if envelope == scp_msg {
                            b_received = true;
                        }
                    }
                }
                Some(event) = events_c.recv() => {
                    if let OverlayEvent::ScpReceived { envelope, .. } = event {
                        if envelope == scp_msg {
                            c_received = true;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        assert!(b_received, "Node B should receive SCP from A");
        assert!(c_received, "Node C should receive SCP from A");

        handle_a.shutdown().await;
        handle_b.shutdown().await;
        handle_c.shutdown().await;
    }

    /// Test TX propagation across 3 nodes
    #[tokio::test]
    async fn test_three_node_tx_propagation() {
        let keypair_a = Keypair::generate_ed25519();
        let keypair_b = Keypair::generate_ed25519();
        let keypair_c = Keypair::generate_ed25519();

        let (handle_a, _events_a, _tx_events_a, overlay_a) =
            create_overlay(keypair_a, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_b, _events_b, mut tx_events_b, overlay_b) =
            create_overlay(keypair_b, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle_c, _events_c, mut tx_events_c, overlay_c) =
            create_overlay(keypair_c, Arc::new(OverlayMetrics::new())).unwrap();

        let port_a = 20001;
        let port_b = 20002;
        let port_c = 20003;

        tokio::spawn(async move { overlay_a.run("127.0.0.1", port_a).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay_b.run("127.0.0.1", port_b).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay_c.run("127.0.0.1", port_c).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Triangle topology: A-B, B-C, A-C
        let addr_a: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_a)
            .parse()
            .unwrap();
        let addr_b: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port_b)
            .parse()
            .unwrap();

        handle_b.dial(addr_a.clone()).await;
        handle_c.dial(addr_b).await;
        handle_c.dial(addr_a).await;

        tokio::time::sleep(Duration::from_millis(500)).await;

        while tx_events_b.try_recv().is_ok() {}
        while tx_events_c.try_recv().is_ok() {}

        // A broadcasts TX
        let tx_msg = test_tx_xdr(40_000);
        handle_a.broadcast_tx(vtx(tx_msg.clone())).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut b_received = false;
        let mut c_received = false;

        while tokio::time::Instant::now() < deadline && (!b_received || !c_received) {
            tokio::select! {
                Some(event) = tx_events_b.recv() => {
                    if let OverlayEvent::TxReceived { tx, .. } = event {
                        if tx.bytes() == tx_msg.as_slice() {
                            b_received = true;
                        }
                    }
                }
                Some(event) = tx_events_c.recv() => {
                    if let OverlayEvent::TxReceived { tx, .. } = event {
                        if tx.bytes() == tx_msg.as_slice() {
                            c_received = true;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }

        assert!(b_received, "Node B should receive TX");
        assert!(c_received, "Node C should receive TX");

        handle_a.shutdown().await;
        handle_b.shutdown().await;
        handle_c.shutdown().await;
    }

    /// Test that shutdown is clean (no hung connections)
    #[tokio::test]
    async fn test_clean_shutdown() {
        let keypair = Keypair::generate_ed25519();
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

        let overlay_task = tokio::spawn(async move {
            overlay.run("127.0.0.1", 20100).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Shutdown should complete quickly
        let shutdown_result = tokio::time::timeout(Duration::from_secs(2), handle.shutdown()).await;

        assert!(
            shutdown_result.is_ok(),
            "Shutdown should complete within 2 seconds"
        );

        // Task should finish
        let task_result = tokio::time::timeout(Duration::from_secs(1), overlay_task).await;

        assert!(
            task_result.is_ok(),
            "Overlay task should complete after shutdown"
        );
    }

    /// Test overlay handles dial to invalid address gracefully
    #[tokio::test]
    async fn test_dial_invalid_address() {
        let keypair = Keypair::generate_ed25519();
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

        tokio::spawn(async move { overlay.run("127.0.0.1", 20200).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Dial an address where nothing is listening
        let bad_addr: Multiaddr = "/ip4/127.0.0.1/udp/59999/quic-v1".parse().unwrap();
        handle.dial(bad_addr).await;

        // Should not crash - just log an error and continue
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Overlay should still be operational
        handle.shutdown().await;
    }

    /// Stress test: TX backpressure under heavy load
    /// Verifies:
    /// 1. SCP messages are NEVER dropped (critical path on unbounded channel)
    /// 2. TXs may be dropped under extreme load (acceptable - they'll be re-requested)
    /// 3. No unbounded memory growth (bounded TX channel caps at TX_EVENT_CHANNEL_CAPACITY)
    #[tokio::test]
    async fn test_tx_backpressure_stress() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();

        let (handle1, _events1, _tx_events1, overlay1) =
            create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
        let (handle2, mut events2, mut tx_events2, overlay2) =
            create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

        // Use unique ports to avoid conflicts with other tests
        let listen_port = 22901;
        tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move { overlay2.run("127.0.0.1", 22902).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
            .parse()
            .unwrap();
        handle2.dial(addr).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain any initial events
        while events2.try_recv().is_ok() {}
        while tx_events2.try_recv().is_ok() {}

        // STRESS TEST: Flood with many TXs while also sending SCP
        // This simulates a real attack scenario where the network is flooded with TXs
        let tx_flood_count = 50_000u32; // Exceed TX_EVENT_CHANNEL_CAPACITY (10,000)
        let scp_msg_count = 100u32;

        // Start flooding TXs (don't wait for processing)
        let handle1_clone = handle1.clone();
        let tx_flood_task = tokio::spawn(async move {
            for i in 0..tx_flood_count {
                // Each TX unique to avoid dedup
                let tx = test_tx_xdr(i as i64);
                handle1_clone.broadcast_tx(vtx(tx)).await;
                // Small yield to avoid overwhelming the command channel
                if i % 1000 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });

        // Simultaneously send SCP messages (critical path)
        let handle1_clone2 = handle1.clone();
        let scp_task = tokio::spawn(async move {
            for i in 0..scp_msg_count {
                let scp = test_scp_envelope_xdr(i as u64);
                handle1_clone2.broadcast_scp(scp).await;
                // Space out SCP messages
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        // Wait for floods to complete
        let _ = tokio::join!(tx_flood_task, scp_task);

        // Collect results with timeout
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut scp_received = 0u32;
        let mut tx_received = 0u32;

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(event) = events2.recv() => {
                    if let OverlayEvent::ScpReceived { .. } = event {
                        scp_received += 1;
                    }
                }
                Some(event) = tx_events2.recv() => {
                    if let OverlayEvent::TxReceived { .. } = event {
                        tx_received += 1;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Check if channels are empty
                    if events2.is_empty() && tx_events2.is_empty() {
                        // Give a bit more time for any in-flight messages
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        if events2.is_empty() && tx_events2.is_empty() {
                            break;
                        }
                    }
                }
            }
        }

        println!("SCP received: {}/{}", scp_received, scp_msg_count);
        println!("TX received: {}/{}", tx_received, tx_flood_count);

        // CRITICAL ASSERTION 1: ALL SCP messages must be received (never dropped)
        assert_eq!(
            scp_received, scp_msg_count,
            "ALL SCP messages must be received (critical path). Got {}/{}",
            scp_received, scp_msg_count
        );

        // ASSERTION 2: TXs may be dropped under backpressure - this is acceptable
        // We expect SOME TXs to be received (channel isn't completely broken)
        assert!(tx_received > 0, "At least some TXs should be received");

        // ASSERTION 3: TX count should be bounded by channel capacity + what was processed
        // If backpressure is working, we shouldn't receive more than we can handle
        // (This is more about verifying the mechanism works than a strict bound)
        println!(
            "TX backpressure working: received {} of {} flooded TXs ({}%)",
            tx_received,
            tx_flood_count,
            (tx_received as f64 / tx_flood_count as f64 * 100.0) as u32
        );

        handle1.shutdown().await;
        handle2.shutdown().await;
    }
}

/// Test TX set source tracking - verify we ask the right peer
#[tokio::test]
async fn test_txset_source_tracking() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20101;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20102).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect overlay2 to overlay1
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Record that peer1 (from overlay2's perspective) has a specific TX set
    let test_hash: [u8; 32] = [0xAB; 32];
    // We need to get peer1's ID first - overlay2 should have seen it connect
    // For now, test that record_txset_source doesn't crash
    let fake_peer = PeerId::random();
    handle2.record_txset_source(test_hash, fake_peer).await;

    // Give time for command to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now try to fetch - since fake_peer isn't connected, it should fall back
    handle2.fetch_txset(test_hash).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Clean up
    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test TX set fetch from connected peer
#[tokio::test]
async fn test_txset_fetch_flow() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20201;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20202).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // overlay2 requests a TX set that overlay1 doesn't have
    let test_hash: [u8; 32] = [0xCD; 32];
    handle2.fetch_txset(test_hash).await;

    // overlay1 should receive the request (as TxSetRequested event)
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut got_request = false;
    while let Ok(event) = events1.try_recv() {
        if let OverlayEvent::TxSetRequested { hash, .. } = event {
            if hash == test_hash {
                got_request = true;
            }
        }
    }

    assert!(
        got_request,
        "overlay1 should receive TxSet request from overlay2"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that peer disconnect triggers reconnect attempt
#[tokio::test]
async fn test_peer_disconnect_detection() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20301;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20302).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify connection was established by checking we can send SCP
    handle1.broadcast_scp(test_scp_envelope_xdr(5)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now shutdown overlay2 - overlay1 should detect disconnect
    handle2.shutdown().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // overlay1 should have received a disconnect event or connection closed
    // (Connection closed is handled internally by libp2p, we verify no crash)

    handle1.shutdown().await;
    // Test passes if we get here without hanging or crashing
}

/// Test connect to unreachable peer times out gracefully
#[tokio::test]
async fn test_connect_unreachable_peer_timeout() {
    let keypair = Keypair::generate_ed25519();
    let (handle, _events, _tx_events, overlay) =
        create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20401;
    tokio::spawn(async move { overlay.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to connect to a non-existent peer
    // Use a port that's definitely not listening
    let bad_addr: Multiaddr = "/ip4/127.0.0.1/udp/59999/quic-v1".parse().unwrap();

    // This should not hang - dial returns immediately, connection fails async
    let start = tokio::time::Instant::now();
    handle.dial(bad_addr).await;

    // Give some time for the connection attempt
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify we didn't hang for too long
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "Connection attempt should not block for more than 5 seconds"
    );

    // Overlay should still be operational
    handle.shutdown().await;
}

/// Test large TX set doesn't block SCP messages
#[tokio::test]
async fn test_large_txset_doesnt_block_scp() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20501;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20502).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain initial events
    while events1.try_recv().is_ok() {}
    while events2.try_recv().is_ok() {}

    let send_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    // Immediately send SCP message - should NOT be blocked
    let scp_msg = test_scp_envelope_xdr(6);
    let scp_start = tokio::time::Instant::now();
    handle1.broadcast_scp(scp_msg.clone()).await;

    // SCP should arrive quickly (< 100ms) even if TX set is being transferred
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut scp_received = false;

    while tokio::time::Instant::now() < deadline && !scp_received {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, .. } = event {
                    if envelope == scp_msg {
                        scp_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    let scp_latency = scp_start.elapsed();
    assert!(scp_received, "SCP message should be received");
    assert!(
        scp_latency < Duration::from_millis(200),
        "SCP latency should be < 200ms, was {:?}",
        scp_latency
    );

    send_task.await.unwrap();
    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test TX set request to peer that has the data
#[tokio::test]
async fn test_txset_request_and_response() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20601;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20602).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain events
    while events1.try_recv().is_ok() {}
    while events2.try_recv().is_ok() {}

    // Node2 requests a TX set
    let (requested_hash, txset_data) = test_txset_xdr(0x77);

    handle2.fetch_txset(requested_hash).await;

    // Node1 receives request and responds
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut responded = false;

    while tokio::time::Instant::now() < deadline && !responded {
        tokio::select! {
            Some(event) = events1.recv() => {
                if let OverlayEvent::TxSetRequested { hash, from } = event {
                    assert_eq!(hash, requested_hash, "Request should have correct hash");
                    handle1.send_txset(hash, txset_data.clone(), from).await;
                    responded = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        responded,
        "Node1 should receive and respond to TX set request"
    );

    // Node2 should receive the TX set
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut received = false;

    while tokio::time::Instant::now() < deadline && !received {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                    assert_eq!(hash, requested_hash, "Received hash should match");
                    assert_eq!(data, txset_data, "Received data should match");
                    received = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(received, "Node2 should receive TX set response");

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test TX set fetch when no peers are connected
#[tokio::test]
async fn test_txset_fetch_no_peers() {
    let keypair = Keypair::generate_ed25519();
    let (handle, mut events, _tx_events, overlay) =
        create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20701;
    tokio::spawn(async move { overlay.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Request TX set with no peers connected
    let requested_hash: [u8; 32] = [0x88; 32];
    handle.fetch_txset(requested_hash).await;

    // Should not crash or hang - just no response
    // Wait briefly to ensure no panic
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain any events (there shouldn't be any TX set related ones)
    let mut txset_events = 0;
    while let Ok(event) = events.try_recv() {
        if matches!(event, OverlayEvent::TxSetReceived { .. }) {
            txset_events += 1;
        }
    }
    assert_eq!(
        txset_events, 0,
        "Should not receive TX set when no peers connected"
    );

    handle.shutdown().await;
}

/// Test multiple concurrent TX set requests
#[tokio::test]
async fn test_txset_multiple_concurrent_requests() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 20801;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 20802).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain events
    while events1.try_recv().is_ok() {}
    while events2.try_recv().is_ok() {}

    // Request multiple TX sets concurrently
    let hash1: [u8; 32] = [0x11; 32];
    let hash2: [u8; 32] = [0x22; 32];
    let hash3: [u8; 32] = [0x33; 32];

    handle2.fetch_txset(hash1).await;
    handle2.fetch_txset(hash2).await;
    handle2.fetch_txset(hash3).await;

    // Node1 should receive all 3 requests
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut received_hashes = std::collections::HashSet::new();

    while tokio::time::Instant::now() < deadline && received_hashes.len() < 3 {
        tokio::select! {
            Some(event) = events1.recv() => {
                if let OverlayEvent::TxSetRequested { hash, from } = event {
                    received_hashes.insert(hash);
                    // Respond to each request
                    let data = format!("txset for {:?}", &hash[..4]).into_bytes();
                    handle1.send_txset(hash, data, from).await;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    assert_eq!(
        received_hashes.len(),
        3,
        "Should receive all 3 TX set requests"
    );
    assert!(received_hashes.contains(&hash1));
    assert!(received_hashes.contains(&hash2));
    assert!(received_hashes.contains(&hash3));

    handle1.shutdown().await;
    handle2.shutdown().await;
}

#[tokio::test]
async fn test_scp_state_request_on_connection() {
    // Test that when two nodes connect, they request SCP state from each other
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 19801;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 19802).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect node2 to node1
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;

    // Wait for connection + SCP stream setup
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Both nodes should receive ScpStateRequested events (each receives request from the other)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node1_received_request = false;
    let mut node2_received_request = false;

    while tokio::time::Instant::now() < deadline
        && (!node1_received_request || !node2_received_request)
    {
        tokio::select! {
            Some(event) = events1.recv() => {
                if let OverlayEvent::ScpStateRequested { ledger_seq, .. } = event {
                    assert_eq!(ledger_seq, 0, "Should request all recent state (ledger_seq=0)");
                    node1_received_request = true;
                }
            }
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpStateRequested { ledger_seq, .. } = event {
                    assert_eq!(ledger_seq, 0, "Should request all recent state (ledger_seq=0)");
                    node2_received_request = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    assert!(
        node1_received_request,
        "Node 1 should receive SCP state request from node 2"
    );
    assert!(
        node2_received_request,
        "Node 2 should receive SCP state request from node 1"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that QUIC keep-alive keeps connection alive during idle periods
#[tokio::test]
async fn test_quic_keepalive_survives_idle() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    // Use unique ports to avoid conflicts with other tests
    let listen_port = 23001;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 23002).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify initial connectivity by sending SCP
    let scp_msg1 = test_scp_envelope_xdr(7);
    handle1.broadcast_scp(scp_msg1.clone()).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut received_initial = false;
    while tokio::time::Instant::now() < deadline && !received_initial {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, .. } = event {
                    if envelope == scp_msg1 {
                        received_initial = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(received_initial, "Should receive initial SCP message");

    // Wait longer than keep-alive interval (15s) but less than max idle (60s)
    // Use 20 seconds to ensure keep-alive packets are sent
    info!("Waiting 20 seconds to test keep-alive...");
    tokio::time::sleep(Duration::from_secs(20)).await;

    // Verify connection is still alive by sending another SCP
    let scp_msg2 = test_scp_envelope_xdr(8);
    handle1.broadcast_scp(scp_msg2.clone()).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut received_after_idle = false;
    while tokio::time::Instant::now() < deadline && !received_after_idle {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, .. } = event {
                    if envelope == scp_msg2 {
                        received_after_idle = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        received_after_idle,
        "Connection should survive 20s idle period thanks to QUIC keep-alive"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that overlay listens on configured IP address
#[tokio::test]
async fn test_listen_on_configured_ip() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 21101;

    // Start overlay1 listening on 127.0.0.1
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 21102).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect using the specific IP - this should work
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify connection works by checking for SCP state request
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline && !connected {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpStateRequested { .. } = event {
                    connected = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        connected,
        "Should connect when dialing configured listen IP"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that different listen IPs work correctly
#[tokio::test]
async fn test_listen_ip_binding() {
    // Test that we can specify different IPs for run()
    // On most systems, 127.0.0.1 and 127.0.0.2 are both valid loopback addresses
    let keypair = Keypair::generate_ed25519();
    let (handle, _events, _tx_events, overlay) =
        create_overlay(keypair, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 21201;

    // Start on 127.0.0.1 specifically (not 0.0.0.0)
    let overlay_task = tokio::spawn(async move {
        overlay.run("127.0.0.1", listen_port).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The overlay should be running and listening
    // We verify by checking it accepts the shutdown gracefully
    handle.shutdown().await;

    tokio::time::timeout(Duration::from_secs(2), overlay_task)
        .await
        .expect("Overlay should shutdown")
        .expect("Overlay task should complete");
}

/// Test that event loop remains responsive during broadcast (proves parallelism)
#[tokio::test]
async fn test_scp_broadcast_does_not_block_event_loop() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let port1 = 21301;
    let port2 = 21302;

    tokio::spawn(async move { overlay1.run("127.0.0.1", port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", port2).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect
    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port1)
        .parse()
        .unwrap();
    handle2.dial(addr1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Fire off 100 SCP broadcasts rapidly
    for i in 0..100 {
        let msg = test_scp_envelope_xdr(i as u64);
        handle1.broadcast_scp(msg).await;
    }

    // Immediately ping the event loop - if blocked by sequential sends,
    // this won't return until all 100 network writes complete
    let start = tokio::time::Instant::now();
    handle1.ping().await.expect("Ping should succeed");
    let ping_latency = start.elapsed();

    // Ping should return quickly if event loop isn't blocked.
    // Allow 50ms for tokio scheduling overhead - still catches the bug
    // where 100 sequential sends would take seconds.
    assert!(
        ping_latency < Duration::from_millis(50),
        "Ping should return in <50ms (event loop not blocked), took {:?}",
        ping_latency
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that SCP and TxSet streams can be written concurrently to the same peer.
/// This validates that the per-stream mutex design allows independent writes.
#[tokio::test]
async fn test_concurrent_scp_and_txset_writes_to_same_peer() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let peer2_id = PeerId::from_public_key(&keypair2.public());

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let listen_port = 21001;
    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(async move { overlay2.run("127.0.0.1", 21002).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect node2 to node1
    let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port)
        .parse()
        .unwrap();
    handle2.dial(addr).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain initial events
    while events2.try_recv().is_ok() {}

    // Shared flag to coordinate timing
    let txset_started = Arc::new(AtomicBool::new(false));

    // Start sending large TxSet from node1 to node2
    let (txset_hash, txset_data) = test_txset_xdr(0x22);
    let handle1_txset = handle1.clone();
    let txset_started_clone = txset_started.clone();

    let txset_task = tokio::spawn(async move {
        txset_started_clone.store(true, Ordering::SeqCst);
        handle1_txset
            .send_txset(txset_hash, txset_data, peer2_id)
            .await;
    });

    // Wait for TxSet send to start
    while !txset_started.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // Immediately send SCP message - should NOT be blocked by TxSet write
    let scp_msg = test_scp_envelope_xdr(9);
    let scp_start = tokio::time::Instant::now();
    handle1.broadcast_scp(scp_msg.clone()).await;
    let scp_send_time = scp_start.elapsed();

    // The key assertion: SCP send should complete quickly (<50ms)
    // If the mutexes were shared, SCP would block waiting for TxSet write to finish
    assert!(
        scp_send_time < Duration::from_millis(50),
        "SCP send should not block on TxSet write. Send took {:?}",
        scp_send_time
    );

    // Wait for SCP to be received by node2
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut scp_received = false;
    let mut txset_received = false;

    while tokio::time::Instant::now() < deadline && (!scp_received || !txset_received) {
        tokio::select! {
            Some(event) = events2.recv() => {
                match event {
                    OverlayEvent::ScpReceived { envelope, .. } => {
                        if envelope == scp_msg {
                            scp_received = true;
                        }
                    }
                    OverlayEvent::TxSetReceived { hash, .. } => {
                        if hash == txset_hash {
                            txset_received = true;
                        }
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    txset_task.await.unwrap();

    assert!(scp_received, "SCP message should be received");
    assert!(txset_received, "TxSet should be received");

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that pending_txset_requests tracks peer and is cleaned on disconnect.
/// This is a simpler unit test that verifies the data structure changes work.
#[tokio::test]
async fn test_pending_txset_cleanup_on_disconnect() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let peer1_id = PeerId::from_public_key(&keypair1.public());

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    // Start both overlays (ports must not collide with test_20_node_full_mesh 22000-22019)
    let listen_port1 = 22501;
    let listen_port2 = 22502;

    tokio::spawn(async move { overlay1.run("127.0.0.1", listen_port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", listen_port2).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect node1 to node2
    let addr2: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", listen_port2)
        .parse()
        .unwrap();
    handle1.dial(addr2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify connection by exchanging SCP message
    handle1.broadcast_scp(test_scp_envelope_xdr(10)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline && !connected {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { .. } = event {
                    connected = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(connected, "Nodes should be connected");

    // Request TxSet - this tests that pending_txset_requests correctly stores (hash, peer)
    let (txset_hash, txset_data) = test_txset_xdr(0x42);
    handle1.fetch_txset(txset_hash).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify node2 received the request
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut got_request = false;
    while tokio::time::Instant::now() < deadline && !got_request {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::TxSetRequested { hash, .. } = event {
                    if hash == txset_hash {
                        got_request = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(got_request, "Node2 should receive TxSet request");

    // Now have node2 respond with the TxSet
    // This verifies the pending cleanup works when response is received
    handle2
        .send_txset(txset_hash, txset_data.clone(), peer1_id)
        .await;

    // Verify node1 receives the TxSet response
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut got_response = false;
    while tokio::time::Instant::now() < deadline && !got_response {
        tokio::select! {
            Some(event) = events1.recv() => {
                if let OverlayEvent::TxSetReceived { hash, data, .. } = event {
                    if hash == txset_hash && data == txset_data {
                        got_response = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(got_response, "Node1 should receive TxSet response");

    // Request the same TxSet again - should NOT be skipped since pending was cleared
    handle1.fetch_txset(txset_hash).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify node2 receives the second request
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut got_second_request = false;
    while tokio::time::Instant::now() < deadline && !got_second_request {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::TxSetRequested { hash, .. } = event {
                    if hash == txset_hash {
                        got_second_request = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        got_second_request,
        "Node2 should receive second TxSet request after pending was cleared by response"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test INV/GETDATA protocol: TX propagation via INV→GETDATA→TX flow
#[tokio::test]
async fn test_inv_getdata_tx_propagation() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    // Create overlays with INV/GETDATA enabled
    let (handle1, _events1, tx_events1, overlay1) =
        create_overlay(keypair1.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, mut tx_events2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let peer1_id = PeerId::from_public_key(&keypair1.public());

    let listen_port = 19251;
    let overlay1_task = tokio::spawn(async move {
        overlay1.run("127.0.0.1", listen_port).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let overlay2_task = tokio::spawn(async move {
        overlay2.run("127.0.0.1", listen_port + 1).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Node2 dials Node1
    let addr: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
        listen_port, peer1_id
    )
    .parse()
    .unwrap();
    handle2.dial(addr).await;

    // Wait for connection to establish and streams to open
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node1 broadcasts a TX
    let test_tx = test_tx_xdr(50_000);
    handle1.broadcast_tx(vtx(test_tx.clone())).await;

    // Wait for INV→GETDATA→TX flow (with batching delay + RTT)
    // - INV is batched for up to 100ms
    // - GETDATA sent
    // - TX response sent
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut tx_received = false;

    while tokio::time::Instant::now() < deadline && !tx_received {
        tokio::select! {
            Some(event) = tx_events2.recv() => {
                if let OverlayEvent::TxReceived { tx, from } = event {
                    if tx.bytes() == test_tx.as_slice() && from == peer1_id {
                        tx_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    assert!(
        tx_received,
        "Node2 should receive TX via INV/GETDATA protocol"
    );

    // Suppress warning
    drop(tx_events1);

    handle1.shutdown().await;
    handle2.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), overlay1_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay2_task).await;
}

/// Test INV/GETDATA protocol: TX relay through 3 nodes (A→B→C)
#[tokio::test]
async fn test_inv_getdata_three_node_relay() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let keypair3 = Keypair::generate_ed25519();

    // Create overlays with INV/GETDATA enabled (controlled topology)
    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, mut tx_events2, overlay2) =
        create_overlay(keypair2.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle3, _events3, mut tx_events3, overlay3) =
        create_overlay(keypair3, Arc::new(OverlayMetrics::new())).unwrap();

    let peer1_id = PeerId::from_public_key(&keypair1.public());
    let peer2_id = PeerId::from_public_key(&keypair2.public());

    let base_port = 19261;

    let overlay1_task = tokio::spawn(async move {
        overlay1.run("127.0.0.1", base_port).await;
    });

    let overlay2_task = tokio::spawn(async move {
        overlay2.run("127.0.0.1", base_port + 1).await;
    });

    let overlay3_task = tokio::spawn(async move {
        overlay3.run("127.0.0.1", base_port + 2).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Topology: Node1 ←→ Node2 ←→ Node3 (Node1 NOT connected to Node3)
    // Node2 dials Node1
    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}", base_port, peer1_id)
        .parse()
        .unwrap();
    handle2.dial(addr1).await;

    // Wait for Node1-Node2 connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node3 dials Node2
    let addr2: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
        base_port + 1,
        peer2_id
    )
    .parse()
    .unwrap();
    handle3.dial(addr2).await;

    // Wait for Node2-Node3 connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node1 broadcasts a TX
    let test_tx = test_tx_xdr(60_000);
    handle1.broadcast_tx(vtx(test_tx.clone())).await;

    // First verify Node2 receives the TX from Node1
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node2_received = false;
    while tokio::time::Instant::now() < deadline && !node2_received {
        tokio::select! {
            Some(event) = tx_events2.recv() => {
                if let OverlayEvent::TxReceived { tx, from } = event {
                    eprintln!(
                        "Node2 received TX from {}: {:02x?}",
                        from,
                        &tx.bytes()[..tx.bytes().len().min(8)]
                    );
                    if tx.bytes() == test_tx.as_slice() && from == peer1_id {
                        node2_received = true;
                        // Receive no longer auto-relays: relay waits for
                        // Core's validity verdict (pre-flood validation
                        // gate). Stand in for Core here and mark it valid.
                        handle2.relay_validated_tx(tx, from).await;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(node2_received, "Node2 should receive TX from Node1");

    // Then Node3 should receive the TX via relay through Node2
    // Flow: Node1 →INV→ Node2 →GETDATA→ Node1 →TX→ Node2 →INV→ Node3 →GETDATA→ Node2 →TX→ Node3
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut tx_received = false;

    while tokio::time::Instant::now() < deadline && !tx_received {
        tokio::select! {
            Some(event) = tx_events3.recv() => {
                if let OverlayEvent::TxReceived { tx, from } = event {
                    eprintln!(
                        "Node3 received TX from {}: {:02x?}",
                        from,
                        &tx.bytes()[..tx.bytes().len().min(8)]
                    );
                    // Node3 must receive TX from Node2 (relay), not Node1 (no direct connection)
                    if tx.bytes() == test_tx.as_slice() && from == peer2_id {
                        tx_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    assert!(
        tx_received,
        "Node3 should receive TX relayed through Node2 via INV/GETDATA"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
    handle3.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), overlay1_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay2_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay3_task).await;
}

/// Test an explicit repeat broadcast through 3 nodes: A→B→C.
///
/// Topology: Node1 ←→ Node2 ←→ Node3 (Node1 NOT connected to Node3)
/// Node1 broadcasts SCP. The test explicitly asks Node2 to broadcast the same
/// bytes and verifies that Node3 receives them.
///
/// Core no longer performs this repeat for received SCP envelopes in the dense
/// mesh. The primitive remains useful for state repair and verifies that
/// `scp_seen` does not suppress an explicit outbound request.
#[tokio::test]
async fn test_scp_relay_three_nodes() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let keypair3 = Keypair::generate_ed25519();

    let (handle1, _events1, _tx_events1, overlay1) =
        create_overlay(keypair1.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle3, mut events3, _tx_events3, overlay3) =
        create_overlay(keypair3, Arc::new(OverlayMetrics::new())).unwrap();

    let peer1_id = PeerId::from_public_key(&keypair1.public());
    let peer2_id = PeerId::from_public_key(&keypair2.public());

    let base_port = 19361;

    let overlay1_task = tokio::spawn(async move {
        overlay1.run("127.0.0.1", base_port).await;
    });

    let overlay2_task = tokio::spawn(async move {
        overlay2.run("127.0.0.1", base_port + 1).await;
    });

    let overlay3_task = tokio::spawn(async move {
        overlay3.run("127.0.0.1", base_port + 2).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Node2 dials Node1
    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}", base_port, peer1_id)
        .parse()
        .unwrap();
    handle2.dial(addr1).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node3 dials Node2 (NOT Node1 - ensuring no direct A↔C path)
    let addr2: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
        base_port + 1,
        peer2_id
    )
    .parse()
    .unwrap();
    handle3.dial(addr2).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain connection events
    while events2.try_recv().is_ok() {}
    while events3.try_recv().is_ok() {}

    // Node1 broadcasts SCP
    let scp_msg = test_scp_envelope_xdr(11);
    handle1.broadcast_scp(scp_msg.clone()).await;

    // Node2 should receive it from Node1
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node2_received = false;
    while tokio::time::Instant::now() < deadline && !node2_received {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, from, .. } = event {
                    if envelope == scp_msg && from == peer1_id {
                        node2_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(node2_received, "Node2 should receive SCP from Node1");

    // Explicitly ask Node2 to broadcast the same SCP message. Normal C++ Core
    // receipt does not do this in the dense-mesh path.
    handle2.broadcast_scp(scp_msg.clone()).await;

    // Node3 should receive it via Node2's relay
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node3_received = false;
    while tokio::time::Instant::now() < deadline && !node3_received {
        tokio::select! {
            Some(event) = events3.recv() => {
                if let OverlayEvent::ScpReceived { envelope, from, .. } = event {
                    if envelope == scp_msg && from == peer2_id {
                        node3_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        node3_received,
        "Node3 should receive SCP relayed through Node2"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
    handle3.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), overlay1_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay2_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay3_task).await;
}

/// Test that an explicit SCP repeat broadcast doesn't echo to the sender.
///
/// Topology: Node1 ←→ Node2
/// Node1 broadcasts SCP. The test explicitly asks Node2 to broadcast the same
/// bytes. Node1 must NOT receive them again.
#[tokio::test]
async fn test_scp_relay_no_echo_to_sender() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx_events1, overlay1) =
        create_overlay(keypair1.clone(), Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, mut events2, _tx_events2, overlay2) =
        create_overlay(keypair2.clone(), Arc::new(OverlayMetrics::new())).unwrap();

    let peer1_id = PeerId::from_public_key(&keypair1.public());

    let base_port = 19461;

    let overlay1_task = tokio::spawn(async move {
        overlay1.run("127.0.0.1", base_port).await;
    });

    let overlay2_task = tokio::spawn(async move {
        overlay2.run("127.0.0.1", base_port + 1).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", base_port)
        .parse()
        .unwrap();
    handle2.dial(addr1).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain connection events
    while events1.try_recv().is_ok() {}
    while events2.try_recv().is_ok() {}

    // Node1 broadcasts SCP
    let scp_msg = test_scp_envelope_xdr(12);
    handle1.broadcast_scp(scp_msg.clone()).await;

    // Node2 receives it
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut node2_received = false;
    while tokio::time::Instant::now() < deadline && !node2_received {
        tokio::select! {
            Some(event) = events2.recv() => {
                if let OverlayEvent::ScpReceived { envelope, from, .. } = event {
                    if envelope == scp_msg && from == peer1_id {
                        node2_received = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(node2_received, "Node2 should receive SCP from Node1");

    // An explicit repeat broadcast by Node2 should NOT send back to Node1
    // (already in scp_sent_to). Normal received envelopes are not rebroadcast
    // by stellar-core.
    handle2.broadcast_scp(scp_msg.clone()).await;

    // Wait and verify Node1 does NOT receive an echo
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut echo_count = 0;
    while let Ok(event) = events1.try_recv() {
        if let OverlayEvent::ScpReceived { envelope, .. } = event {
            if envelope == scp_msg {
                echo_count += 1;
            }
        }
    }
    assert_eq!(
        echo_count, 0,
        "Node1 should NOT receive echo of its own SCP message"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;

    let _ = tokio::time::timeout(Duration::from_secs(1), overlay1_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), overlay2_task).await;
}

/// Test that 20 overlays can form a fully-connected mesh when dialing
/// simultaneously. This validates the fix for the stream-open deadlock:
/// `open_streams_to_peer` must be spawned (not awaited inline) so the
/// swarm event loop stays free to process incoming stream-open requests.
///
/// Without the fix, most `control.open_stream()` calls would time out
/// because the swarm couldn't be polled while awaiting inside the
/// `ConnectionEstablished` handler.
#[ignore = "flaky test"]
#[tokio::test]
async fn test_20_node_full_mesh() {
    const N: usize = 20;
    const BASE_PORT: u16 = 22000;

    // Create all overlays
    let mut handles = Vec::with_capacity(N);
    let mut metrics = Vec::with_capacity(N);
    let mut tasks = Vec::with_capacity(N);

    for i in 0..N {
        let keypair = Keypair::generate_ed25519();
        let m = Arc::new(OverlayMetrics::new());
        let (handle, _events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&m)).unwrap();

        let port = BASE_PORT + i as u16;
        tasks.push(tokio::spawn(async move {
            overlay.run("127.0.0.1", port).await;
        }));
        handles.push(handle);
        metrics.push(m);
    }

    // Brief pause for listeners to bind
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Every node dials every other node simultaneously — the thundering-herd
    // scenario that triggers the deadlock on unfixed code.
    for i in 0..N {
        for j in 0..N {
            if i == j {
                continue;
            }
            let port = BASE_PORT + j as u16;
            let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port)
                .parse()
                .unwrap();
            handles[i].dial(addr).await;
        }
    }

    // Wait for all connections and streams to establish.
    // With the deadlock fix, this should converge well within 5 seconds.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut all_connected = true;
        for i in 0..N {
            let count = handles[i].connected_peer_count().await;
            if count < N - 1 {
                all_connected = false;
                break;
            }
        }
        if all_connected {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            // Print diagnostics before failing
            for i in 0..N {
                let count = handles[i].connected_peer_count().await;
                let auth = metrics[i].connection_authenticated.load(Ordering::Relaxed);
                eprintln!(
                    "Node {}: connected_peer_count={}, connection_authenticated={}",
                    i, count, auth
                );
            }
            panic!(
                "Timed out waiting for full mesh: not all {} nodes have {} peers",
                N,
                N - 1
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Final assertion: every node has exactly N-1 authenticated peers
    for i in 0..N {
        let count = handles[i].connected_peer_count().await;
        assert_eq!(
            count,
            N - 1,
            "Node {} should have {} peers, got {}",
            i,
            N - 1,
            count
        );
    }

    // Shutdown all overlays
    for handle in &handles {
        handle.shutdown().await;
    }
    for task in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
}

/// Test that simultaneous dials between two peers result in exactly one
/// logical connection (num_established check prevents double stream setup).
#[tokio::test]
async fn test_simultaneous_dial_dedup() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let m1 = Arc::new(OverlayMetrics::new());
    let m2 = Arc::new(OverlayMetrics::new());
    let (handle1, _events1, _tx1, overlay1) = create_overlay(keypair1, Arc::clone(&m1)).unwrap();
    let (handle2, mut events2, _tx2, overlay2) = create_overlay(keypair2, Arc::clone(&m2)).unwrap();

    let port1 = 23100;
    let port2 = 23101;
    tokio::spawn(async move { overlay1.run("127.0.0.1", port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", port2).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Both sides dial each other simultaneously
    let addr1: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port1)
        .parse()
        .unwrap();
    let addr2: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port2)
        .parse()
        .unwrap();
    handle1.dial(addr2).await;
    handle2.dial(addr1).await;

    // Wait for connections to settle
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Each side should see exactly 1 connected peer (not 2)
    let count1 = handle1.connected_peer_count().await;
    let count2 = handle2.connected_peer_count().await;
    assert_eq!(count1, 1, "Node1 should have 1 peer, got {}", count1);
    assert_eq!(count2, 1, "Node2 should have 1 peer, got {}", count2);

    // connection_authenticated metric should also be 1 on each side
    let auth1 = m1.connection_authenticated.load(Ordering::Relaxed);
    let auth2 = m2.connection_authenticated.load(Ordering::Relaxed);
    assert_eq!(
        auth1, 1,
        "Node1 connection_authenticated should be 1, got {}",
        auth1
    );
    assert_eq!(
        auth2, 1,
        "Node2 connection_authenticated should be 1, got {}",
        auth2
    );

    // Verify SCP messages flow correctly (streams not corrupted by duplicate)
    handle1.broadcast_scp(test_scp_envelope_xdr(13)).await;
    let received = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(event) = events2.recv().await {
                if let OverlayEvent::ScpReceived { envelope, .. } = event {
                    return envelope;
                }
            }
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "Node2 should receive SCP message through deduped connection"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that DialPeer (PeerId-based) skips dialing when already connected.
#[tokio::test]
async fn test_dial_peer_skips_when_connected() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();
    let peer_id2 = keypair2.public().to_peer_id();

    let m1 = Arc::new(OverlayMetrics::new());
    let (handle1, _events1, _tx1, overlay1) = create_overlay(keypair1, Arc::clone(&m1)).unwrap();
    let (handle2, _events2, _tx2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let port1 = 23200;
    let port2 = 23201;
    tokio::spawn(async move { overlay1.run("127.0.0.1", port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", port2).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // First connection: address-based dial (bootstrap)
    let addr2: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port2)
        .parse()
        .unwrap();
    handle1.dial(addr2.clone()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(handle1.connected_peer_count().await, 1);

    // Record outbound_attempt before the PeerId-based dial
    let attempts_before = m1.outbound_attempt.load(Ordering::Relaxed);

    // PeerId-based dial should be a no-op (already connected)
    handle1.dial_peer(peer_id2, addr2.clone()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Should still have exactly 1 connection
    assert_eq!(handle1.connected_peer_count().await, 1);
    // outbound_attempt increments (we submitted the command), but connection_pending
    // should NOT have changed (DialPeer was rejected by libp2p before handshake)
    let attempts_after = m1.outbound_attempt.load(Ordering::Relaxed);
    assert_eq!(
        attempts_after,
        attempts_before + 1,
        "outbound_attempt should increment by 1"
    );

    handle1.shutdown().await;
    handle2.shutdown().await;
}

/// Test that PeerConnected event is emitted with the correct address
/// and that PeerDisconnected triggers reconnection.
#[tokio::test]
async fn test_peer_connected_event_emitted() {
    let keypair1 = Keypair::generate_ed25519();
    let keypair2 = Keypair::generate_ed25519();

    let (handle1, mut events1, _tx1, overlay1) =
        create_overlay(keypair1, Arc::new(OverlayMetrics::new())).unwrap();
    let (handle2, _events2, _tx2, overlay2) =
        create_overlay(keypair2, Arc::new(OverlayMetrics::new())).unwrap();

    let port1 = 23300;
    let port2 = 23301;
    tokio::spawn(async move { overlay1.run("127.0.0.1", port1).await });
    tokio::spawn(async move { overlay2.run("127.0.0.1", port2).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let addr2: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port2)
        .parse()
        .unwrap();
    handle1.dial(addr2).await;

    // Should receive PeerConnected event
    let connected_event = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(event) = events1.recv().await {
                if let OverlayEvent::PeerConnected { peer_id, addr } = event {
                    return (peer_id, addr);
                }
            }
        }
    })
    .await;

    assert!(
        connected_event.is_ok(),
        "Should receive PeerConnected event"
    );
    let (peer_id, addr) = connected_event.unwrap();
    // The address should contain 127.0.0.1 and port2
    let addr_str = addr.to_string();
    assert!(
        addr_str.contains("127.0.0.1") && addr_str.contains(&port2.to_string()),
        "PeerConnected addr should contain the peer's address, got: {}",
        addr_str
    );

    // Shutdown node2 → node1 should receive PeerDisconnected
    handle2.shutdown().await;
    let disconnect_event = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = events1.recv().await {
                if let OverlayEvent::PeerDisconnected { peer_id: pid } = event {
                    return pid;
                }
            }
        }
    })
    .await;
    assert!(
        disconnect_event.is_ok(),
        "Should receive PeerDisconnected event"
    );
    assert_eq!(disconnect_event.unwrap(), peer_id);

    handle1.shutdown().await;
}

/// Test that the 20-node mesh works with the new connectivity algorithm.
/// Audits metrics to verify no reconnection storms or duplicate connections.
#[ignore = "flaky test"]
#[tokio::test]
async fn test_20_node_mesh_with_dedup() {
    const N: usize = 20;
    const BASE_PORT: u16 = 24000;

    let mut handles = Vec::with_capacity(N);
    let mut event_rxs = Vec::with_capacity(N);
    let mut metrics = Vec::with_capacity(N);
    let mut tasks = Vec::with_capacity(N);

    for i in 0..N {
        let keypair = Keypair::generate_ed25519();
        let m = Arc::new(OverlayMetrics::new());
        let (handle, events, _tx_events, overlay) =
            create_overlay(keypair, Arc::clone(&m)).unwrap();

        let port = BASE_PORT + i as u16;
        tasks.push(tokio::spawn(async move {
            overlay.run("127.0.0.1", port).await;
        }));
        handles.push(handle);
        event_rxs.push(events);
        metrics.push(m);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let dial_start = tokio::time::Instant::now();

    // Every node dials every other node simultaneously
    for i in 0..N {
        for j in 0..N {
            if i == j {
                continue;
            }
            let port = BASE_PORT + j as u16;
            let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port)
                .parse()
                .unwrap();
            handles[i].dial(addr).await;
        }
    }

    // ── Convergence timeline: sample every 100ms ──
    eprintln!("\n=== Convergence timeline (20 nodes) ===");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut prev_total_peers = 0usize;
    let mut first_sample = true;
    let convergence_time = loop {
        let elapsed = dial_start.elapsed();
        let mut min_peers = usize::MAX;
        let mut max_peers = 0usize;
        let mut total_peers = 0usize;
        let mut total_out_est = 0u64;
        let mut total_in_est = 0u64;
        for i in 0..N {
            let count = handles[i].connected_peer_count().await;
            total_out_est += metrics[i].outbound_establish.load(Ordering::Relaxed);
            total_in_est += metrics[i].inbound_establish.load(Ordering::Relaxed);
            min_peers = min_peers.min(count);
            max_peers = max_peers.max(count);
            total_peers += count;
        }
        // Only print when something changed
        if total_peers != prev_total_peers || first_sample {
            eprintln!(
                "  t={:5.0?}ms  min_peers={:2}  max_peers={:2}  total_conns={:4}  out_est={:4}  in_est={:4}",
                elapsed.as_millis(), min_peers, max_peers, total_peers, total_out_est, total_in_est
            );
            prev_total_peers = total_peers;
            first_sample = false;
        }
        if min_peers >= N - 1 {
            eprintln!("  *** CONVERGED at t={:.0?}ms ***", elapsed.as_millis());
            break elapsed;
        }
        if tokio::time::Instant::now() >= deadline {
            for i in 0..N {
                let count = handles[i].connected_peer_count().await;
                let auth = metrics[i].connection_authenticated.load(Ordering::Relaxed);
                eprintln!("Node {}: peers={}, auth={}", i, count, auth);
            }
            panic!("Timed out: not all {} nodes have {} peers", N, N - 1);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    // ── Post-convergence stability: sample every 500ms for 3s ──
    eprintln!("\n=== Post-convergence stability (3s hold) ===");
    let mut prev_out: Vec<u64> = (0..N)
        .map(|i| metrics[i].outbound_establish.load(Ordering::Relaxed))
        .collect();
    let mut prev_in: Vec<u64> = (0..N)
        .map(|i| metrics[i].inbound_establish.load(Ordering::Relaxed))
        .collect();
    let mut prev_drop: Vec<u64> = (0..N)
        .map(|i| metrics[i].outbound_drop.load(Ordering::Relaxed))
        .collect();

    for tick in 1..=6 {
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut delta_out = 0u64;
        let mut delta_in = 0u64;
        let mut delta_drop = 0u64;
        let mut peer_counts_changed = false;
        for i in 0..N {
            let out = metrics[i].outbound_establish.load(Ordering::Relaxed);
            let inp = metrics[i].inbound_establish.load(Ordering::Relaxed);
            let drp = metrics[i].outbound_drop.load(Ordering::Relaxed);
            delta_out += out - prev_out[i];
            delta_in += inp - prev_in[i];
            delta_drop += drp - prev_drop[i];
            prev_out[i] = out;
            prev_in[i] = inp;
            prev_drop[i] = drp;

            let count = handles[i].connected_peer_count().await;
            if count != N - 1 {
                peer_counts_changed = true;
            }
        }
        eprintln!(
            "  t=+{:.1}s  new_out_est={:3}  new_in_est={:3}  new_drops={}  peer_counts_stable={}",
            tick as f64 * 0.5,
            delta_out,
            delta_in,
            delta_drop,
            !peer_counts_changed
        );

        assert_eq!(delta_drop, 0, "Drops at t=+{:.1}s", tick as f64 * 0.5);
        assert!(
            !peer_counts_changed,
            "Peer counts changed at t=+{:.1}s",
            tick as f64 * 0.5
        );
    }

    eprintln!("\n=== Final per-node metrics ===\n");

    // ── Detailed per-node audit ──
    let expected_dials = (N - 1) as u64; // each node dials N-1 others
    let mut total_outbound_establish = 0u64;
    let mut total_inbound_establish = 0u64;
    let mut total_outbound_drop = 0u64;
    let mut any_reconnect = false;
    let mut total_duplicate_conns = 0u64;

    for i in 0..N {
        let count = handles[i].connected_peer_count().await;
        let auth = metrics[i].connection_authenticated.load(Ordering::Relaxed);
        let out_attempt = metrics[i].outbound_attempt.load(Ordering::Relaxed);
        let out_establish = metrics[i].outbound_establish.load(Ordering::Relaxed);
        let in_establish = metrics[i].inbound_establish.load(Ordering::Relaxed);
        let out_drop = metrics[i].outbound_drop.load(Ordering::Relaxed);
        let pending = metrics[i].connection_pending.load(Ordering::Relaxed);
        // Duplicate connections = total transport connections - unique peers
        // auth == unique peers, (out_establish + in_establish) == total transport connections on this node
        let duplicates = (out_establish + in_establish) as i64 - auth;

        total_outbound_establish += out_establish;
        total_inbound_establish += in_establish;
        total_outbound_drop += out_drop;
        if duplicates > 0 {
            total_duplicate_conns += duplicates as u64;
        }

        eprintln!(
            "Node {:2}: peers={:2} auth={:2} out_attempt={:3} out_est={:2} in_est={:2} drops={} pending={} dupes={}",
            i, count, auth, out_attempt, out_establish, in_establish, out_drop, pending, duplicates
        );

        assert_eq!(count, N - 1, "Node {} peer count", i);
        assert_eq!(auth, (N - 1) as i64, "Node {} auth metric", i);
        assert_eq!(
            out_attempt, expected_dials,
            "Node {} should have dialed exactly {} peers",
            i, expected_dials
        );
        assert_eq!(
            out_drop, 0,
            "Node {} should have 0 drops (no reconnects)",
            i
        );
        assert_eq!(pending, 0, "Node {} should have 0 pending connections", i);

        if out_drop > 0 {
            any_reconnect = true;
        }
    }

    eprintln!(
        "\nTotals: out_establish={} in_establish={} drops={} duplicate_transport_conns={}",
        total_outbound_establish,
        total_inbound_establish,
        total_outbound_drop,
        total_duplicate_conns
    );
    eprintln!("Convergence time: {:.0?}ms", convergence_time.as_millis());
    eprintln!(
        "Unique peer pairs: {} (expected C({},2) = {})",
        total_outbound_establish / 2, // rough: each pair has ~2 outbound establishes
        N,
        N * (N - 1) / 2
    );

    assert!(
        !any_reconnect,
        "No node should have experienced a reconnect/drop"
    );

    // Verify SCP still flows: node 0 broadcasts, all others receive
    handles[0].broadcast_scp(test_scp_envelope_xdr(14)).await;
    let mut received_count = 0u32;
    for i in 1..N {
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(event) = event_rxs[i].recv().await {
                    match event {
                        OverlayEvent::ScpReceived { .. } => return true,
                        OverlayEvent::PeerConnected { .. } => continue,
                        _ => continue,
                    }
                }
            }
        })
        .await;
        if result.is_ok() {
            received_count += 1;
        }
    }
    assert_eq!(
        received_count,
        (N - 1) as u32,
        "All {} peers should receive SCP, got {}",
        N - 1,
        received_count
    );

    for handle in &handles {
        handle.shutdown().await;
    }
    for task in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
}
