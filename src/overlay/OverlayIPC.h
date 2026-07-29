// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "overlay/IPC.h"
#include "xdr/Stellar-overlay.h"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace stellar
{

class Application;

/**
 * OverlayIPC manages communication with the external Rust overlay process.
 *
 * This class:
 * 1. Spawns the overlay process on startup
 * 2. Sends SCP envelopes to be broadcast
 * 3. Receives SCP envelopes from the network
 * 4. Requests TX set hashes for nomination
 *
 * The overlay process handles:
 * - Peer connections and authentication (Noise protocol)
 * - SCP message relay with deduplication
 * - TX flooding with push-k strategy
 * - Mempool with fee ordering
 */
class OverlayIPC
{
  public:
    /// Callback when SCP envelope received from network
    using SCPReceivedCallback = std::function<void(SCPEnvelope const&)>;

    /// Callback when peer requests SCP state - returns envelopes to send
    using ScpStateRequestCallback =
        std::function<std::vector<SCPEnvelope>(uint32_t ledgerSeq)>;

    /// Callback when TX set received from peers (async fetch response)
    using TxSetReceivedCallback = std::function<void(
        Hash const& hash, GeneralizedTransactionSet const& txSet)>;

    /// Callback when Rust overlay reports quorum connectivity status.
    using QuorumConnectivityReportCallback =
        std::function<void(std::vector<std::string> const& missingValidators)>;

    /// Callback when the overlay asks Core to validate a batch of received
    /// transactions before flooding them. Invoked on the IPC reader thread;
    /// implementations must not block. Envelopes that failed to parse are
    /// represented as std::nullopt and must receive a verdict of 0.
    using ValidateTxsCallback = std::function<void(
        uint64_t batchId,
        std::vector<std::optional<TransactionEnvelope>> const& txs)>;

    /**
     * Create an OverlayIPC instance.
     *
     * @param socketPath Path for Unix domain socket, or empty for default
     * @param overlayBinaryPath Path to the overlay binary, or empty to search
     * @param peerPort Port for peer TCP connections (passed to overlay)
     */
    OverlayIPC(std::optional<std::string> socketPath,
               std::optional<std::string> overlayBinaryPath, uint16_t peerPort,
               std::optional<std::string> nodeSeedHex = std::nullopt,
               uint64_t quorumCheckGraceSecs = 30);

    static std::string defaultSocketPath(uint16_t peerPort);
    static std::optional<std::string> findOverlayBinaryPath();

    ~OverlayIPC();

    /**
     * Start the overlay process and connect.
     *
     * @return true if started successfully
     */
    bool start();

    /**
     * Stop the overlay process.
     */
    void shutdown();

    /**
     * Broadcast an SCP envelope to all peers.
     *
     * @param envelope The SCP envelope to broadcast
     * @return true if sent successfully
     */
    bool broadcastSCP(SCPEnvelope const& envelope);

    /**
     * Notify overlay of ledger close.
     *
     * @param ledgerSeq The closed ledger sequence number
     * @param ledgerHash The closed ledger hash
     * @param numClusters Maximum Reed-Solomon coding workers
     */
    void notifyLedgerClosed(uint32_t ledgerSeq, Hash const& ledgerHash,
                            uint32_t numClusters = 1);

    /**
     * Notify overlay that a TX set was externalized.
     *
     * The overlay should clear the corresponding TXs from its mempool.
     *
     * @param txSetHash The hash of the externalized TX set
     * @param txHashes The hashes of all TXs in the externalized TX set
     */
    void notifyTxSetExternalized(Hash const& txSetHash,
                                 std::vector<Hash> const& txHashes);

    /**
     * Request top N transactions by fee for nomination.
     *
     * This is a synchronous call that blocks until response received
     * or timeout expires.
     *
     * @param count Number of transactions to request
     * @param timeoutMs Timeout in milliseconds
     * @return Vector of transaction envelopes (may be less than count if
     * mempool is small)
     */
    std::vector<TransactionEnvelope> getTopTransactions(size_t count,
                                                        int timeoutMs = 1000);

    /**
     * Submit a transaction to the overlay for flooding.
     *
     * @param tx The transaction envelope
     * @param fee Transaction fee
     * @param numOps Number of operations
     */
    void submitTransaction(TransactionEnvelope const& tx, int64_t fee,
                           uint32_t numOps);

    /**
     * Request SCP state from peers.
     * Rust overlay will ask random peers for SCP messages >= ledgerSeq.
     *
     * @param ledgerSeq Minimum ledger sequence to request
     */
    void requestScpState(uint32_t ledgerSeq);

    /**
     * Configure peer addresses for the overlay.
     *
     * @param knownPeers List of known peer addresses (host:port)
     * @param preferredPeers List of preferred peer addresses (host:port)
     * @param listenPort Local port to listen on
     * @param numClusters Maximum Reed-Solomon coding workers
     */
    void setPeerConfig(std::vector<std::string> const& knownPeers,
                       std::vector<std::string> const& preferredPeers,
                       uint16_t listenPort,
                       std::vector<std::string> const& quorumMembers = {},
                       size_t txBatchMaxSize = 0,
                       uint32_t numClusters = 1,
                       bool suppressTxBroadcast = false);

    /**
     * Push the upcoming nomination leaders for `slotIndex` to the overlay
     * (validator strkeys, ordered by election priority). Replaces the
     * overlay's previous flood-target set. See
     * docs/direct-leader-flooding.md.
     */
    void updateLeaders(uint64_t slotIndex,
                       std::vector<std::string> const& leaderStrkeys);

    /**
     * Request a TX set by hash from peers (asynchronous).
     *
     * The Rust overlay will fetch from peers and notify via the
     * TxSetReceivedCallback when available.
     *
     * @param hash The TX set hash to request
     */
    void requestTxSet(Hash const& hash);

    /**
     * Cache a locally-built TX set in the Rust overlay.
     *
     * After Core builds a TX set from mempool transactions, it must
     * send the set to Rust so that Rust can serve it to other peers
     * who request it via TX set fetching.
     *
     * @param hash The TX set hash
     * @param xdr The serialized TX set XDR
     */
    void cacheTxSet(Hash const& hash, std::vector<uint8_t> const& xdr);

    /**
     * Eagerly disseminate a locally-built TX set as erasure-coded shreds.
     *
     * Like cacheTxSet, but in addition to caching the set the overlay
     * codes and assigns shreds immediately, so receivers have it before/when
     * they process the nomination that
     * references it -- removing the GetTxSet request round-trip from the
     * nomination critical path. Intended for the round-1 leader only.
     *
     * @param hash The TX set hash
     * @param xdr The serialized TX set XDR
     */
    void broadcastTxSet(Hash const& hash, std::vector<uint8_t> const& xdr);

    /// Set callback for received SCP envelopes
    void setOnSCPReceived(SCPReceivedCallback cb);

    /// Set callback for SCP state requests from peers
    void setOnScpStateRequest(ScpStateRequestCallback cb);

    /// Set callback for TX set received from peers (async fetch)
    void setOnTxSetReceived(TxSetReceivedCallback cb);

    /// Set callback for quorum connectivity reports.
    void setOnQuorumConnectivityReport(QuorumConnectivityReportCallback cb);

    /// Set callback for pre-flood tx validation requests from the overlay.
    void setOnValidateTxs(ValidateTxsCallback cb);

    /// Send the per-tx verdicts for a VALIDATE_TXS batch back to the overlay.
    /// Thread-safe; callable from any thread.
    void sendTxValidationVerdicts(uint64_t batchId,
                                  std::vector<uint8_t> const& verdicts);

    /**
     * Request overlay metrics snapshot from Rust overlay.
     *
     * Synchronous call — blocks until the Rust overlay responds with
     * a JSON-serialized metrics snapshot, or timeout.
     *
     * @param timeoutMs Timeout in milliseconds
     * @return JSON string with the overlay metrics, empty on timeout/error
     */
    std::string requestMetrics(int timeoutMs = 1000);

    /// Check if connected to overlay
    bool isConnected() const;

    /// Get the socket path
    std::string const&
    getSocketPath() const
    {
        return mSocketPath;
    }

  private:
    /// Spawn the overlay process
    bool spawnOverlay();

    std::optional<std::string> resolveOverlayBinaryPath() const;

    /// Reader thread function for one IPC channel.
    void readerLoop(IPCChannel* channel, char const* channelName);

    /// Handle a received IPC message
    void handleMessage(IPCMessage const& msg);

    /// Send SCP state response to overlay with request ID for correlation
    void sendScpStateResponse(uint64_t requestId,
                              std::vector<SCPEnvelope> const& envelopes);

    std::string mSocketPath;
    // SCP uses a physically separate socket so consensus messages cannot be
    // queued behind or decoded after bulk transaction-set payloads.
    std::string mSCPSocketPath;
    std::optional<std::string> mOverlayBinaryPath;
    uint16_t mPeerPort;
    std::optional<std::string> mNodeSeedHex;
    uint64_t mQuorumCheckGraceSecs;
    std::optional<std::string> mStartupConfigPath;

    std::unique_ptr<IPCChannel> mChannel;
    std::unique_ptr<IPCChannel> mSCPChannel;
    std::thread mReaderThread;
    std::thread mSCPReaderThread;
    std::atomic<bool> mRunning{false};

    pid_t mOverlayPid{-1};

    SCPReceivedCallback mOnSCPReceived;
    ScpStateRequestCallback mOnScpStateRequest;
    TxSetReceivedCallback mOnTxSetReceived;
    QuorumConnectivityReportCallback mOnQuorumConnectivityReport;
    ValidateTxsCallback mOnValidateTxs;

    // For synchronous request/response (getTopTransactions)
    std::mutex mRequestMutex;
    std::condition_variable mRequestCv;
    std::optional<IPCMessage> mPendingResponse;

    // For synchronous metrics request/response
    std::mutex mMetricsMutex;
    std::condition_variable mMetricsCv;
    std::optional<IPCMessage> mPendingMetricsResponse;

    // Protects mChannel->send() - channel is not thread-safe
    mutable std::mutex mSendMutex;
    // Protects mSCPChannel->send() independently from bulk IPC writes.
    mutable std::mutex mSCPSendMutex;
};

} // namespace stellar
