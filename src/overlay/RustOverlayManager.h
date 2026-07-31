// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "herder/TxSetFrame.h"
#include "overlay/OverlayIPC.h"
#include "overlay/OverlayMetrics.h"
#include <optional>
#include <unordered_map>

namespace stellar
{

class Application;
class PeerBareAddress;
struct StellarMessage;

using TxSetXDRFrameConstPtr = std::shared_ptr<TxSetXDRFrame const>;

/**
 * RustOverlayManager delegates peer management to an external Rust process.
 *
 * All networking is routed through the Rust overlay via IPC:
 * - broadcastMessage() -> sends SCP/TX via IPC
 * - Peer discovery handled by Kademlia DHT in Rust overlay
 */
class RustOverlayManager
{
  public:
    RustOverlayManager(Application& app);
    ~RustOverlayManager();

    // Lifecycle
    void start();
    void shutdown();
    bool isShuttingDown() const;

    // Network operations
    bool broadcastMessage(std::shared_ptr<StellarMessage const> msg,
                          std::optional<Hash> const hash = std::nullopt);
    void broadcastTransaction(TransactionEnvelope const& tx, int64_t fee,
                              uint32_t numOps);

    void clearLedgersBelow(uint32_t ledgerSeq, uint32_t lclSeq);

    // TX set management - notify that TX set was externalized with its TX
    // hashes
    void notifyTxSetExternalized(Hash const& txSetHash,
                                 std::vector<Hash> const& txHashes);

    // Request TX set from peers (via Rust overlay, async)
    void requestTxSet(Hash const& txSetHash);

    // Cache a locally-built TX set in Rust overlay
    void cacheTxSet(Hash const& txSetHash, std::vector<uint8_t> const& xdr);

    // Eagerly code and disseminate a TX set (round-1 leader only). The slot
    // the set is proposed for travels with the request so the overlay never
    // mis-attributes an early (pre-trigger) broadcast to the previous slot.
    void broadcastTxSet(Hash const& txSetHash, std::vector<uint8_t> const& xdr,
                        uint64_t slotIndex);

    // Get top transactions from Rust overlay's mempool for TX set building
    std::vector<TransactionEnvelope> getTopTransactions(size_t count,
                                                        int timeoutMs = 5000);

    // Metrics and managers
    OverlayMetrics& getOverlayMetrics();

    /// Fetch the latest metrics snapshot from the Rust overlay and update
    /// the libmedida-backed OverlayMetrics counters/timers so they appear
    /// on the /metrics HTTP endpoint.
    void syncOverlayMetrics();

    // Access to IPC (for Herder to set callbacks)
    OverlayIPC&
    getOverlayIPC()
    {
        return *mOverlayIPC;
    }

  private:
    // Max Reed-Solomon coding workers for the overlay's TX-set shreds, from
    // ledgerMaxDependentTxClusters. 1 when there is no Soroban config yet.
    uint32_t txSetCodingParallelism() const;

    Application& mApp;
    std::unique_ptr<OverlayIPC> mOverlayIPC;
    std::atomic<bool> mShuttingDown{false};

    OverlayMetrics mOverlayMetrics;

    // For computing deltas on monotonic counters between syncs.
    // Key: metric name, Value: last synced value.
    std::unordered_map<std::string, int64_t> mLastSyncedValues;
};

} // namespace stellar
