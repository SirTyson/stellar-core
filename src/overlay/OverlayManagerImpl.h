// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "Peer.h"
#include "PeerAuth.h"
#include "PeerDoor.h"
#include "PeerManager.h"
#include "herder/TxSetFrame.h"
#include "ledger/ImmutableLedgerView.h"
#include "ledger/LedgerTxn.h"
#include "overlay/Floodgate.h"
#include "overlay/OverlayManager.h"
#include "overlay/OverlayMetrics.h"
#include "overlay/QuorumPeering.h"
#include "overlay/SurveyManager.h"
#include "overlay/TxDemandsManager.h"
#include "util/Timer.h"

#include "util/RandomEvictionCache.h"

#include <future>
#include <set>
#include <vector>

namespace medida
{
class Meter;
class Counter;
}

/*
Maintain the set of peers we are connected to
*/
namespace stellar
{

class OverlayManagerImpl : public OverlayManager
{
  protected:
    Application& mApp;
    std::set<PeerBareAddress> mConfigurationPreferredPeers;

    struct PeersList
    {
        explicit PeersList(OverlayManagerImpl& overlayManager,
                           MetricsRegistry& metricsRegistry,
                           std::string const& directionString,
                           std::string const& cancelledName,
                           int maxAuthenticatedCount, bool inbound,
                           std::shared_ptr<SurveyManager> sm);

        medida::Meter& mConnectionsAttempted;
        medida::Meter& mConnectionsEstablished;
        medida::Meter& mConnectionsDropped;
        medida::Meter& mConnectionsCancelled;

        OverlayManagerImpl& mOverlayManager;
        std::string mDirectionString;
        size_t mMaxAuthenticatedCount;
        bool const mInbound;
        std::shared_ptr<SurveyManager> mSurveyManager;

        std::vector<Peer::pointer> mPending;
        std::map<NodeID, Peer::pointer> mAuthenticated;
        // Keep dropped peers alive, just so overlay thread can still
        // safely perform delayed shutdown, etc; when overlay thread is done and
        // main is the only user left, release all references
        std::unordered_set<Peer::pointer> mDropped;

        Peer::pointer byAddress(PeerBareAddress const& address) const;
        void removePeer(Peer* peer);
        bool moveToAuthenticated(Peer::pointer peer);
        bool acceptAuthenticatedPeer(Peer::pointer peer);
        void shutdown();

        // Number of authenticated peers that are mutually trusted quorum
        // peers.
        size_t countMutuallyTrusted() const;
        // Slots available to mutually trusted quorum peers. Inbound, this is
        // capped so that RESERVED_UNPRIVILEGED_INBOUND_SLOTS slots remain
        // that trusted peers can neither fill nor evict into; outbound,
        // trusted peers get their own budget on top of
        // TARGET_PEER_CONNECTIONS.
        size_t trustedCapacity() const;
        // Evict an authenticated peer that is neither preferred nor mutually
        // trusted; returns false if there is no such victim.
        bool evictNonPrioritized(Peer::pointer forPeer);
    };

    std::shared_ptr<int> mLiveInboundPeersCounter;

    PeersList& getPeersList(Peer* peer);

    PeerManager mPeerManager;
    PeerDoor mDoor;
    PeerAuth mAuth;
    QuorumPeering mQuorumPeering;
    std::atomic<bool> mShuttingDown;

    OverlayMetrics mOverlayMetrics;

    // NOTE: bool is used here as a placeholder, since no ValueType is needed.
    RandomEvictionCache<uint64_t, bool> mMessageCache;

    void tick();
    void updateTimerAndMaybeDropRandomPeer(bool shouldDrop);
    VirtualTimer mTimer;
    VirtualTimer mPeerIPTimer;
    std::optional<VirtualClock::time_point> mLastOutOfSyncReconnect;

    friend class OverlayManagerTests;
    friend class Simulation;

    Floodgate mFloodGate;
    TxDemandsManager mTxDemandsManager;

    std::shared_ptr<SurveyManager> mSurveyManager;

    PeersList mInboundPeers;
    PeersList mOutboundPeers;
    int availableOutboundPendingSlots() const;

  public:
    OverlayManagerImpl(Application& app);
    ~OverlayManagerImpl();

    void clearLedgersBelow(uint32_t ledgerSeq, uint32_t lclSeq) override;
    bool recvFloodedMsgID(Peer::pointer peer, Hash const& msgID) override;
    void recvTransaction(TransactionFrameBasePtr transaction,
                         Peer::pointer peer, Hash const& index) override;
    void forgetFloodedMsg(Hash const& msgID) override;
    void recvTxDemand(FloodDemand const& dmd, Peer::pointer peer) override;
    bool
    broadcastMessage(std::shared_ptr<StellarMessage const> msg,
                     std::optional<Hash> const hash = std::nullopt) override;
    void connectTo(PeerBareAddress const& address) override;

    void maybeAddInboundConnection(Peer::pointer peer) override;
    bool addOutboundConnection(Peer::pointer peer) override;
    void removePeer(Peer* peer) override;
    void storeConfigPeers();
    void purgeDeadPeers();

    bool acceptAuthenticatedPeer(Peer::pointer peer) override;
    bool isPreferred(Peer* peer) const override;
    // True when the peer is a quorum member that confirmed mutual trust
    // during the handshake (see QuorumPeering).
    bool isMutuallyTrusted(Peer* peer) const;
    // Preferred (operator config) or mutually trusted (automatic quorum
    // peering): peers we always want to stay connected to.
    bool isPrioritized(Peer* peer) const;
    std::vector<Peer::pointer> const& getInboundPendingPeers() const override;
    std::vector<Peer::pointer> const& getOutboundPendingPeers() const override;
    std::vector<Peer::pointer> getPendingPeers() const override;

    virtual std::shared_ptr<int> getLiveInboundPeersCounter() const override;

    int getPendingPeersCount() const override;
    std::map<NodeID, Peer::pointer> const&
    getInboundAuthenticatedPeers() const override;
    std::map<NodeID, Peer::pointer> const&
    getOutboundAuthenticatedPeers() const override;
    std::map<NodeID, Peer::pointer> getAuthenticatedPeers() const override;
    int getAuthenticatedPeersCount() const override;

    // returns nullptr if the passed peer isn't found
    Peer::pointer getConnectedPeer(PeerBareAddress const& address) override;

    std::vector<Peer::pointer> getRandomAuthenticatedPeers() override;
    std::vector<Peer::pointer> getRandomInboundAuthenticatedPeers() override;
    std::vector<Peer::pointer> getRandomOutboundAuthenticatedPeers() override;

    std::set<Peer::pointer> getPeersKnows(Hash const& h) override;

    OverlayMetrics& getOverlayMetrics() override;
    PeerAuth& getPeerAuth() override;

    PeerManager& getPeerManager() override;

    QuorumPeering& getQuorumPeering() override;

    SurveyManager& getSurveyManager() override;

    void start() override;
    void shutdown() override;

    bool isShuttingDown() const override;

    void recordMessageMetric(StellarMessage const& stellarMsg,
                             Peer::pointer peer) override;

    ImmutableLedgerView& getOverlayThreadSnapshot() override;

  private:
    struct ResolvedPeers
    {
        std::vector<PeerBareAddress> known;
        std::vector<PeerBareAddress> preferred;
        bool errors;
    };

    std::map<PeerType, std::unique_ptr<RandomPeerSource>> mPeerSources;
    std::future<ResolvedPeers> mResolvedPeers;
    bool mResolvingPeersWithBackoff;
    int mResolvingPeersRetryCount;
    RandomEvictionCache<Hash, std::weak_ptr<CapacityTrackedMessage>>
        mScheduledMessages;

    // Snapshot of ledger state for use ONLY by the overlay thread
    std::optional<ImmutableLedgerView> mOverlayThreadSnapshot;

    void triggerPeerResolution();
    std::pair<std::vector<PeerBareAddress>, bool>
    resolvePeers(std::vector<std::string> const& peers);
    void storePeerList(std::vector<PeerBareAddress> const& addresses,
                       bool setPreferred, bool startup);

    virtual bool connectToImpl(PeerBareAddress const& address,
                               bool forceoutbound);
    int connectTo(int maxNum, PeerType peerType);
    int connectTo(std::vector<PeerBareAddress> const& peers,
                  bool forceoutbound);
    std::vector<PeerBareAddress> getPeersToConnectTo(int maxNum,
                                                     PeerType peerType);

    bool moveToAuthenticated(Peer::pointer peer);

    int availableOutboundAuthenticatedSlots() const;
    int nonPreferredAuthenticatedCount() const;

    // Number of connected (inbound or outbound) mutually trusted quorum
    // peers.
    size_t countConnectedMutuallyTrusted() const;
    // Invalidate MUTUAL quorum dispositions whose pinned address keeps
    // failing while the key is disconnected, so hunting resumes for them.
    void invalidateStaleQuorumPeers();

    virtual bool isPossiblyPreferred(std::string const& ip) const override;
    virtual bool haveSpaceForConnection(std::string const& ip) const override;

    void updateSizeCounters();

    void extractPeersFromMap(std::map<NodeID, Peer::pointer> const& peerMap,
                             std::vector<Peer::pointer>& result);
    void shufflePeerList(std::vector<Peer::pointer>& peerList);
    uint32_t getFlowControlBytesTotal() const override;

    // Returns `true` iff the overlay can accept the outbound peer at `address`.
    // Logs whenever a peer cannot be accepted.
    bool canAcceptOutboundPeer(PeerBareAddress const& address) const;

    bool checkScheduledAndCache(
        std::shared_ptr<CapacityTrackedMessage> tracker) override;
};
}
