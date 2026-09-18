#include "scp/LeaderElection.h"
#include "scp/LocalNode.h"
#include "scp/SCP.h"
#include "scp/Slot.h"
#include "simulation/Simulation.h"
#include "test/Catch2.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

namespace stellar
{

class TestElectionSCP : public SCPDriver
{
  public:
    SCP mSCP;
    uint32_t mInitialBallotTimeoutMS = 1000;
    uint32_t mIncrementBallotTimeoutMS = 1000;

    TestElectionSCP(NodeID const& nodeID, SCPQuorumSet const& qSetLocal)
        : mSCP(*this, nodeID, true, qSetLocal)
    {
        auto localQSet =
            std::make_shared<SCPQuorumSet>(mSCP.getLocalQuorumSet());
        storeQuorumSet(localQSet);
    }

    void
    signEnvelope(SCPEnvelope&) override
    {
    }

    void
    storeQuorumSet(SCPQuorumSetPtr qSet)
    {
        Hash qSetHash = sha256(xdr::xdr_to_opaque(*qSet.get()));
        mQuorumSets[qSetHash] = qSet;
    }

    SCPDriver::ValidationLevel
    validateValue(uint64 slotIndex, Value const& value) const override
    {
        return SCPDriver::kFullyValidatedValue;
    }

    SCPQuorumSetPtr
    getQSet(Hash const& qSetHash) override
    {
        if (mQuorumSets.find(qSetHash) != mQuorumSets.end())
        {

            return mQuorumSets[qSetHash];
        }
        return SCPQuorumSetPtr();
    }

    void
    emitEnvelope(SCPEnvelope const& envelope) override
    {
    }

    void
    setupTimer(uint64 slotIndex, int timerID, std::chrono::milliseconds timeout,
               std::function<void()> cb) override
    {
    }

    void
    stopTimer(uint64 slotIndex, int timerID) override
    {
    }

    std::optional<std::chrono::milliseconds>
    getTxSetDownloadWaitTime(Value const& v) const override
    {
        return std::nullopt;
    }

    std::chrono::milliseconds
    getTxSetDownloadTimeout() const override
    {
        return std::chrono::milliseconds(100);
    }

    Value
    makeEmptyTxSetValueFromValue(Value const& value) const override
    {
        releaseAssert(false);
    }

    bool
    isEmptyTxSetValue(Value const& v) const override
    {
        releaseAssert(false);
    }

    bool
    isParallelTxSetDownloadEnabled() const override
    {
        return true;
    }

    bool
    protocolAllowsEmptyTxSetValues() const override
    {
        return true;
    }

    std::map<Hash, SCPQuorumSetPtr> mQuorumSets;

    Hash
    getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const override
    {
        SHA256 hasher;
        for (auto const& v : vals)
        {
            hasher.add(v);
        }
        return hasher.finish();
    }

    // Copied from HerderSCPDriver.cpp
    static uint32_t const MAX_TIMEOUT_MS = (30 * 60) * 1000;

    std::chrono::milliseconds
    computeTimeout(uint32 roundNumber) override
    {
        int initialTimeoutMS = mInitialBallotTimeoutMS;
        int incrementMS = mIncrementBallotTimeoutMS;

        int timeoutMS = initialTimeoutMS + (roundNumber - 1) * incrementMS;
        if (timeoutMS > MAX_TIMEOUT_MS)
        {
            timeoutMS = MAX_TIMEOUT_MS;
        }
        return std::chrono::milliseconds(timeoutMS);
    }

    bool
    isEnvelopeReady(SCPEnvelope const& envelope) const override
    {
        // Not implemented. These tests do not use PendingEnvelopes, and so do
        // not require this method.
        releaseAssert(false);
    }
};

// Deliberately repeat the first winner in round 2, so the second call must
// fast-forward to round 3. This catches predicting round 2's hash in isolation.
class LeaderPreviewTestDriver : public TestElectionSCP
{
  public:
    std::vector<NodeID> nodes;
    bool tie = false;
    std::set<NodeID> zeroWeight;
    size_t emitted = 0;
    size_t timers = 0;

    LeaderPreviewTestDriver(NodeID const& local, SCPQuorumSet const& qset)
        : TestElectionSCP(local, qset), nodes(qset.validators)
    {
    }

    uint64
    getNodeWeight(NodeID const& id) const override
    {
        return zeroWeight.count(id) ? 0 : UINT64_MAX;
    }

    uint64
    computeHashNode(uint64, Value const&, bool priority, int32 round,
                    NodeID const& id) override
    {
        if (!priority)
        {
            return 0;
        }
        auto winner = round < 3 ? nodes[0] : round == 3 ? nodes[1] : nodes[2];
        return id == winner || (tie && round < 3 && id == nodes[2]) ? 100 : 1;
    }

    void
    emitEnvelope(SCPEnvelope const&) override
    {
        ++emitted;
    }

    void
    setupTimer(uint64, int timerID, std::chrono::milliseconds,
               std::function<void()> cb) override
    {
        ++timers;
    }
};

TEST_CASE("leader preview has no protocol side effects", "[scp][leader]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SCPQuorumSet qset;
    qset.threshold = 2;
    qset.validators = {v0NodeID, v1NodeID, v2NodeID};
    // The local node appears in a later round. Previewing the schedule must
    // not create a ballot, emit a vote, or arm a timer.
    LeaderPreviewTestDriver driver(v1NodeID, qset);
    auto& scp = driver.mSCP;
    Value previous{42}, value{43};
    auto const first = scp.predictLeaders(7, previous, 1);
    auto const firstTwo = scp.predictLeaders(7, previous, 2);
    REQUIRE(first == std::set<NodeID>{v0NodeID});
    REQUIRE(firstTwo == std::set<NodeID>{v0NodeID, v1NodeID});
    REQUIRE(scp.electLeader(7, previous) == v0NodeID);
    REQUIRE(scp.getKnownSlotsCount() == 0);
    REQUIRE(driver.emitted == 0);
    REQUIRE(driver.timers == 0);
}

TEST_CASE("leader preview preserves ties and zero weights", "[scp][leader]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SCPQuorumSet qset;
    qset.threshold = 2;
    qset.validators = {v0NodeID, v1NodeID, v2NodeID};
    LeaderPreviewTestDriver driver(v1NodeID, qset);
    Value previous{42};
    SECTION("ties may elect more than two nodes in the first two calls")
    {
        driver.tie = true;
        REQUIRE(driver.mSCP.predictLeaders(7, previous, 1) ==
                std::set<NodeID>{v0NodeID, v2NodeID});
        REQUIRE(driver.mSCP.predictLeaders(7, previous, 2) ==
                std::set<NodeID>{v0NodeID, v1NodeID, v2NodeID});
    }
    SECTION("zero weight winners are excluded, including self")
    {
        driver.zeroWeight = {v0NodeID, v1NodeID};
        REQUIRE(driver.mSCP.predictLeaders(7, previous, 2) ==
                std::set<NodeID>{v2NodeID});
    }
    SECTION("no eligible nodes")
    {
        driver.zeroWeight = {v0NodeID, v1NodeID, v2NodeID};
        REQUIRE(driver.mSCP.predictLeaders(7, previous, 2).empty());
    }
    REQUIRE(driver.emitted == 0);
    REQUIRE(driver.timers == 0);
    REQUIRE(driver.mSCP.getKnownSlotsCount() == 0);
}

TEST_CASE("leader election agrees across observers and quorum shapes",
          "[scp][leader-ballot][leader]")
{
    std::vector<NodeID> ids;
    for (int i = 0; i < 5; ++i)
        ids.push_back(
            SecretKey::fromSeed(sha256("leader-election-" + std::to_string(i)))
                .getPublicKey());
    SCPQuorumSet qset;
    qset.threshold = 4;
    qset.validators.assign(ids.begin(), ids.end());
    std::vector<std::unique_ptr<TestElectionSCP>> nodes;
    for (size_t i = 0; i < ids.size(); ++i)
    {
        auto local = qset;
        std::rotate(local.validators.begin(), local.validators.begin() + i,
                    local.validators.end());
        nodes.emplace_back(std::make_unique<TestElectionSCP>(ids[i], local));
    }
    std::set<NodeID> winners;
    for (uint64 slot = 1; slot <= 256; ++slot)
    {
        for (auto previous : {Value{1}, Value{2}, Value{3}})
        {
            auto winner = nodes[0]->mSCP.electLeader(slot, previous);
            winners.insert(winner);
            for (auto& node : nodes)
            {
                REQUIRE(node->mSCP.electLeader(slot, previous) == winner);
                REQUIRE(node->mSCP.getKnownSlotsCount() == 0);
            }
        }
    }
    REQUIRE(winners.size() == ids.size());
}

TEST_CASE("weighted leader election agrees across validators and watchers",
          "[scp][leader-ballot][leader]")
{
    class WeightedDriver : public TestElectionSCP
    {
      public:
        std::map<NodeID, uint64> weights;
        WeightedDriver(NodeID const& id, SCPQuorumSet const& qset)
            : TestElectionSCP(id, qset)
        {
        }
        uint64
        getNodeWeight(NodeID const& id) const override
        {
            return weights.at(id);
        }
    };
    std::vector<NodeID> ids;
    for (int i = 0; i < 5; ++i)
        ids.push_back(SecretKey::fromSeed(
                          sha256("weighted-election-" + std::to_string(i)))
                          .getPublicKey());
    SCPQuorumSet qset;
    qset.threshold = 4;
    qset.validators.assign(ids.begin(), ids.end());
    std::vector<std::unique_ptr<WeightedDriver>> nodes;
    for (auto const& id : ids)
    {
        auto node = std::make_unique<WeightedDriver>(id, qset);
        for (size_t i = 0; i < ids.size(); ++i)
            node->weights[ids[i]] = i == 4 ? 0 : UINT64_MAX / (i + 1);
        nodes.push_back(std::move(node));
    }
    std::set<NodeID> winners;
    for (uint64 slot = 1; slot <= 256; ++slot)
    {
        Value previous{42};
        auto leader = nodes[0]->mSCP.electLeader(slot, previous);
        REQUIRE(leader != ids.back());
        winners.insert(leader);
        for (auto& node : nodes)
        {
            REQUIRE(node->mSCP.electLeader(slot, previous) == leader);
            auto watcher = stellar::predictLeaders(
                *node, slot, previous, qset,
                SecretKey::fromSeed(sha256("watcher")).getPublicKey(), false,
                1);
            REQUIRE(*watcher.begin() == leader);
            REQUIRE(node->mSCP.getKnownSlotsCount() == 0);
        }
    }
    REQUIRE(winners.size() == 4);
}
}
