#include "scp/LocalNode.h"
#include "scp/QuorumSetUtils.h"
#include "scp/SCP.h"
#include "scp/Slot.h"
#include "simulation/Simulation.h"
#include "test/Catch2.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

namespace stellar
{
static bool
isNear(uint64 r, double target)
{
    double v = (double)r / (double)UINT64_MAX;
    return (std::abs(v - target) < .01);
}

class TestNominationSCP : public SCPDriver
{
  public:
    SCP mSCP;
    uint32_t mInitialNominationTimeoutMS = 1000;
    uint32_t mIncrementNominationTimeoutMS = 1000;
    uint32_t mInitialBallotTimeoutMS = 1000;
    uint32_t mIncrementBallotTimeoutMS = 1000;

    TestNominationSCP(NodeID const& nodeID, SCPQuorumSet const& qSetLocal)
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
    validateValue(uint64 slotIndex, Value const& value,
                  bool nomination) override
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

    ValueWrapperPtr
    combineCandidates(uint64 slotIndex,
                      ValueWrapperPtrSet const& candidates) override
    {
        return nullptr;
    }

    bool
    hasUpgrades(Value const& v) override
    {
        // Not implemented
        releaseAssert(false);
    }

    ValueWrapperPtr
    stripAllUpgrades(Value const& v) override
    {
        // Not implemented
        releaseAssert(false);
    }

    uint32_t
    getUpgradeNominationTimeoutLimit() const override
    {
        return std::numeric_limits<uint32_t>::max();
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

    std::map<Hash, SCPQuorumSetPtr> mQuorumSets;

    Value const&
    getLatestCompositeCandidate(uint64 slotIndex)
    {
        static Value const emptyValue{};
        return emptyValue;
    }

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
    computeTimeout(uint32 roundNumber, bool isNomination) override
    {
        int initialTimeoutMS;
        int incrementMS;

        if (isNomination)
        {
            initialTimeoutMS = mInitialNominationTimeoutMS;
            incrementMS = mIncrementNominationTimeoutMS;
        }
        else
        {
            initialTimeoutMS = mInitialBallotTimeoutMS;
            incrementMS = mIncrementBallotTimeoutMS;
        }

        int timeoutMS = initialTimeoutMS + (roundNumber - 1) * incrementMS;
        if (timeoutMS > MAX_TIMEOUT_MS)
        {
            timeoutMS = MAX_TIMEOUT_MS;
        }
        return std::chrono::milliseconds(timeoutMS);
    }
};

TEST_CASE("nomination weight", "[scp]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);

    SCPQuorumSet qSet;
    qSet.threshold = 3;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);

    TestNominationSCP const nomSCP(v0NodeID, qSet);

    uint64 result = nomSCP.getNodeWeight(v2NodeID, qSet, false);

    REQUIRE(isNear(result, .75));

    result = nomSCP.getNodeWeight(v4NodeID, qSet, false);
    REQUIRE(result == 0);

    SCPQuorumSet iQSet;
    iQSet.threshold = 1;
    iQSet.validators.push_back(v4NodeID);
    iQSet.validators.push_back(v5NodeID);
    qSet.innerSets.push_back(iQSet);

    result = nomSCP.getNodeWeight(v4NodeID, qSet, false);

    REQUIRE(isNear(result, .6 * .5));
}

class NominationTestHandler : public NominationProtocol
{
  public:
    NominationTestHandler(Slot& s) : NominationProtocol(s)
    {
    }

    void
    setPreviousValue(Value const& v)
    {
        mPreviousValue = v;
    }

    void
    setLeaderElectionSeed(Value const& v)
    {
        mLeaderElectionSeed = v;
    }

    void
    setRoundNumber(int32 n)
    {
        mRoundNumber = n;
    }

    int32
    getRoundNumber() const
    {
        return mRoundNumber;
    }

    void
    updateRoundLeaders()
    {
        NominationProtocol::updateRoundLeaders();
    }

    // Drives one nomination step the way the live nominate() path does:
    // increments the round number, then recomputes/accumulates leaders.
    void
    bumpRoundAndUpdateLeaders()
    {
        ++mRoundNumber;
        NominationProtocol::updateRoundLeaders();
    }

    std::set<NodeID>&
    getRoundLeaders()
    {
        return mRoundLeaders;
    }
};

// A test SCPDriver that allows specification of nodes with 0 weight.
class ZeroWeightTestNominationSCP : public TestNominationSCP
{
  public:
    std::set<NodeID> mZeroWeightNodes;

    ZeroWeightTestNominationSCP(NodeID const& nodeID,
                                SCPQuorumSet const& qSetLocal,
                                std::set<NodeID> const& zeroWeightNodes)
        : TestNominationSCP(nodeID, qSetLocal)
        , mZeroWeightNodes(zeroWeightNodes)
    {
    }

    uint64
    getNodeWeight(NodeID const& nodeID, SCPQuorumSet const& qset,
                  bool isLocalNode) const override
    {
        if (mZeroWeightNodes.count(nodeID))
        {
            return 0;
        }
        return TestNominationSCP::getNodeWeight(nodeID, qset, isLocalNode);
    }
};

static SCPQuorumSet
makeQSet(std::vector<NodeID> const& nodeIDs, int threshold, int total,
         int offset)
{
    SCPQuorumSet qSet;
    qSet.threshold = threshold;
    for (int i = 0; i < total; i++)
    {
        qSet.validators.push_back(nodeIDs[i + offset]);
    }
    return qSet;
}

TEST_CASE("updateRoundLeaders handles zero weight nodes", "[scp]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    // 3 nodes total: v0 (local), v1 (normal weight), v2 (zero weight).
    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    auto runScenario = [&](std::set<NodeID> const& zeroWeightNodes) {
        ZeroWeightTestNominationSCP nomSCP(v0NodeID, qSet, zeroWeightNodes);

        Slot slot(0, nomSCP.mSCP);
        NominationTestHandler nom(slot);

        Value v;
        v.emplace_back(uint8_t(42));
        nom.setLeaderElectionSeed(v);

        // Ensure that even with many more rounds than validators,
        // `updateRoundLeaders` always terminates and never picks a zero-weight
        // node as leader.
        int const maxRounds = 20;
        for (int i = 0; i < maxRounds; i++)
        {
            nom.setRoundNumber(i);
            nom.updateRoundLeaders();
        }

        return nom.getRoundLeaders();
    };

    SECTION("non-local zero-weight validator is excluded from round leaders")
    {
        // v2 simulates a LOW-quality validator with zero weight, mimicking
        // HerderSCPDriver::getNodeWeight behavior for LOW-quality nodes.
        auto const& leaders = runScenario({v2NodeID});
        REQUIRE(leaders.count(v0NodeID) == 1);
        REQUIRE(leaders.count(v1NodeID) == 1);
        REQUIRE(leaders.count(v2NodeID) == 0);
        REQUIRE(leaders.size() == 2);
    }

    SECTION("local zero-weight validator is excluded from round leaders")
    {
        auto const& leaders = runScenario({v0NodeID});
        REQUIRE(leaders.count(v0NodeID) == 0);
        REQUIRE(leaders.count(v1NodeID) == 1);
        REQUIRE(leaders.count(v2NodeID) == 1);
        REQUIRE(leaders.size() == 2);
    }
}

// A test driver whose weight function ignores `isLocalNode`, mimicking
// HerderSCPDriver's application-specific weights. Under such weights every node
// computes the same weight for every validator (including itself), so the
// ahead-of-time leader schedule is identical across nodes.
class UniformWeightNominationSCP : public TestNominationSCP
{
  public:
    UniformWeightNominationSCP(NodeID const& nodeID,
                               SCPQuorumSet const& qSetLocal)
        : TestNominationSCP(nodeID, qSetLocal)
    {
    }

    uint64
    getNodeWeight(NodeID const&, SCPQuorumSet const&, bool) const override
    {
        // Same weight for every node, independent of isLocalNode.
        return UINT64_MAX / 2;
    }
};

// This is the linchpin for direct leader flooding: the leaders predicted ahead
// of time by NominationProtocol::computeLeaderSchedule must equal the leaders
// SCP actually elects during live nomination when fed the same seed. Steps 2/3
// (overlay push + TX routing) rely on the prediction targeting the real
// proposer.
TEST_CASE("computeLeaderSchedule matches live leader election", "[scp]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);

    std::vector<NodeID> nodeIDs = {v0NodeID, v1NodeID, v2NodeID, v3NodeID,
                                   v4NodeID};

    SCPQuorumSet qSet;
    qSet.threshold = 3;
    for (auto const& id : nodeIDs)
    {
        qSet.validators.push_back(id);
    }

    // Arbitrary, but fixed, leader-election seed for the slot.
    Value seed;
    for (uint8_t b : std::vector<uint8_t>{1, 2, 3, 4, 5})
    {
        seed.emplace_back(b);
    }

    uint64 const slotIndex = 7;

    auto normalizedQSet = [&](NodeID const& localID) {
        SCPQuorumSet q = qSet;
        normalizeQSet(q, &localID); // excludes self
        return q;
    };

    SECTION("predicted full schedule equals live accumulated leaders")
    {
        TestNominationSCP nomSCP(v0NodeID, qSet);
        Slot slot(slotIndex, nomSCP.mSCP);
        NominationTestHandler nom(slot);
        nom.setLeaderElectionSeed(seed);

        // Drive the live path exactly as nominate() does (bump round, then
        // recompute leaders) until the leader set saturates.
        nom.setRoundNumber(0);
        size_t lastSize = 0;
        int guard = 0;
        do
        {
            lastSize = nom.getRoundLeaders().size();
            nom.bumpRoundAndUpdateLeaders();
        } while (nom.getRoundLeaders().size() != lastSize && ++guard < 1000);

        std::set<NodeID> const actual = nom.getRoundLeaders();
        REQUIRE(!actual.empty());

        // A count larger than the number of nodes saturates the schedule; it is
        // capped internally by the number of weighted nodes.
        auto schedule = NominationProtocol::computeLeaderSchedule(
            nomSCP, seed, slotIndex, nodeIDs.size() + 1,
            normalizedQSet(v0NodeID), v0NodeID);

        std::set<NodeID> const predicted(schedule.begin(), schedule.end());
        // The ordered schedule must contain no duplicates.
        REQUIRE(schedule.size() == predicted.size());
        REQUIRE(predicted == actual);
    }

    SECTION("top-K prefix equals the first leaders elected live")
    {
        TestNominationSCP nomSCP(v0NodeID, qSet);
        Slot slot(slotIndex, nomSCP.mSCP);
        NominationTestHandler nom(slot);
        nom.setLeaderElectionSeed(seed);

        // The first productive round's leaders are what a node uses with no
        // nomination timeout -- the schedule prefix must match them exactly.
        nom.setRoundNumber(0);
        nom.bumpRoundAndUpdateLeaders();
        std::set<NodeID> const firstRound = nom.getRoundLeaders();
        REQUIRE(!firstRound.empty());

        auto schedule = NominationProtocol::computeLeaderSchedule(
            nomSCP, seed, slotIndex, firstRound.size(),
            normalizedQSet(v0NodeID), v0NodeID);
        REQUIRE(schedule.size() == firstRound.size());
        std::set<NodeID> const prefix(schedule.begin(), schedule.end());
        REQUIRE(prefix == firstRound);
    }

    SECTION("ordering is deterministic for repeated calls")
    {
        TestNominationSCP nomSCP(v0NodeID, qSet);
        auto a = NominationProtocol::computeLeaderSchedule(
            nomSCP, seed, slotIndex, nodeIDs.size(), normalizedQSet(v0NodeID),
            v0NodeID);
        auto b = NominationProtocol::computeLeaderSchedule(
            nomSCP, seed, slotIndex, nodeIDs.size(), normalizedQSet(v0NodeID),
            v0NodeID);
        REQUIRE(a == b);
        REQUIRE(!a.empty());
    }

    SECTION("schedule is identical across nodes under uniform weights")
    {
        // With weights independent of isLocalNode (as in production's
        // application-specific weights), every node computes the same ordered
        // schedule.
        UniformWeightNominationSCP scp0(v0NodeID, qSet);
        UniformWeightNominationSCP scp1(v1NodeID, qSet);

        auto s0 = NominationProtocol::computeLeaderSchedule(
            scp0, seed, slotIndex, nodeIDs.size(), normalizedQSet(v0NodeID),
            v0NodeID);
        auto s1 = NominationProtocol::computeLeaderSchedule(
            scp1, seed, slotIndex, nodeIDs.size(), normalizedQSet(v1NodeID),
            v1NodeID);

        REQUIRE(!s0.empty());
        REQUIRE(s0 == s1);
    }
}

TEST_CASE("later nomination leader uses supplied empty fallback", "[scp]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    std::vector<NodeID> nodeIDs = {v0NodeID, v1NodeID, v2NodeID};
    SCPQuorumSet qSet;
    qSet.threshold = 2;
    for (auto const& id : nodeIDs)
    {
        qSet.validators.push_back(id);
    }

    Value seed = {1, 2, 3, 4, 5};
    uint64_t const slotIndex = 11;

    UniformWeightNominationSCP scheduleDriver(v0NodeID, qSet);
    SCPQuorumSet normalized = qSet;
    normalizeQSet(normalized, &v0NodeID);
    auto const schedule = NominationProtocol::computeLeaderSchedule(
        scheduleDriver, seed, slotIndex, nodeIDs.size(), normalized, v0NodeID);
    REQUIRE(schedule.size() == nodeIDs.size());

    // Model a node outside the first two pre-routed candidate leaders. Herder
    // supplies this node a canonical empty-set value instead of making it
    // construct a full proposal.
    NodeID const& laterLeader = schedule[2];
    REQUIRE(laterLeader != schedule[0]);
    REQUIRE(laterLeader != schedule[1]);

    auto nomSCP =
        std::make_shared<UniformWeightNominationSCP>(laterLeader, qSet);
    auto slot = std::make_shared<Slot>(slotIndex, nomSCP->mSCP);
    NominationTestHandler nomination(*slot);

    Value previousValue = {9};
    Value emptyFallback = {0xee};
    auto wrappedFallback = nomSCP->wrapValue(emptyFallback);

    bool nominatedFallback = false;
    for (size_t attempt = 0; attempt < 20 && !nominatedFallback; ++attempt)
    {
        nomination.nominate(wrappedFallback, previousValue, seed,
                            /*timedout=*/attempt != 0);
        auto const* envelope = nomination.getLastMessageSend();
        if (envelope)
        {
            auto const& votes = envelope->statement.pledges.nominate().votes;
            nominatedFallback =
                std::find(votes.begin(), votes.end(), emptyFallback) !=
                votes.end();
        }
    }

    // Once nomination timeouts advance to this later leader, it votes for the
    // supplied empty value exactly as it would any normal local proposal.
    REQUIRE(nominatedFallback);
}

// this test case display statistical information on the priority function used
// by nomination
TEST_CASE("nomination weight stats", "[scp][!hide]")
{
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);
    SIMULATION_CREATE_NODE(6);

    std::vector<NodeID> nodeIDs = {v0NodeID, v1NodeID, v2NodeID, v3NodeID,
                                   v4NodeID, v5NodeID, v6NodeID};

    int const totalSlots = 1000;
    int const maxRoundPerSlot = 5; // 5 -> 15 seconds
    int const totalRounds = totalSlots * maxRoundPerSlot;

    auto runTests = [&](SCPQuorumSet qSet) {
        std::map<NodeID, int> wins;

        TestNominationSCP nomSCP(v0NodeID, qSet);
        for (int s = 0; s < totalSlots; s++)
        {
            Slot slot(s, nomSCP.mSCP);

            NominationTestHandler nom(slot);

            Value v;
            v.emplace_back(uint8_t(s)); // anything will do as a value

            nom.setLeaderElectionSeed(v);

            for (int i = 0; i < maxRoundPerSlot; i++)
            {
                nom.setRoundNumber(i);
                nom.updateRoundLeaders();
                auto& l = nom.getRoundLeaders();
                REQUIRE(!l.empty());
                for (auto& w : l)
                {
                    wins[w]++;
                }
            }
        }
        return wins;
    };

    SECTION("flat quorum")
    {
        auto flatTest = [&](int threshold, int total) {
            auto qSet = makeQSet(nodeIDs, threshold, total, 0);

            auto wins = runTests(qSet);

            for (auto& w : wins)
            {
                double stats = double(w.second * 100) / double(totalRounds);
                CLOG_INFO(SCP, "Got {}{}", stats,
                          ((v0NodeID == w.first) ? " LOCAL" : ""));
            }
        };

        SECTION("3 out of 5")
        {
            flatTest(3, 5);
        }
        SECTION("2 out of 3")
        {
            flatTest(2, 3);
        }
    }
    SECTION("hierarchy")
    {
        auto qSet = makeQSet(nodeIDs, 3, 4, 0);

        auto qSetInner = makeQSet(nodeIDs, 2, 3, 4);
        qSet.innerSets.emplace_back(qSetInner);

        auto wins = runTests(qSet);

        for (auto& w : wins)
        {
            double stats = double(w.second * 100) / double(totalRounds);
            bool outer =
                std::any_of(qSet.validators.begin(), qSet.validators.end(),
                            [&](auto const& k) { return k == w.first; });
            CLOG_INFO(SCP, "Got {} {}", stats,
                      ((v0NodeID == w.first) ? "LOCAL"
                                             : (outer ? "OUTER" : "INNER")));
        }
    }
}

TEST_CASE("nomination two nodes win stats", "[scp][!hide]")
{
    int const nbRoundsForStats = 9;
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);
    SIMULATION_CREATE_NODE(6);

    std::vector<NodeID> nodeIDs = {v0NodeID, v1NodeID, v2NodeID, v3NodeID,
                                   v4NodeID, v5NodeID, v6NodeID};

    int const totalIter = 10000;

    // maxRounds is the number of rounds to evaluate in a row
    // the iteration is considered successful if validators could
    // agree on what to nominate before maxRounds is reached
    auto nominationLeaders = [&](int maxRounds, SCPQuorumSet qSetNode0,
                                 SCPQuorumSet qSetNode1) {
        TestNominationSCP nomSCP0(v0NodeID, qSetNode0);
        TestNominationSCP nomSCP1(v1NodeID, qSetNode1);

        int tot = 0;
        for (int g = 0; g < totalIter; g++)
        {
            Slot slot0(0, nomSCP0.mSCP);
            NominationTestHandler nom0(slot0);

            Slot slot1(0, nomSCP1.mSCP);
            NominationTestHandler nom1(slot1);

            Value v;
            v.emplace_back(uint8_t(g));
            nom0.setLeaderElectionSeed(v);
            nom1.setLeaderElectionSeed(v);

            bool res = true;

            bool v0Voted = false;
            bool v1Voted = false;

            int r = 0;
            do
            {
                nom0.setRoundNumber(r);
                nom1.setRoundNumber(r);
                nom0.updateRoundLeaders();
                nom1.updateRoundLeaders();

                auto& l0 = nom0.getRoundLeaders();
                REQUIRE(!l0.empty());
                auto& l1 = nom1.getRoundLeaders();
                REQUIRE(!l1.empty());

                auto updateVoted = [&](auto const& id, auto const& leaders,
                                       bool& voted) {
                    if (!voted)
                    {
                        voted = std::find(leaders.begin(), leaders.end(), id) !=
                                leaders.end();
                    }
                };

                // checks if id voted (any past round, including this one)
                // AND id is a leader this round
                auto findNode = [](auto const& id, bool idVoted,
                                   auto const& otherLeaders) {
                    bool r = (idVoted && std::find(otherLeaders.begin(),
                                                   otherLeaders.end(),
                                                   id) != otherLeaders.end());
                    return r;
                };

                updateVoted(v0NodeID, l0, v0Voted);
                updateVoted(v1NodeID, l1, v1Voted);

                // either both vote for v0 or both vote for v1
                res = findNode(v0NodeID, v0Voted, l1);
                res = res || findNode(v1NodeID, v1Voted, l0);
            } while (!res && ++r < maxRounds);

            tot += res ? 1 : 0;
        }
        return tot;
    };

    SECTION("flat quorum")
    {
        // test using the same quorum on all nodes
        auto flatTest = [&](int threshold, int total) {
            auto qSet = makeQSet(nodeIDs, threshold, total, 0);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet, qSet);
                double stats = double(tot * 100) / double(totalIter);
                CLOG_INFO(SCP, "Win rate for {} : {}", maxRounds, stats);
            }
        };

        SECTION("3 out of 5")
        {
            flatTest(3, 5);
        }
        SECTION("2 out of 3")
        {
            flatTest(2, 3);
        }
    }

    SECTION("hierarchy")
    {
        SECTION("same qSet")
        {
            auto qSet = makeQSet(nodeIDs, 3, 4, 0);

            auto qSetInner = makeQSet(nodeIDs, 2, 3, 4);
            qSet.innerSets.emplace_back(qSetInner);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet, qSet);
                double stats = double(tot * 100) / double(totalIter);
                CLOG_INFO(SCP, "Win rate for {} : {}", maxRounds, stats);
            }
        }
        SECTION("v0 is inner node for v1")
        {
            auto qSet0 = makeQSet(nodeIDs, 3, 4, 0);
            auto qSetInner0 = makeQSet(nodeIDs, 2, 3, 4);
            qSet0.innerSets.emplace_back(qSetInner0);

            // v1's qset: we move v0 into the inner set
            auto qSet1 = qSet0;
            REQUIRE(qSet1.validators[0] == v0NodeID);
            std::swap(qSet1.validators[0], qSet1.innerSets[0].validators[0]);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet0, qSet1);
                double stats = double(tot * 100) / double(totalIter);
                CLOG_INFO(SCP, "Win rate for {} : {}", maxRounds, stats);
            }
        }
    }
}
}
