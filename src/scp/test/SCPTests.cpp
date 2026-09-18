// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0
#include "util/asio.h"

#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "ledger/NetworkConfig.h"
#include "scp/LocalNode.h"
#include "scp/SCP.h"
#include "scp/Slot.h"
#include "simulation/Simulation.h"
#include "test/Catch2.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"
#include "xdrpp/printer.h"
#include <fmt/format.h>

// General convention in this file is that numbers in parenthesis
// refer to the rule number in the related protocol from the white paper
// For example (2) in the ballot protocol refers to:
// If phi = PREPARE and m lets v confirm new higher ballots prepared,
// then raise h to the highest such ballot and set z = h.x

namespace stellar
{

// Tx set download timeout value for tests.
constexpr std::chrono::milliseconds TX_SET_TIMEOUT{5000};

// UNDER and OVER are below and above TX_SET_TIMEOUT for tests that want to
// control whether a tx set download has timed out or not.
constexpr std::chrono::milliseconds UNDER_TX_SET_TIMEOUT{1000};
constexpr std::chrono::milliseconds OVER_TX_SET_TIMEOUT{6000};

class TestSCP : public SCPDriver
{
  public:
    SCP mSCP;
    uint32_t mInitialBallotTimeoutMS = 1000;
    uint32_t mIncrementBallotTimeoutMS = 1000;

    TestSCP(NodeID const& nodeID, SCPQuorumSet const& qSetLocal,
            bool isValidator = true)
        : mSCP(*this, nodeID, isValidator, qSetLocal)
    {
        mPriorityLookup = [&](NodeID const& n) {
            return (n == mSCP.getLocalNodeID()) ? 1000 : 1;
        };

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
        if (mValidateValueOverride)
        {
            return mValidateValueOverride(slotIndex, value);
        }
        // If we're tracking download wait time for this value, it's awaiting
        // download
        if (mDownloadWaitTimes.find(value) != mDownloadWaitTimes.end())
        {
            return SCPDriver::kStructurallyValidValue;
        }
        return SCPDriver::kFullyValidatedValue;
    }

    void
    ballotDidHearFromQuorum(uint64 slotIndex, SCPBallot const& ballot) override
    {
        mHeardFromQuorums[slotIndex].push_back(ballot);
    }

    void
    valueExternalized(uint64 slotIndex, Value const& value) override
    {
        if (mExternalizedValues.find(slotIndex) != mExternalizedValues.end())
        {
            throw std::out_of_range("Value already externalized");
        }
        mExternalizedValues[slotIndex] = value;
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

    std::optional<std::chrono::milliseconds>
    getTxSetDownloadWaitTime(Value const& v) const override
    {
        auto it = mDownloadWaitTimes.find(v);
        if (it != mDownloadWaitTimes.end())
        {
            return it->second;
        }
        return std::nullopt;
    }

    std::chrono::milliseconds
    getTxSetDownloadTimeout() const override
    {
        return TX_SET_TIMEOUT;
    }

    Value
    makeEmptyTxSetValueFromValue(Value const& value) const override
    {
        // Create an empty-tx-set value by prefixing with "EMPTY:"
        Value emptyTxSetValue;
        emptyTxSetValue.resize(6 + value.size());
        emptyTxSetValue[0] = 'E';
        emptyTxSetValue[1] = 'M';
        emptyTxSetValue[2] = 'P';
        emptyTxSetValue[3] = 'T';
        emptyTxSetValue[4] = 'Y';
        emptyTxSetValue[5] = ':';
        std::copy(value.begin(), value.end(), emptyTxSetValue.begin() + 6);
        return emptyTxSetValue;
    }

    bool
    isEmptyTxSetValue(Value const& v) const override
    {
        // Check if value starts with "EMPTY:"
        if (v.size() < 6)
        {
            return false;
        }
        return v[0] == 'E' && v[1] == 'M' && v[2] == 'P' && v[3] == 'T' &&
               v[4] == 'Y' && v[5] == ':';
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

    void
    emitEnvelope(SCPEnvelope const& envelope) override
    {
        mEnvs.push_back(envelope);
    }

    // used to test BallotProtocol and bypass nomination
    bool
    bumpState(uint64 slotIndex, Value const& v)
    {
        return mSCP.getSlot(slotIndex, true)->bumpState(v, true);
    }

    // only used by nomination protocol

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

    // override the internal hashing scheme in order to make tests
    // more predictable.
    uint64
    computeHashNode(uint64 slotIndex, Value const& prev, bool isPriority,
                    int32_t roundNumber, NodeID const& nodeID) override
    {
        uint64 res;
        if (isPriority)
        {
            res = mPriorityLookup(nodeID);
        }
        else
        {
            res = 0;
        }
        return res;
    }

    // override the value hashing, to make tests more predictable.

    std::function<uint64(NodeID const&)> mPriorityLookup;
    std::function<SCPDriver::ValidationLevel(uint64, Value const&)>
        mValidateValueOverride;

    std::map<Hash, SCPQuorumSetPtr> mQuorumSets;
    std::vector<SCPEnvelope> mEnvs;
    std::map<uint64, Value> mExternalizedValues;
    std::map<uint64, std::vector<SCPBallot>> mHeardFromQuorums;

    // Empty-tx-set value support
    std::map<Value, std::chrono::milliseconds> mDownloadWaitTimes;

    struct TimerData
    {
        std::chrono::milliseconds mAbsoluteTimeout;
        std::function<void()> mCallback;
    };
    std::map<int, TimerData> mTimers;
    std::chrono::milliseconds mCurrentTimerOffset{0};

    void
    setupTimer(uint64 slotIndex, int timerID, std::chrono::milliseconds timeout,
               std::function<void()> cb) override
    {
        mTimers[timerID] =
            TimerData{mCurrentTimerOffset +
                          (cb ? timeout : std::chrono::milliseconds::zero()),
                      cb};
    }

    void
    stopTimer(uint64 slotIndex, int timerID) override
    {
        mTimers.erase(timerID);
    }

    TimerData
    getBallotProtocolTimer()
    {
        return mTimers[Slot::BALLOT_PROTOCOL_TIMER];
    }

    // pretends the time moved forward
    std::chrono::milliseconds
    bumpTimerOffset()
    {
        // increase by more than the maximum timeout
        mCurrentTimerOffset += std::chrono::hours(5);
        return mCurrentTimerOffset;
    }

    // returns true if a ballot protocol timer exists (in the past or future)
    bool
    hasBallotTimer()
    {
        return !!getBallotProtocolTimer().mCallback;
    }

    // returns true if the ballot protocol timer is scheduled in the future
    // false if scheduled in the past
    // this method is mostly used to verify that the timer *would* have fired
    bool
    hasBallotTimerUpcoming()
    {
        // timer must be scheduled in the past or future
        REQUIRE(hasBallotTimer());
        return mCurrentTimerOffset < getBallotProtocolTimer().mAbsoluteTimeout;
    }

    SCP::EnvelopeState
    receiveEnvelope(SCPEnvelope const& envelope)
    {
        auto envW = mSCP.getDriver().wrapEnvelope(envelope);
        return mSCP.receiveEnvelope(envW);
    }

    Slot&
    getSlot(uint64 index)
    {
        return *mSCP.getSlot(index, false);
    }

    std::vector<SCPEnvelope>
    getEntireState(uint64 index)
    {
        auto v = mSCP.getSlot(index, false)->getEntireCurrentState();
        return v;
    }

    SCPEnvelope
    getCurrentEnvelope(uint64 index, NodeID const& id)
    {
        auto r = getEntireState(index);
        auto it = std::find_if(r.begin(), r.end(), [&](SCPEnvelope const& e) {
            return e.statement.nodeID == id;
        });
        if (it != r.end())
        {
            return *it;
        }
        throw std::runtime_error("not found");
    }

    // Helper methods for empty-tx-set value testing
    void
    startDownload(Value const& v, std::chrono::milliseconds waitTime)
    {
        mDownloadWaitTimes[v] = waitTime;
    }

    void
    clearDownload(Value const& v)
    {
        mDownloadWaitTimes.erase(v);
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

namespace
{
// x < y < z < zz
// k can be anything
Value xValue, yValue, zValue, zzValue, kValue;

void
setupValues()
{
    std::vector<Value> v;
    std::string d =
        fmt::format("SEED_VALUE_DATA_{}", getGlobalRandomEngine()());
    for (int i = 0; i < 4; i++)
    {
        auto h = sha256(fmt::format("{}/{}", d, i));
        v.emplace_back(xdr::xdr_to_opaque(h));
    }
    std::sort(v.begin(), v.end());
    xValue = v[0];
    yValue = v[1];
    zValue = v[2];
    zzValue = v[3];

    // kValue is independent
    auto kHash = sha256(d);
    kValue = xdr::xdr_to_opaque(kHash);
}

SCPEnvelope
makeEnvelope(SecretKey const& secretKey, uint64 slotIndex,
             SCPStatement const& statement)
{
    SCPEnvelope envelope;
    envelope.statement = statement;
    envelope.statement.nodeID = secretKey.getPublicKey();
    envelope.statement.slotIndex = slotIndex;

    envelope.signature = secretKey.sign(xdr::xdr_to_opaque(envelope.statement));

    return envelope;
}

SCPEnvelope
makeExternalize(SecretKey const& secretKey, Hash const& qSetHash,
                uint64 slotIndex, SCPBallot const& commitBallot, uint32 nH)
{
    SCPStatement st;
    st.pledges.type(SCP_ST_EXTERNALIZE);
    auto& ext = st.pledges.externalize();
    ext.commit = commitBallot;
    ext.nH = nH;
    ext.commitQuorumSetHash = qSetHash;

    return makeEnvelope(secretKey, slotIndex, st);
}

SCPEnvelope
makeConfirm(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
            uint32 prepareCounter, SCPBallot const& b, uint32 nC, uint32 nH)
{
    SCPStatement st;
    st.pledges.type(SCP_ST_CONFIRM);
    auto& con = st.pledges.confirm();
    con.ballot = b;
    con.nPrepared = prepareCounter;
    con.nCommit = nC;
    con.nH = nH;
    con.quorumSetHash = qSetHash;

    return makeEnvelope(secretKey, slotIndex, st);
}

SCPEnvelope
makePrepare(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
            SCPBallot const& ballot, SCPBallot* prepared = nullptr,
            uint32 nC = 0, uint32 nH = 0, SCPBallot* preparedPrime = nullptr)
{
    SCPStatement st;
    st.pledges.type(SCP_ST_PREPARE);
    auto& p = st.pledges.prepare();
    p.ballot = ballot;
    p.quorumSetHash = qSetHash;
    if (prepared)
    {
        p.prepared.activate() = *prepared;
    }

    p.nC = nC;
    p.nH = nH;

    if (preparedPrime)
    {
        p.preparedPrime.activate() = *preparedPrime;
    }

    return makeEnvelope(secretKey, slotIndex, st);
}

SCPEnvelope
makeNominate(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
             std::vector<Value> votes, std::vector<Value> accepted)
{
    std::sort(votes.begin(), votes.end());
    std::sort(accepted.begin(), accepted.end());

    SCPStatement st;
    st.pledges.type(SCP_ST_NOMINATE);
    auto& nom = st.pledges.nominate();
    nom.quorumSetHash = qSetHash;
    for (auto const& v : votes)
    {
        nom.votes.emplace_back(v);
    }
    for (auto const& a : accepted)
    {
        nom.accepted.emplace_back(a);
    }
    return makeEnvelope(secretKey, slotIndex, st);
}

void
verifyPrepare(SCPEnvelope const& actual, SecretKey const& secretKey,
              Hash const& qSetHash, uint64 slotIndex, SCPBallot const& ballot,
              SCPBallot* prepared = nullptr, uint32 nC = 0, uint32 nH = 0,
              SCPBallot* preparedPrime = nullptr)
{
    auto exp = makePrepare(secretKey, qSetHash, slotIndex, ballot, prepared, nC,
                           nH, preparedPrime);
    REQUIRE(exp.statement == actual.statement);
}

void
verifyConfirm(SCPEnvelope const& actual, SecretKey const& secretKey,
              Hash const& qSetHash, uint64 slotIndex, uint32 nPrepared,
              SCPBallot const& b, uint32 nC, uint32 nH)
{
    auto exp =
        makeConfirm(secretKey, qSetHash, slotIndex, nPrepared, b, nC, nH);
    REQUIRE(exp.statement == actual.statement);
}

void
verifyExternalize(SCPEnvelope const& actual, SecretKey const& secretKey,
                  Hash const& qSetHash, uint64 slotIndex,
                  SCPBallot const& commit, uint32 nH)
{
    auto exp = makeExternalize(secretKey, qSetHash, slotIndex, commit, nH);
    REQUIRE(exp.statement == actual.statement);
}

// Simulate xValue being only structurally valid (e.g., due to an invalid tx
// set)
SCPDriver::ValidationLevel
xValueStructurallyValidValidationOverride(uint64, Value const& v)
{
    if (v == xValue)
    {
        return SCPDriver::kStructurallyValidValue;
    }
    return SCPDriver::kFullyValidatedValue;
}

// Returns kInvalidValue for xValue This simulates a value being invalid for
// some reason *other* than a bad tx set (e.g. bad close time or signature).
SCPDriver::ValidationLevel
xValueNonTxSetInvalidValidationOverride(uint64, Value const& v)
{
    if (v == xValue)
    {
        return SCPDriver::kInvalidValue;
    }
    return SCPDriver::kFullyValidatedValue;
}

// Returns kMaybeValidNotCurrentValue for xValue, simulating that the value is
// NOT for the current ledger.
SCPDriver::ValidationLevel
xValueNotCurrentLedgerOverride(uint64, Value const& v)
{
    return SCPDriver::kMaybeValidNotCurrentValue;
}
} // namespace

TEST_CASE("vblocking and quorum", "[scp]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);

    SCPQuorumSet qSet;
    qSet.threshold = 3;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);

    std::vector<NodeID> nodeSet;
    nodeSet.push_back(v0NodeID);

    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == false);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == false);

    nodeSet.push_back(v2NodeID);

    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == false);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);

    nodeSet.push_back(v3NodeID);
    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == true);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);

    nodeSet.push_back(v1NodeID);
    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == true);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);
}

TEST_CASE("v blocking distance", "[scp]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);
    SIMULATION_CREATE_NODE(6);
    SIMULATION_CREATE_NODE(7);

    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    auto check = [&](SCPQuorumSet const& qSetCheck, std::set<NodeID> const& s,
                     size_t expected) {
        auto r = LocalNode::findClosestVBlocking(qSetCheck, s, nullptr);
        REQUIRE(expected == r.size());
    };

    std::set<NodeID> good;
    good.insert(v0NodeID);

    // already v-blocking
    check(qSet, good, 0);

    good.insert(v1NodeID);
    // either v0 or v1
    check(qSet, good, 1);

    good.insert(v2NodeID);
    // any 2 of v0..v2
    check(qSet, good, 2);

    SCPQuorumSet qSubSet1;
    qSubSet1.threshold = 1;
    qSubSet1.validators.push_back(v3NodeID);
    qSubSet1.validators.push_back(v4NodeID);
    qSubSet1.validators.push_back(v5NodeID);
    qSet.innerSets.push_back(qSubSet1);

    good.insert(v3NodeID);
    // any 3 of v0..v3
    check(qSet, good, 3);

    good.insert(v4NodeID);
    // v0..v2
    check(qSet, good, 3);

    qSet.threshold = 1;
    // v0..v4
    check(qSet, good, 5);

    good.insert(v5NodeID);
    // v0..v5
    check(qSet, good, 6);

    SCPQuorumSet qSubSet2;
    qSubSet2.threshold = 2;
    qSubSet2.validators.push_back(v6NodeID);
    qSubSet2.validators.push_back(v7NodeID);

    qSet.innerSets.push_back(qSubSet2);
    // v0..v5
    check(qSet, good, 6);

    good.insert(v6NodeID);
    // v0..v5
    check(qSet, good, 6);

    good.insert(v7NodeID);
    // v0..v5 and one of 6,7
    check(qSet, good, 7);

    qSet.threshold = 4;
    // v6, v7
    check(qSet, good, 2);

    qSet.threshold = 3;
    // v0..v2
    check(qSet, good, 3);

    qSet.threshold = 2;
    // v0..v2 and one of v6,v7
    check(qSet, good, 4);
}

typedef std::function<SCPEnvelope(SecretKey const& sk)> genEnvelope;

using namespace std::placeholders;

static genEnvelope
makePrepareGen(Hash const& qSetHash, SCPBallot const& ballot,
               SCPBallot* prepared = nullptr, uint32 nC = 0, uint32 nH = 0,
               SCPBallot* preparedPrime = nullptr)
{
    return std::bind(makePrepare, _1, std::cref(qSetHash), 0, std::cref(ballot),
                     prepared, nC, nH, preparedPrime);
}

static genEnvelope
makeConfirmGen(Hash const& qSetHash, uint32 prepareCounter, SCPBallot const& b,
               uint32 nC, uint32 nH)
{
    return std::bind(makeConfirm, _1, std::cref(qSetHash), 0, prepareCounter,
                     std::cref(b), nC, nH);
}

static genEnvelope
makeExternalizeGen(Hash const& qSetHash, SCPBallot const& commitBallot,
                   uint32 nH)
{
    return std::bind(makeExternalize, _1, std::cref(qSetHash), 0,
                     std::cref(commitBallot), nH);
}

// Testing matrix that covers interesting min/max values for each timeout
// parameter
static void
testTimeouts(TestSCP& scp, std::function<void(TestSCP&)> f)
{
    SECTION("minimum values")
    {
        scp.mInitialBallotTimeoutMS =
            MinimumSorobanNetworkConfig::BALLOT_TIMEOUT_INITIAL_MILLISECONDS;
        scp.mIncrementBallotTimeoutMS =
            MinimumSorobanNetworkConfig::BALLOT_TIMEOUT_INCREMENT_MILLISECONDS;
        f(scp);
    }

    SECTION("initial values")
    {
        scp.mInitialBallotTimeoutMS =
            InitialSorobanNetworkConfig::BALLOT_TIMEOUT_INITIAL_MILLISECONDS;
        scp.mIncrementBallotTimeoutMS =
            InitialSorobanNetworkConfig::BALLOT_TIMEOUT_INCREMENT_MILLISECONDS;
        f(scp);
    }

    SECTION("maximum values")
    {
        scp.mInitialBallotTimeoutMS =
            MaximumSorobanNetworkConfig::BALLOT_TIMEOUT_INITIAL_MILLISECONDS;
        scp.mIncrementBallotTimeoutMS =
            MaximumSorobanNetworkConfig::BALLOT_TIMEOUT_INCREMENT_MILLISECONDS;
        f(scp);
    }
}

TEST_CASE("ballot protocol core5", "[scp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);

    // we need 5 nodes to avoid sharing various thresholds:
    // v-blocking set size: 2
    // threshold: 4 = 3 + self or 4 others
    SCPQuorumSet qSet;
    qSet.threshold = 4;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);
    qSet.validators.push_back(v4NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);

    auto test = [&](TestSCP& scp) {
        scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));
        uint256 qSetHash0 = scp.mSCP.getLocalNode()->getQuorumSetHash();

        REQUIRE(xValue < yValue);
        REQUIRE(yValue < zValue);
        REQUIRE(zValue < zzValue);

        CLOG_INFO(SCP, "");
        CLOG_INFO(SCP, "BEGIN TEST");

        auto recvVBlockingChecks = [&](genEnvelope gen, bool withChecks) {
            SCPEnvelope e1 = gen(v1SecretKey);
            SCPEnvelope e2 = gen(v2SecretKey);

            scp.bumpTimerOffset();

            // nothing should happen with first message
            size_t i = scp.mEnvs.size();
            scp.receiveEnvelope(e1);
            if (withChecks)
            {
                REQUIRE(scp.mEnvs.size() == i);
            }
            i++;
            scp.receiveEnvelope(e2);
            if (withChecks)
            {
                REQUIRE(scp.mEnvs.size() == i);
            }
        };

        auto recvVBlocking = std::bind(recvVBlockingChecks, _1, true);

        auto recvQuorumChecksEx = [&](genEnvelope gen, bool withChecks,
                                      bool delayedQuorum, bool checkUpcoming) {
            SCPEnvelope e1 = gen(v1SecretKey);
            SCPEnvelope e2 = gen(v2SecretKey);
            SCPEnvelope e3 = gen(v3SecretKey);
            SCPEnvelope e4 = gen(v4SecretKey);

            scp.bumpTimerOffset();

            scp.receiveEnvelope(e1);
            scp.receiveEnvelope(e2);
            size_t i = scp.mEnvs.size() + 1;
            scp.receiveEnvelope(e3);
            if (withChecks && !delayedQuorum)
            {
                REQUIRE(scp.mEnvs.size() == i);
            }
            if (checkUpcoming && !delayedQuorum)
            {
                REQUIRE(scp.hasBallotTimerUpcoming());
            }
            // nothing happens with an extra vote (unless we're in
            // delayedQuorum)
            scp.receiveEnvelope(e4);
            if (withChecks && delayedQuorum)
            {
                REQUIRE(scp.mEnvs.size() == i);
            }
            if (checkUpcoming && delayedQuorum)
            {
                REQUIRE(scp.hasBallotTimerUpcoming());
            }
        };
        // doesn't check timers
        auto recvQuorumChecks =
            std::bind(recvQuorumChecksEx, _1, _2, _3, false);
        // checks enabled, no delayed quorum
        auto recvQuorumEx = std::bind(recvQuorumChecksEx, _1, true, false, _2);
        // checks enabled, no delayed quorum, no check timers
        auto recvQuorum = std::bind(recvQuorumEx, _1, false);

        auto nodesAllPledgeToCommit = [&]() {
            SCPBallot b(1, xValue);
            SCPEnvelope prepare1 = makePrepare(v1SecretKey, qSetHash, 0, b);
            SCPEnvelope prepare2 = makePrepare(v2SecretKey, qSetHash, 0, b);
            SCPEnvelope prepare3 = makePrepare(v3SecretKey, qSetHash, 0, b);
            SCPEnvelope prepare4 = makePrepare(v4SecretKey, qSetHash, 0, b);

            REQUIRE(scp.bumpState(0, xValue));
            REQUIRE(scp.mEnvs.size() == 1);

            verifyPrepare(scp.mEnvs[0], v0SecretKey, qSetHash0, 0, b);

            scp.receiveEnvelope(prepare1);
            REQUIRE(scp.mEnvs.size() == 1);
            REQUIRE(scp.mHeardFromQuorums[0].size() == 0);

            scp.receiveEnvelope(prepare2);
            REQUIRE(scp.mEnvs.size() == 1);
            REQUIRE(scp.mHeardFromQuorums[0].size() == 0);

            scp.receiveEnvelope(prepare3);
            REQUIRE(scp.mEnvs.size() == 2);
            REQUIRE(scp.mHeardFromQuorums[0].size() == 1);
            REQUIRE(scp.mHeardFromQuorums[0][0] == b);

            // We have a quorum including us

            verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, b, &b);

            scp.receiveEnvelope(prepare4);
            REQUIRE(scp.mEnvs.size() == 2);

            SCPEnvelope prepared1 =
                makePrepare(v1SecretKey, qSetHash, 0, b, &b);
            SCPEnvelope prepared2 =
                makePrepare(v2SecretKey, qSetHash, 0, b, &b);
            SCPEnvelope prepared3 =
                makePrepare(v3SecretKey, qSetHash, 0, b, &b);
            SCPEnvelope prepared4 =
                makePrepare(v4SecretKey, qSetHash, 0, b, &b);

            scp.receiveEnvelope(prepared4);
            scp.receiveEnvelope(prepared3);
            REQUIRE(scp.mEnvs.size() == 2);

            scp.receiveEnvelope(prepared2);
            REQUIRE(scp.mEnvs.size() == 3);

            // confirms prepared
            verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, b, &b,
                          b.counter, b.counter);

            // extra statement doesn't do anything
            scp.receiveEnvelope(prepared1);
            REQUIRE(scp.mEnvs.size() == 3);
        };

        SECTION("bumpState x")
        {
            REQUIRE(scp.bumpState(0, xValue));
            REQUIRE(scp.mEnvs.size() == 1);

            SCPBallot expectedBallot(1, xValue);

            verifyPrepare(scp.mEnvs[0], v0SecretKey, qSetHash0, 0,
                          expectedBallot);
        }

        SECTION("start <1,x>")
        {
            // no timer is set
            REQUIRE(!scp.hasBallotTimer());

            Value const& aValue = xValue;
            Value const& bValue = zValue;
            Value const& midValue = yValue;
            Value const& bigValue = zzValue;

            SCPBallot A1(1, aValue);
            SCPBallot B1(1, bValue);
            SCPBallot Mid1(1, midValue);
            SCPBallot Big1(1, bigValue);

            SCPBallot A2 = A1;
            A2.counter++;

            SCPBallot A3 = A2;
            A3.counter++;

            SCPBallot A4 = A3;
            A4.counter++;

            SCPBallot A5 = A4;
            A5.counter++;

            SCPBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

            SCPBallot B2 = B1;
            B2.counter++;

            SCPBallot B3 = B2;
            B3.counter++;

            SCPBallot Mid2 = Mid1;
            Mid2.counter++;

            SCPBallot Big2 = Big1;
            Big2.counter++;

            REQUIRE(scp.bumpState(0, aValue));
            REQUIRE(scp.mEnvs.size() == 1);
            REQUIRE(!scp.hasBallotTimer());

            SECTION("prepared A1")
            {
                recvQuorumEx(makePrepareGen(qSetHash, A1), true);

                REQUIRE(scp.mEnvs.size() == 2);
                verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &A1);

                SECTION("bump prepared A2")
                {
                    // bump to (2,a)

                    scp.bumpTimerOffset();
                    REQUIRE(scp.bumpState(0, aValue));
                    REQUIRE(scp.mEnvs.size() == 3);
                    verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, A2,
                                  &A1);
                    REQUIRE(!scp.hasBallotTimer());

                    recvQuorumEx(makePrepareGen(qSetHash, A2), true);
                    REQUIRE(scp.mEnvs.size() == 4);
                    verifyPrepare(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, A2,
                                  &A2);

                    SECTION("Confirm prepared A2")
                    {
                        recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                        REQUIRE(scp.mEnvs.size() == 5);
                        verifyPrepare(scp.mEnvs[4], v0SecretKey, qSetHash0, 0,
                                      A2, &A2, 2, 2);
                        REQUIRE(!scp.hasBallotTimerUpcoming());

                        SECTION("Accept commit")
                        {
                            SECTION("Quorum A2")
                            {
                                recvQuorum(
                                    makePrepareGen(qSetHash, A2, &A2, 2, 2));
                                REQUIRE(scp.mEnvs.size() == 6);
                                verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                              qSetHash0, 0, 2, A2, 2, 2);
                                REQUIRE(!scp.hasBallotTimerUpcoming());

                                SECTION("Quorum prepared A3")
                                {
                                    recvVBlocking(makePrepareGen(qSetHash, A3,
                                                                 &A2, 2, 2));
                                    REQUIRE(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 2, A3, 2, 2);
                                    REQUIRE(!scp.hasBallotTimer());

                                    recvQuorumEx(
                                        makePrepareGen(qSetHash, A3, &A2, 2, 2),
                                        true);
                                    REQUIRE(scp.mEnvs.size() == 8);
                                    verifyConfirm(scp.mEnvs[7], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 2);

                                    SECTION("Accept more commit A3")
                                    {
                                        recvQuorum(makePrepareGen(qSetHash, A3,
                                                                  &A3, 2, 3));
                                        REQUIRE(scp.mEnvs.size() == 9);
                                        verifyConfirm(scp.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, 3, A3, 2,
                                                      3);
                                        REQUIRE(!scp.hasBallotTimerUpcoming());

                                        REQUIRE(
                                            scp.mExternalizedValues.size() ==
                                            0);

                                        SECTION("Quorum externalize A3")
                                        {
                                            recvQuorum(makeConfirmGen(
                                                qSetHash, 3, A3, 2, 3));
                                            REQUIRE(scp.mEnvs.size() == 10);
                                            verifyExternalize(
                                                scp.mEnvs[9], v0SecretKey,
                                                qSetHash0, 0, A2, 3);
                                            REQUIRE(!scp.hasBallotTimer());

                                            REQUIRE(scp.mExternalizedValues
                                                        .size() == 1);
                                            REQUIRE(
                                                scp.mExternalizedValues[0] ==
                                                aValue);
                                        }
                                    }
                                    SECTION("v-blocking accept more A3")
                                    {
                                        SECTION("Confirm A3")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, A3, 2, 3));
                                            REQUIRE(scp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                scp.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, 3, A3, 2, 3);
                                            REQUIRE(
                                                !scp.hasBallotTimerUpcoming());
                                        }
                                        SECTION("Externalize A3")
                                        {
                                            recvVBlocking(makeExternalizeGen(
                                                qSetHash, A2, 3));
                                            REQUIRE(scp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                scp.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, UINT32_MAX, AInf,
                                                2, UINT32_MAX);
                                            REQUIRE(!scp.hasBallotTimer());
                                        }
                                        SECTION(
                                            "other nodes moved to c=A4 h=A5")
                                        {
                                            SECTION("Confirm A4..5")
                                            {
                                                recvVBlocking(makeConfirmGen(
                                                    qSetHash, 3, A5, 4, 5));
                                                REQUIRE(scp.mEnvs.size() == 9);
                                                verifyConfirm(
                                                    scp.mEnvs[8], v0SecretKey,
                                                    qSetHash0, 0, 3, A5, 4, 5);
                                                REQUIRE(!scp.hasBallotTimer());
                                            }
                                            SECTION("Externalize A4..5")
                                            {
                                                recvVBlocking(
                                                    makeExternalizeGen(qSetHash,
                                                                       A4, 5));
                                                REQUIRE(scp.mEnvs.size() == 9);
                                                verifyConfirm(
                                                    scp.mEnvs[8], v0SecretKey,
                                                    qSetHash0, 0, UINT32_MAX,
                                                    AInf, 4, UINT32_MAX);
                                                REQUIRE(!scp.hasBallotTimer());
                                            }
                                        }
                                    }
                                }
                                SECTION("v-blocking prepared A3")
                                {
                                    recvVBlocking(makePrepareGen(qSetHash, A3,
                                                                 &A3, 2, 2));
                                    REQUIRE(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 2);
                                    REQUIRE(!scp.hasBallotTimer());
                                }
                                SECTION("v-blocking prepared A3+B3")
                                {
                                    recvVBlocking(makePrepareGen(
                                        qSetHash, A3, &B3, 2, 2, &A3));
                                    REQUIRE(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 2);
                                    REQUIRE(!scp.hasBallotTimer());
                                }
                                SECTION("v-blocking confirm A3")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 3, A3, 2, 2));
                                    REQUIRE(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 2);
                                    REQUIRE(!scp.hasBallotTimer());
                                }
                                SECTION(
                                    "Hang - does not switch to B in CONFIRM")
                                {
                                    SECTION("Network EXTERNALIZE")
                                    {
                                        // externalize messages have a counter
                                        // at infinite
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, B2, 3));
                                        REQUIRE(scp.mEnvs.size() == 7);
                                        verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                      qSetHash0, 0, 2, AInf, 2,
                                                      2);
                                        REQUIRE(!scp.hasBallotTimer());

                                        // stuck
                                        recvQuorumChecks(
                                            makeExternalizeGen(qSetHash, B2, 3),
                                            false, false);
                                        REQUIRE(scp.mEnvs.size() == 7);
                                        REQUIRE(
                                            scp.mExternalizedValues.size() ==
                                            0);
                                        // timer scheduled as there is a quorum
                                        // with (2, *)
                                        REQUIRE(scp.hasBallotTimerUpcoming());
                                    }
                                    SECTION("Network CONFIRMS other ballot")
                                    {
                                        SECTION("at same counter")
                                        {
                                            // nothing should happen here, in
                                            // particular, node should not
                                            // attempt to switch 'p'
                                            recvQuorumChecks(
                                                makeConfirmGen(qSetHash, 3, B2,
                                                               2, 3),
                                                false, false);
                                            REQUIRE(scp.mEnvs.size() == 6);
                                            REQUIRE(scp.mExternalizedValues
                                                        .size() == 0);
                                            REQUIRE(
                                                !scp.hasBallotTimerUpcoming());
                                        }
                                        SECTION("at a different counter")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, B3, 3, 3));
                                            REQUIRE(scp.mEnvs.size() == 7);
                                            verifyConfirm(
                                                scp.mEnvs[6], v0SecretKey,
                                                qSetHash0, 0, 2, A3, 2, 2);
                                            REQUIRE(!scp.hasBallotTimer());

                                            recvQuorumChecks(
                                                makeConfirmGen(qSetHash, 3, B3,
                                                               3, 3),
                                                false, false);
                                            REQUIRE(scp.mEnvs.size() == 7);
                                            REQUIRE(scp.mExternalizedValues
                                                        .size() == 0);
                                            // timer scheduled as there is a
                                            // quorum with (3, *)
                                            REQUIRE(
                                                scp.hasBallotTimerUpcoming());
                                        }
                                    }
                                }
                            }
                            SECTION("v-blocking")
                            {
                                SECTION("CONFIRM")
                                {
                                    SECTION("CONFIRM A2")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 2, A2, 2, 2));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, 2, A2, 2,
                                                      2);
                                        REQUIRE(!scp.hasBallotTimerUpcoming());
                                    }
                                    SECTION("CONFIRM A3..4")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 4, A4, 3, 4));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, 4, A4, 3,
                                                      4);
                                        REQUIRE(!scp.hasBallotTimer());
                                    }
                                    SECTION("CONFIRM B2")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 2, B2, 2, 2));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, 2, B2, 2,
                                                      2);
                                        REQUIRE(!scp.hasBallotTimerUpcoming());
                                    }
                                }
                                SECTION("EXTERNALIZE")
                                {
                                    SECTION("EXTERNALIZE A2")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, A2, 2));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, UINT32_MAX,
                                                      AInf, 2, UINT32_MAX);
                                        REQUIRE(!scp.hasBallotTimer());
                                    }
                                    SECTION("EXTERNALIZE B2")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, B2, 2));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, UINT32_MAX,
                                                      BInf, 2, UINT32_MAX);
                                        REQUIRE(!scp.hasBallotTimer());
                                    }
                                }
                            }
                        }
                        SECTION("get conflicting prepared B")
                        {
                            SECTION("same counter")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, B2, &B2));
                                REQUIRE(scp.mEnvs.size() == 6);
                                verifyPrepare(scp.mEnvs[5], v0SecretKey,
                                              qSetHash0, 0, A2, &B2, 0, 2, &A2);
                                REQUIRE(!scp.hasBallotTimerUpcoming());

                                recvQuorum(
                                    makePrepareGen(qSetHash, B2, &B2, 2, 2));
                                REQUIRE(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 2, B2, 2, 2);
                                REQUIRE(!scp.hasBallotTimerUpcoming());
                            }
                            SECTION("higher counter")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, B3, &B2, 2, 2));
                                REQUIRE(scp.mEnvs.size() == 6);
                                verifyPrepare(scp.mEnvs[5], v0SecretKey,
                                              qSetHash0, 0, A3, &B2, 0, 2, &A2);
                                REQUIRE(!scp.hasBallotTimer());

                                recvQuorumChecksEx(
                                    makePrepareGen(qSetHash, B3, &B2, 2, 2),
                                    true, true, true);
                                REQUIRE(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, B3, 2, 2);
                            }
                            SECTION("higher counter mixed")
                            {
                                recvVBlocking(makePrepareGen(qSetHash, A3, &B3,
                                                             0, 2, &A2));
                                REQUIRE(scp.mEnvs.size() == 6);
                                // h still A2
                                // v-blocking
                                //     prepared B3 -> p = B3, p'=A2 (1)
                                //     counter 3, b = A3 (9) (same value than h)
                                // c = 0 (1)
                                verifyPrepare(scp.mEnvs[5], v0SecretKey,
                                              qSetHash0, 0, A3, &B3, 0, 2, &A2);
                                recvQuorumEx(makePrepareGen(qSetHash, A3, &B3,
                                                            0, 2, &A2),
                                             true);
                                // p=B3, p'=A3 (1)
                                // computed_h = B3
                                // b = computed_h = B3 (8)
                                // h = computed_h = B3 (2)
                                // c = h = B3 (3)
                                REQUIRE(scp.mEnvs.size() == 7);
                                verifyPrepare(scp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, B3, &B3, 3, 3, &A3);
                            }
                        }
                    }
                    SECTION("Confirm prepared mixed")
                    {
                        // a few nodes prepared B2
                        recvVBlocking(
                            makePrepareGen(qSetHash, B2, &B2, 0, 0, &A2));
                        REQUIRE(scp.mEnvs.size() == 5);
                        verifyPrepare(scp.mEnvs[4], v0SecretKey, qSetHash0, 0,
                                      A2, &B2, 0, 0, &A2);
                        REQUIRE(!scp.hasBallotTimerUpcoming());

                        SECTION("mixed A2")
                        {
                            // causes h=A2
                            // but c = 0, as p >!~ h
                            scp.bumpTimerOffset();
                            scp.receiveEnvelope(
                                makePrepare(v3SecretKey, qSetHash, 0, A2, &A2));

                            REQUIRE(scp.mEnvs.size() == 6);
                            verifyPrepare(scp.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A2, &B2, 0, 2, &A2);
                            REQUIRE(!scp.hasBallotTimerUpcoming());

                            scp.bumpTimerOffset();
                            scp.receiveEnvelope(
                                makePrepare(v4SecretKey, qSetHash, 0, A2, &A2));

                            REQUIRE(scp.mEnvs.size() == 6);
                            REQUIRE(!scp.hasBallotTimerUpcoming());
                        }
                        SECTION("mixed B2")
                        {
                            // causes h=B2, c=B2
                            scp.bumpTimerOffset();
                            scp.receiveEnvelope(
                                makePrepare(v3SecretKey, qSetHash, 0, B2, &B2));

                            REQUIRE(scp.mEnvs.size() == 6);
                            verifyPrepare(scp.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, B2, &B2, 2, 2, &A2);
                            REQUIRE(!scp.hasBallotTimerUpcoming());

                            scp.bumpTimerOffset();
                            scp.receiveEnvelope(
                                makePrepare(v4SecretKey, qSetHash, 0, B2, &B2));

                            REQUIRE(scp.mEnvs.size() == 6);
                            REQUIRE(!scp.hasBallotTimerUpcoming());
                        }
                    }
                }
                SECTION("switch prepared B1 from A1")
                {
                    // (p,p') = (B1, A1) [ from (A1, null) ]
                    recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
                    REQUIRE(scp.mEnvs.size() == 3);
                    verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, A1,
                                  &B1, 0, 0, &A1);
                    REQUIRE(!scp.hasBallotTimerUpcoming());

                    // v-blocking with n=2 -> bump n
                    recvVBlocking(makePrepareGen(qSetHash, B2));
                    REQUIRE(scp.mEnvs.size() == 4);
                    verifyPrepare(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, A2,
                                  &B1, 0, 0, &A1);

                    // move to (p,p') = (B2, A1) [update p from B1 -> B2]
                    recvVBlocking(makePrepareGen(qSetHash, B2, &B2));
                    REQUIRE(scp.mEnvs.size() == 5);
                    verifyPrepare(scp.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &B2, 0, 0, &A1);
                    REQUIRE(!scp.hasBallotTimer()); // no quorum (other nodes on
                                                    // (A,1))

                    SECTION("v-blocking switches to previous value of p")
                    {
                        // v-blocking with n=3 -> bump n
                        recvVBlocking(makePrepareGen(qSetHash, B3));
                        REQUIRE(scp.mEnvs.size() == 6);
                        verifyPrepare(scp.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      A3, &B2, 0, 0, &A1);
                        REQUIRE(!scp.hasBallotTimer()); // no quorum (other
                                                        // nodes on (A,1))

                        // vBlocking set says "B1" is prepared - but we already
                        // have p=B2
                        recvVBlockingChecks(makePrepareGen(qSetHash, B3, &B1),
                                            false);
                        REQUIRE(scp.mEnvs.size() == 6);
                        REQUIRE(!scp.hasBallotTimer());
                    }
                    SECTION("switch p' to Mid2")
                    {
                        // (p,p') = (B2, Mid2)
                        recvVBlocking(
                            makePrepareGen(qSetHash, B2, &B2, 0, 0, &Mid2));
                        REQUIRE(scp.mEnvs.size() == 6);
                        verifyPrepare(scp.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      A2, &B2, 0, 0, &Mid2);
                        REQUIRE(!scp.hasBallotTimer());
                    }
                    SECTION("switch again Big2")
                    {
                        // both p and p' get updated
                        // (p,p') = (Big2, B2)
                        recvVBlocking(
                            makePrepareGen(qSetHash, B2, &Big2, 0, 0, &B2));
                        REQUIRE(scp.mEnvs.size() == 6);
                        verifyPrepare(scp.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      A2, &Big2, 0, 0, &B2);
                        REQUIRE(!scp.hasBallotTimer());
                    }
                }
                SECTION("switch prepare B1")
                {
                    recvQuorumChecks(makePrepareGen(qSetHash, B1), true, true);
                    REQUIRE(scp.mEnvs.size() == 3);
                    verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, A1,
                                  &B1, 0, 0, &A1);
                    REQUIRE(!scp.hasBallotTimerUpcoming());
                }
                SECTION("prepare higher counter (v-blocking)")
                {
                    recvVBlocking(makePrepareGen(qSetHash, B2));
                    REQUIRE(scp.mEnvs.size() == 3);
                    verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, A2,
                                  &A1);
                    REQUIRE(!scp.hasBallotTimer());

                    // more timeout from vBlocking set
                    recvVBlocking(makePrepareGen(qSetHash, B3));
                    REQUIRE(scp.mEnvs.size() == 4);
                    verifyPrepare(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, A3,
                                  &A1);
                    REQUIRE(!scp.hasBallotTimer());
                }
            }
            SECTION("prepared B (v-blocking)")
            {
                recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
                REQUIRE(scp.mEnvs.size() == 2);
                verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
                REQUIRE(!scp.hasBallotTimer());
            }
            SECTION("prepare B (quorum)")
            {
                recvQuorumChecksEx(makePrepareGen(qSetHash, B1), true, true,
                                   true);
                REQUIRE(scp.mEnvs.size() == 2);
                verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
            }
            SECTION("confirm (v-blocking)")
            {
                SECTION("via CONFIRM")
                {
                    scp.bumpTimerOffset();
                    scp.receiveEnvelope(
                        makeConfirm(v1SecretKey, qSetHash, 0, 3, A3, 3, 3));
                    scp.receiveEnvelope(
                        makeConfirm(v2SecretKey, qSetHash, 0, 4, A4, 2, 4));
                    REQUIRE(scp.mEnvs.size() == 2);
                    verifyConfirm(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, 3,
                                  A3, 3, 3);
                    REQUIRE(!scp.hasBallotTimer());
                }
                SECTION("via EXTERNALIZE")
                {
                    scp.receiveEnvelope(
                        makeExternalize(v1SecretKey, qSetHash, 0, A2, 4));
                    scp.receiveEnvelope(
                        makeExternalize(v2SecretKey, qSetHash, 0, A3, 5));
                    REQUIRE(scp.mEnvs.size() == 2);
                    verifyConfirm(scp.mEnvs[1], v0SecretKey, qSetHash0, 0,
                                  UINT32_MAX, AInf, 3, UINT32_MAX);
                    REQUIRE(!scp.hasBallotTimer());
                }
            }
        }

        // this is the same test suite than "start <1,x>" with the exception
        // that some transitions are not possible as x < z - so instead we
        // verify that nothing happens
        SECTION("start <1,z>")
        {
            // no timer is set
            REQUIRE(!scp.hasBallotTimer());

            Value const& aValue = zValue;
            Value const& bValue = xValue;

            SCPBallot A1(1, aValue);
            SCPBallot B1(1, bValue);

            SCPBallot A2 = A1;
            A2.counter++;

            SCPBallot A3 = A2;
            A3.counter++;

            SCPBallot A4 = A3;
            A4.counter++;

            SCPBallot A5 = A4;
            A5.counter++;

            SCPBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

            SCPBallot B2 = B1;
            B2.counter++;

            SCPBallot B3 = B2;
            B3.counter++;

            SCPBallot B4 = B3;
            B4.counter++;

            REQUIRE(scp.bumpState(0, aValue));
            REQUIRE(scp.mEnvs.size() == 1);
            REQUIRE(!scp.hasBallotTimer());

            SECTION("prepared A1")
            {
                recvQuorumEx(makePrepareGen(qSetHash, A1), true);

                REQUIRE(scp.mEnvs.size() == 2);
                verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &A1);

                SECTION("bump prepared A2")
                {
                    // bump to (2,a)

                    scp.bumpTimerOffset();
                    REQUIRE(scp.bumpState(0, aValue));
                    REQUIRE(scp.mEnvs.size() == 3);
                    verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, A2,
                                  &A1);
                    REQUIRE(!scp.hasBallotTimer());

                    recvQuorumEx(makePrepareGen(qSetHash, A2), true);
                    REQUIRE(scp.mEnvs.size() == 4);
                    verifyPrepare(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, A2,
                                  &A2);

                    SECTION("Confirm prepared A2")
                    {
                        recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                        REQUIRE(scp.mEnvs.size() == 5);
                        verifyPrepare(scp.mEnvs[4], v0SecretKey, qSetHash0, 0,
                                      A2, &A2, 2, 2);
                        REQUIRE(!scp.hasBallotTimerUpcoming());

                        SECTION("Accept commit")
                        {
                            SECTION("Quorum A2")
                            {
                                recvQuorum(
                                    makePrepareGen(qSetHash, A2, &A2, 2, 2));
                                REQUIRE(scp.mEnvs.size() == 6);
                                verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                              qSetHash0, 0, 2, A2, 2, 2);
                                REQUIRE(!scp.hasBallotTimerUpcoming());

                                SECTION("Quorum prepared A3")
                                {
                                    recvVBlocking(makePrepareGen(qSetHash, A3,
                                                                 &A2, 2, 2));
                                    REQUIRE(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 2, A3, 2, 2);
                                    REQUIRE(!scp.hasBallotTimer());

                                    recvQuorumEx(
                                        makePrepareGen(qSetHash, A3, &A2, 2, 2),
                                        true);
                                    REQUIRE(scp.mEnvs.size() == 8);
                                    verifyConfirm(scp.mEnvs[7], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 2);

                                    SECTION("Accept more commit A3")
                                    {
                                        recvQuorum(makePrepareGen(qSetHash, A3,
                                                                  &A3, 2, 3));
                                        REQUIRE(scp.mEnvs.size() == 9);
                                        verifyConfirm(scp.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, 3, A3, 2,
                                                      3);
                                        REQUIRE(!scp.hasBallotTimerUpcoming());

                                        REQUIRE(
                                            scp.mExternalizedValues.size() ==
                                            0);

                                        SECTION("Quorum externalize A3")
                                        {
                                            recvQuorum(makeConfirmGen(
                                                qSetHash, 3, A3, 2, 3));
                                            REQUIRE(scp.mEnvs.size() == 10);
                                            verifyExternalize(
                                                scp.mEnvs[9], v0SecretKey,
                                                qSetHash0, 0, A2, 3);
                                            REQUIRE(!scp.hasBallotTimer());

                                            REQUIRE(scp.mExternalizedValues
                                                        .size() == 1);
                                            REQUIRE(
                                                scp.mExternalizedValues[0] ==
                                                aValue);
                                        }
                                    }
                                    SECTION("v-blocking accept more A3")
                                    {
                                        SECTION("Confirm A3")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, A3, 2, 3));
                                            REQUIRE(scp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                scp.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, 3, A3, 2, 3);
                                            REQUIRE(
                                                !scp.hasBallotTimerUpcoming());
                                        }
                                        SECTION("Externalize A3")
                                        {
                                            recvVBlocking(makeExternalizeGen(
                                                qSetHash, A2, 3));
                                            REQUIRE(scp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                scp.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, UINT32_MAX, AInf,
                                                2, UINT32_MAX);
                                            REQUIRE(!scp.hasBallotTimer());
                                        }
                                        SECTION(
                                            "other nodes moved to c=A4 h=A5")
                                        {
                                            SECTION("Confirm A4..5")
                                            {
                                                recvVBlocking(makeConfirmGen(
                                                    qSetHash, 3, A5, 4, 5));
                                                REQUIRE(scp.mEnvs.size() == 9);
                                                verifyConfirm(
                                                    scp.mEnvs[8], v0SecretKey,
                                                    qSetHash0, 0, 3, A5, 4, 5);
                                                REQUIRE(!scp.hasBallotTimer());
                                            }
                                            SECTION("Externalize A4..5")
                                            {
                                                recvVBlocking(
                                                    makeExternalizeGen(qSetHash,
                                                                       A4, 5));
                                                REQUIRE(scp.mEnvs.size() == 9);
                                                verifyConfirm(
                                                    scp.mEnvs[8], v0SecretKey,
                                                    qSetHash0, 0, UINT32_MAX,
                                                    AInf, 4, UINT32_MAX);
                                                REQUIRE(!scp.hasBallotTimer());
                                            }
                                        }
                                    }
                                }
                                SECTION("v-blocking prepared A3")
                                {
                                    recvVBlocking(makePrepareGen(qSetHash, A3,
                                                                 &A3, 2, 2));
                                    REQUIRE(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 2);
                                    REQUIRE(!scp.hasBallotTimer());
                                }
                                SECTION("v-blocking prepared A3+B3")
                                {
                                    recvVBlocking(makePrepareGen(
                                        qSetHash, A3, &A3, 2, 2, &B3));
                                    REQUIRE(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 2);
                                    REQUIRE(!scp.hasBallotTimer());
                                }
                                SECTION("v-blocking confirm A3")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 3, A3, 2, 2));
                                    REQUIRE(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 2);
                                    REQUIRE(!scp.hasBallotTimer());
                                }
                                SECTION(
                                    "Hang - does not switch to B in CONFIRM")
                                {
                                    SECTION("Network EXTERNALIZE")
                                    {
                                        // externalize messages have a counter
                                        // at infinite
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, B2, 3));
                                        REQUIRE(scp.mEnvs.size() == 7);
                                        verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                                      qSetHash0, 0, 2, AInf, 2,
                                                      2);
                                        REQUIRE(!scp.hasBallotTimer());

                                        // stuck
                                        recvQuorumChecks(
                                            makeExternalizeGen(qSetHash, B2, 3),
                                            false, false);
                                        REQUIRE(scp.mEnvs.size() == 7);
                                        REQUIRE(
                                            scp.mExternalizedValues.size() ==
                                            0);
                                        // timer scheduled as there is a quorum
                                        // with (inf, *)
                                        REQUIRE(scp.hasBallotTimerUpcoming());
                                    }
                                    SECTION("Network CONFIRMS other ballot")
                                    {
                                        SECTION("at same counter")
                                        {
                                            // nothing should happen here, in
                                            // particular, node should not
                                            // attempt to switch 'p'
                                            recvQuorumChecks(
                                                makeConfirmGen(qSetHash, 3, B2,
                                                               2, 3),
                                                false, false);
                                            REQUIRE(scp.mEnvs.size() == 6);
                                            REQUIRE(scp.mExternalizedValues
                                                        .size() == 0);
                                            REQUIRE(
                                                !scp.hasBallotTimerUpcoming());
                                        }
                                        SECTION("at a different counter")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, B3, 3, 3));
                                            REQUIRE(scp.mEnvs.size() == 7);
                                            verifyConfirm(
                                                scp.mEnvs[6], v0SecretKey,
                                                qSetHash0, 0, 2, A3, 2, 2);
                                            REQUIRE(!scp.hasBallotTimer());

                                            recvQuorumChecks(
                                                makeConfirmGen(qSetHash, 3, B3,
                                                               3, 3),
                                                false, false);
                                            REQUIRE(scp.mEnvs.size() == 7);
                                            REQUIRE(scp.mExternalizedValues
                                                        .size() == 0);
                                            // timer scheduled as there is a
                                            // quorum with (3, *)
                                            REQUIRE(
                                                scp.hasBallotTimerUpcoming());
                                        }
                                    }
                                }
                            }
                            SECTION("v-blocking")
                            {
                                SECTION("CONFIRM")
                                {
                                    SECTION("CONFIRM A2")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 2, A2, 2, 2));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, 2, A2, 2,
                                                      2);
                                        REQUIRE(!scp.hasBallotTimerUpcoming());
                                    }
                                    SECTION("CONFIRM A3..4")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 4, A4, 3, 4));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, 4, A4, 3,
                                                      4);
                                        REQUIRE(!scp.hasBallotTimer());
                                    }
                                    SECTION("CONFIRM B2")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 2, B2, 2, 2));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, 2, B2, 2,
                                                      2);
                                        REQUIRE(!scp.hasBallotTimerUpcoming());
                                    }
                                }
                                SECTION("EXTERNALIZE")
                                {
                                    SECTION("EXTERNALIZE A2")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, A2, 2));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, UINT32_MAX,
                                                      AInf, 2, UINT32_MAX);
                                        REQUIRE(!scp.hasBallotTimer());
                                    }
                                    SECTION("EXTERNALIZE B2")
                                    {
                                        // can switch to B2 with externalize
                                        // (higher counter)
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, B2, 2));
                                        REQUIRE(scp.mEnvs.size() == 6);
                                        verifyConfirm(scp.mEnvs[5], v0SecretKey,
                                                      qSetHash0, 0, UINT32_MAX,
                                                      BInf, 2, UINT32_MAX);
                                        REQUIRE(!scp.hasBallotTimer());
                                    }
                                }
                            }
                        }
                        SECTION("get conflicting prepared B")
                        {
                            SECTION("same counter")
                            {
                                // messages are ignored as B2 < A2
                                recvQuorumChecks(
                                    makePrepareGen(qSetHash, B2, &B2), false,
                                    false);
                                REQUIRE(scp.mEnvs.size() == 5);
                                REQUIRE(!scp.hasBallotTimerUpcoming());
                            }
                            SECTION("higher counter")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, B3, &B2, 2, 2));
                                REQUIRE(scp.mEnvs.size() == 6);
                                // A2 > B2 -> p = A2, p'=B2
                                verifyPrepare(scp.mEnvs[5], v0SecretKey,
                                              qSetHash0, 0, A3, &A2, 2, 2, &B2);
                                REQUIRE(!scp.hasBallotTimer());

                                // node is trying to commit A2=<2,y> but rest
                                // of its quorum is trying to commit B2
                                // we end up with a delayed quorum
                                recvQuorumChecksEx(
                                    makePrepareGen(qSetHash, B3, &B2, 2, 2),
                                    true, true, true);
                                REQUIRE(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, B3, 2, 2);
                            }
                            SECTION("higher counter mixed")
                            {
                                recvVBlocking(makePrepareGen(qSetHash, A3, &B3,
                                                             0, 2, &A2));
                                REQUIRE(scp.mEnvs.size() == 6);
                                // h still A2
                                // v-blocking
                                //     prepared B3 -> p = B3, p'=A2 (1)
                                //     counter 3, b = A3 (9) (same value than h)
                                // c = 0 (1)
                                verifyPrepare(scp.mEnvs[5], v0SecretKey,
                                              qSetHash0, 0, A3, &B3, 0, 2, &A2);
                                recvQuorumEx(makePrepareGen(qSetHash, A3, &B3,
                                                            0, 2, &A2),
                                             true);
                                // p=A3, p'=B3 (1)
                                // computed_h = B3 (2) z = B - cannot update b
                                REQUIRE(scp.mEnvs.size() == 7);
                                verifyPrepare(scp.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, A3, &A3, 0, 2, &B3);
                                // timeout, bump to B4
                                REQUIRE(scp.hasBallotTimerUpcoming());
                                auto cb =
                                    scp.getBallotProtocolTimer().mCallback;
                                cb();
                                // computed_h = B3
                                // h = B3 (2)
                                // c = 0
                                REQUIRE(scp.mEnvs.size() == 8);
                                verifyPrepare(scp.mEnvs[7], v0SecretKey,
                                              qSetHash0, 0, B4, &A3, 0, 3, &B3);
                            }
                        }
                    }
                    SECTION("Confirm prepared mixed")
                    {
                        // a few nodes prepared B2
                        recvVBlocking(
                            makePrepareGen(qSetHash, A2, &A2, 0, 0, &B2));
                        REQUIRE(scp.mEnvs.size() == 5);
                        verifyPrepare(scp.mEnvs[4], v0SecretKey, qSetHash0, 0,
                                      A2, &A2, 0, 0, &B2);
                        REQUIRE(!scp.hasBallotTimerUpcoming());

                        SECTION("mixed A2")
                        {
                            // causes h=A2, c=A2
                            scp.bumpTimerOffset();
                            scp.receiveEnvelope(
                                makePrepare(v3SecretKey, qSetHash, 0, A2, &A2));

                            REQUIRE(scp.mEnvs.size() == 6);
                            verifyPrepare(scp.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A2, &A2, 2, 2, &B2);
                            REQUIRE(!scp.hasBallotTimerUpcoming());

                            scp.bumpTimerOffset();
                            scp.receiveEnvelope(
                                makePrepare(v4SecretKey, qSetHash, 0, A2, &A2));

                            REQUIRE(scp.mEnvs.size() == 6);
                            REQUIRE(!scp.hasBallotTimerUpcoming());
                        }
                        SECTION("mixed B2")
                        {
                            // causes computed_h=B2 ~ not set as h ~!= b
                            // -> noop
                            scp.bumpTimerOffset();
                            scp.receiveEnvelope(
                                makePrepare(v3SecretKey, qSetHash, 0, A2, &B2));

                            REQUIRE(scp.mEnvs.size() == 5);
                            REQUIRE(!scp.hasBallotTimerUpcoming());

                            scp.bumpTimerOffset();
                            scp.receiveEnvelope(
                                makePrepare(v4SecretKey, qSetHash, 0, B2, &B2));

                            REQUIRE(scp.mEnvs.size() == 5);
                            REQUIRE(!scp.hasBallotTimerUpcoming());
                        }
                    }
                }
                SECTION("switch prepared B1 from A1")
                {
                    // can't switch to B1
                    recvQuorumChecks(makePrepareGen(qSetHash, B1, &B1), false,
                                     false);
                    REQUIRE(scp.mEnvs.size() == 2);
                    REQUIRE(!scp.hasBallotTimerUpcoming());
                }
                SECTION("switch prepare B1")
                {
                    // doesn't switch as B1 < A1
                    recvQuorumChecks(makePrepareGen(qSetHash, B1), false,
                                     false);
                    REQUIRE(scp.mEnvs.size() == 2);
                    REQUIRE(!scp.hasBallotTimerUpcoming());
                }
                SECTION("prepare higher counter (v-blocking)")
                {
                    recvVBlocking(makePrepareGen(qSetHash, B2));
                    REQUIRE(scp.mEnvs.size() == 3);
                    verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, A2,
                                  &A1);
                    REQUIRE(!scp.hasBallotTimer());

                    // more timeout from vBlocking set
                    recvVBlocking(makePrepareGen(qSetHash, B3));
                    REQUIRE(scp.mEnvs.size() == 4);
                    verifyPrepare(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, A3,
                                  &A1);
                    REQUIRE(!scp.hasBallotTimer());
                }
            }
            SECTION("prepared B (v-blocking)")
            {
                recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
                REQUIRE(scp.mEnvs.size() == 2);
                verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
                REQUIRE(!scp.hasBallotTimer());
            }
            SECTION("prepare B (quorum)")
            {
                recvQuorumChecksEx(makePrepareGen(qSetHash, B1), true, true,
                                   true);
                REQUIRE(scp.mEnvs.size() == 2);
                verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
            }
            SECTION("confirm (v-blocking)")
            {
                SECTION("via CONFIRM")
                {
                    scp.bumpTimerOffset();
                    scp.receiveEnvelope(
                        makeConfirm(v1SecretKey, qSetHash, 0, 3, A3, 3, 3));
                    scp.receiveEnvelope(
                        makeConfirm(v2SecretKey, qSetHash, 0, 4, A4, 2, 4));
                    REQUIRE(scp.mEnvs.size() == 2);
                    verifyConfirm(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, 3,
                                  A3, 3, 3);
                    REQUIRE(!scp.hasBallotTimer());
                }
                SECTION("via EXTERNALIZE")
                {
                    scp.receiveEnvelope(
                        makeExternalize(v1SecretKey, qSetHash, 0, A2, 4));
                    scp.receiveEnvelope(
                        makeExternalize(v2SecretKey, qSetHash, 0, A3, 5));
                    REQUIRE(scp.mEnvs.size() == 2);
                    verifyConfirm(scp.mEnvs[1], v0SecretKey, qSetHash0, 0,
                                  UINT32_MAX, AInf, 3, UINT32_MAX);
                    REQUIRE(!scp.hasBallotTimer());
                }
            }
        }

        // this is the same test suite than "start <1,x>" but only keeping
        // the transitions that are observable when starting from empty
        SECTION("start from pristine")
        {
            REQUIRE(scp.mEnvs.empty());
            scp.receiveEnvelope(
                makePrepare(v1SecretKey, qSetHash, 0, SCPBallot(1, xValue)));
            REQUIRE(scp.mEnvs.size() == 1);
            verifyPrepare(scp.mEnvs[0], v0SecretKey, qSetHash0, 0,
                          SCPBallot(1, xValue));
        }

        SECTION("normal round (1,x)")
        {
            nodesAllPledgeToCommit();
            REQUIRE(scp.mEnvs.size() == 3);

            SCPBallot b(1, xValue);

            // bunch of prepare messages with "commit b"
            SCPEnvelope preparedC1 = makePrepare(v1SecretKey, qSetHash, 0, b,
                                                 &b, b.counter, b.counter);
            SCPEnvelope preparedC2 = makePrepare(v2SecretKey, qSetHash, 0, b,
                                                 &b, b.counter, b.counter);
            SCPEnvelope preparedC3 = makePrepare(v3SecretKey, qSetHash, 0, b,
                                                 &b, b.counter, b.counter);
            SCPEnvelope preparedC4 = makePrepare(v4SecretKey, qSetHash, 0, b,
                                                 &b, b.counter, b.counter);

            // those should not trigger anything just yet
            scp.receiveEnvelope(preparedC1);
            scp.receiveEnvelope(preparedC2);
            REQUIRE(scp.mEnvs.size() == 3);

            // this should cause the node to accept 'commit b' (quorum)
            // and therefore send a "CONFIRM" message
            scp.receiveEnvelope(preparedC3);
            REQUIRE(scp.mEnvs.size() == 4);

            verifyConfirm(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, 1, b,
                          b.counter, b.counter);

            // bunch of confirm messages
            SCPEnvelope confirm1 = makeConfirm(
                v1SecretKey, qSetHash, 0, b.counter, b, b.counter, b.counter);
            SCPEnvelope confirm2 = makeConfirm(
                v2SecretKey, qSetHash, 0, b.counter, b, b.counter, b.counter);
            SCPEnvelope confirm3 = makeConfirm(
                v3SecretKey, qSetHash, 0, b.counter, b, b.counter, b.counter);
            SCPEnvelope confirm4 = makeConfirm(
                v4SecretKey, qSetHash, 0, b.counter, b, b.counter, b.counter);

            // those should not trigger anything just yet
            scp.receiveEnvelope(confirm1);
            scp.receiveEnvelope(confirm2);
            REQUIRE(scp.mEnvs.size() == 4);

            scp.receiveEnvelope(confirm3);
            // this causes our node to
            // externalize (confirm commit c)
            REQUIRE(scp.mEnvs.size() == 5);

            // The slot should have externalized the value
            REQUIRE(scp.mExternalizedValues.size() == 1);
            REQUIRE(scp.mExternalizedValues[0] == xValue);

            verifyExternalize(scp.mEnvs[4], v0SecretKey, qSetHash0, 0, b,
                              b.counter);

            // extra vote should not do anything
            scp.receiveEnvelope(confirm4);
            REQUIRE(scp.mEnvs.size() == 5);
            REQUIRE(scp.mExternalizedValues.size() == 1);

            // duplicate should just no-op
            scp.receiveEnvelope(confirm2);
            REQUIRE(scp.mEnvs.size() == 5);
            REQUIRE(scp.mExternalizedValues.size() == 1);

            SECTION("bumpToBallot prevented once committed")
            {
                SCPBallot b2;
                SECTION("bumpToBallot prevented once committed (by value)")
                {
                    b2 = SCPBallot(1, zValue);
                }
                SECTION("bumpToBallot prevented once committed (by counter)")
                {
                    b2 = SCPBallot(2, xValue);
                }
                SECTION("bumpToBallot prevented once committed (by value and "
                        "counter)")
                {
                    b2 = SCPBallot(2, zValue);
                }

                SCPEnvelope confirm1b2, confirm2b2, confirm3b2, confirm4b2;
                confirm1b2 = makeConfirm(v1SecretKey, qSetHash, 0, b2.counter,
                                         b2, b2.counter, b2.counter);
                confirm2b2 = makeConfirm(v2SecretKey, qSetHash, 0, b2.counter,
                                         b2, b2.counter, b2.counter);
                confirm3b2 = makeConfirm(v3SecretKey, qSetHash, 0, b2.counter,
                                         b2, b2.counter, b2.counter);
                confirm4b2 = makeConfirm(v4SecretKey, qSetHash, 0, b2.counter,
                                         b2, b2.counter, b2.counter);

                scp.receiveEnvelope(confirm1b2);
                scp.receiveEnvelope(confirm2b2);
                scp.receiveEnvelope(confirm3b2);
                scp.receiveEnvelope(confirm4b2);
                REQUIRE(scp.mEnvs.size() == 5);
                REQUIRE(scp.mExternalizedValues.size() == 1);
            }
        }

        SECTION("range check")
        {
            nodesAllPledgeToCommit();
            REQUIRE(scp.mEnvs.size() == 3);

            SCPBallot b(1, xValue);

            // bunch of prepare messages with "commit b"
            SCPEnvelope preparedC1 = makePrepare(v1SecretKey, qSetHash, 0, b,
                                                 &b, b.counter, b.counter);
            SCPEnvelope preparedC2 = makePrepare(v2SecretKey, qSetHash, 0, b,
                                                 &b, b.counter, b.counter);
            SCPEnvelope preparedC3 = makePrepare(v3SecretKey, qSetHash, 0, b,
                                                 &b, b.counter, b.counter);
            SCPEnvelope preparedC4 = makePrepare(v4SecretKey, qSetHash, 0, b,
                                                 &b, b.counter, b.counter);

            // those should not trigger anything just yet
            scp.receiveEnvelope(preparedC1);
            scp.receiveEnvelope(preparedC2);
            REQUIRE(scp.mEnvs.size() == 3);

            // this should cause the node to accept 'commit b' (quorum)
            // and therefore send a "CONFIRM" message
            scp.receiveEnvelope(preparedC3);
            REQUIRE(scp.mEnvs.size() == 4);

            verifyConfirm(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, 1, b,
                          b.counter, b.counter);

            // bunch of confirm messages with different ranges
            SCPBallot b5(5, xValue);
            SCPEnvelope confirm1 = makeConfirm(v1SecretKey, qSetHash, 0, 4,
                                               SCPBallot(4, xValue), 2, 4);
            SCPEnvelope confirm2 = makeConfirm(v2SecretKey, qSetHash, 0, 6,
                                               SCPBallot(6, xValue), 2, 6);
            SCPEnvelope confirm3 = makeConfirm(v3SecretKey, qSetHash, 0, 5,
                                               SCPBallot(5, xValue), 3, 5);
            SCPEnvelope confirm4 = makeConfirm(v4SecretKey, qSetHash, 0, 6,
                                               SCPBallot(6, xValue), 3, 6);

            // this should not trigger anything just yet
            scp.receiveEnvelope(confirm1);

            // v-blocking
            //   * b gets bumped to (4,x)
            //   * p gets bumped to (4,x)
            //   * (c,h) gets bumped to (2,4)
            scp.receiveEnvelope(confirm2);
            REQUIRE(scp.mEnvs.size() == 5);
            verifyConfirm(scp.mEnvs[4], v0SecretKey, qSetHash0, 0, 4,
                          SCPBallot(4, xValue), 2, 4);

            // this causes to externalize
            // range is [3,4]
            scp.receiveEnvelope(confirm4);
            REQUIRE(scp.mEnvs.size() == 6);

            // The slot should have externalized the value
            REQUIRE(scp.mExternalizedValues.size() == 1);
            REQUIRE(scp.mExternalizedValues[0] == xValue);

            verifyExternalize(scp.mEnvs[5], v0SecretKey, qSetHash0, 0,
                              SCPBallot(3, xValue), 4);
        }

        SECTION("timeout when h is set -> stay locked on h")
        {
            SCPBallot bx(1, xValue);
            REQUIRE(scp.bumpState(0, xValue));
            REQUIRE(scp.mEnvs.size() == 1);

            // v-blocking -> prepared
            // quorum -> confirm prepared
            recvQuorum(makePrepareGen(qSetHash, bx, &bx));
            REQUIRE(scp.mEnvs.size() == 3);
            verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, bx, &bx,
                          bx.counter, bx.counter);

            // now, see if we can timeout and move to a different value
            REQUIRE(scp.bumpState(0, yValue));
            REQUIRE(scp.mEnvs.size() == 4);
            SCPBallot newbx(2, xValue);
            verifyPrepare(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, newbx, &bx,
                          bx.counter, bx.counter);
        }
        SECTION("timeout when h exists but can't be set -> vote for h")
        {
            // start with (1,y)
            SCPBallot by(1, yValue);
            REQUIRE(scp.bumpState(0, yValue));
            REQUIRE(scp.mEnvs.size() == 1);

            SCPBallot bx(1, xValue);
            // but quorum goes with (1,x)
            // v-blocking -> prepared
            recvVBlocking(makePrepareGen(qSetHash, bx, &bx));
            REQUIRE(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, by, &bx);
            // quorum -> confirm prepared (no-op as b > h)
            recvQuorumChecks(makePrepareGen(qSetHash, bx, &bx), false, false);
            REQUIRE(scp.mEnvs.size() == 2);

            REQUIRE(scp.bumpState(0, yValue));
            REQUIRE(scp.mEnvs.size() == 3);
            SCPBallot newbx(2, xValue);
            // on timeout:
            // * we should move to the quorum's h value
            // * c can't be set yet as b > h
            verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, newbx, &bx,
                          0, bx.counter);
        }

        SECTION("timeout from multiple nodes")
        {
            REQUIRE(scp.bumpState(0, xValue));

            SCPBallot x1(1, xValue);

            REQUIRE(scp.mEnvs.size() == 1);
            verifyPrepare(scp.mEnvs[0], v0SecretKey, qSetHash0, 0, x1);

            recvQuorum(makePrepareGen(qSetHash, x1));
            // quorum -> prepared (1,x)
            REQUIRE(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, x1, &x1);

            SCPBallot x2(2, xValue);
            // timeout from local node
            REQUIRE(scp.bumpState(0, xValue));
            // prepares (2,x)
            REQUIRE(scp.mEnvs.size() == 3);
            verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, x2, &x1);

            recvQuorum(makePrepareGen(qSetHash, x1, &x1));
            // quorum -> set nH=1
            REQUIRE(scp.mEnvs.size() == 4);
            verifyPrepare(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, x2, &x1, 0,
                          1);
            REQUIRE(scp.mEnvs.size() == 4);

            recvVBlocking(makePrepareGen(qSetHash, x2, &x2, 1, 1));
            // v-blocking prepared (2,x) -> prepared (2,x)
            REQUIRE(scp.mEnvs.size() == 5);
            verifyPrepare(scp.mEnvs[4], v0SecretKey, qSetHash0, 0, x2, &x2, 0,
                          1);

            recvQuorum(makePrepareGen(qSetHash, x2, &x2, 1, 1));
            // quorum (including us) confirms (2,x) prepared -> set h=c=x2
            // we also get extra message: a quorum not including us confirms
            // (1,x) prepared
            //  -> we confirm c=h=x1
            REQUIRE(scp.mEnvs.size() == 7);
            verifyPrepare(scp.mEnvs[5], v0SecretKey, qSetHash0, 0, x2, &x2, 2,
                          2);
            verifyConfirm(scp.mEnvs[6], v0SecretKey, qSetHash0, 0, 2, x2, 1, 1);
        }

        SECTION("timeout after prepare, receive old messages to prepare")
        {
            REQUIRE(scp.bumpState(0, xValue));

            SCPBallot x1(1, xValue);

            REQUIRE(scp.mEnvs.size() == 1);
            verifyPrepare(scp.mEnvs[0], v0SecretKey, qSetHash0, 0, x1);

            scp.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, x1));
            scp.receiveEnvelope(makePrepare(v2SecretKey, qSetHash, 0, x1));
            scp.receiveEnvelope(makePrepare(v3SecretKey, qSetHash, 0, x1));

            // quorum -> prepared (1,x)
            REQUIRE(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, x1, &x1);

            SCPBallot x2(2, xValue);
            // timeout from local node
            REQUIRE(scp.bumpState(0, xValue));
            // prepares (2,x)
            REQUIRE(scp.mEnvs.size() == 3);
            verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, x2, &x1);

            SCPBallot x3(3, xValue);
            // timeout again
            REQUIRE(scp.bumpState(0, xValue));
            // prepares (3,x)
            REQUIRE(scp.mEnvs.size() == 4);
            verifyPrepare(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, x3, &x1);

            // other nodes moved on with x2
            scp.receiveEnvelope(
                makePrepare(v1SecretKey, qSetHash, 0, x2, &x2, 1, 2));
            scp.receiveEnvelope(
                makePrepare(v2SecretKey, qSetHash, 0, x2, &x2, 1, 2));
            // v-blocking -> prepared x2
            REQUIRE(scp.mEnvs.size() == 5);
            verifyPrepare(scp.mEnvs[4], v0SecretKey, qSetHash0, 0, x3, &x2);

            scp.receiveEnvelope(
                makePrepare(v3SecretKey, qSetHash, 0, x2, &x2, 1, 2));
            // quorum -> set nH=2
            REQUIRE(scp.mEnvs.size() == 6);
            verifyPrepare(scp.mEnvs[5], v0SecretKey, qSetHash0, 0, x3, &x2, 0,
                          2);
        }

        SECTION("non validator watching the network")
        {
            SIMULATION_CREATE_NODE(NV);
            TestSCP scpNV(vNVSecretKey.getPublicKey(), qSet, false);
            scpNV.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));
            uint256 qSetHashNV = scpNV.mSCP.getLocalNode()->getQuorumSetHash();

            SCPBallot b(1, xValue);
            REQUIRE(scpNV.bumpState(0, xValue));
            REQUIRE(scpNV.mEnvs.size() == 0);
            verifyPrepare(scpNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey,
                          qSetHashNV, 0, b);
            auto ext1 = makeExternalize(v1SecretKey, qSetHash, 0, b, 1);
            auto ext2 = makeExternalize(v2SecretKey, qSetHash, 0, b, 1);
            auto ext3 = makeExternalize(v3SecretKey, qSetHash, 0, b, 1);
            auto ext4 = makeExternalize(v4SecretKey, qSetHash, 0, b, 1);
            scpNV.receiveEnvelope(ext1);
            scpNV.receiveEnvelope(ext2);
            scpNV.receiveEnvelope(ext3);
            REQUIRE(scpNV.mEnvs.size() == 0);
            verifyConfirm(scpNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey,
                          qSetHashNV, 0, UINT32_MAX,
                          SCPBallot(UINT32_MAX, xValue), 1, UINT32_MAX);
            scpNV.receiveEnvelope(ext4);
            REQUIRE(scpNV.mEnvs.size() == 0);
            verifyExternalize(scpNV.getCurrentEnvelope(0, vNVNodeID),
                              vNVSecretKey, qSetHashNV, 0, b, UINT32_MAX);
            REQUIRE(scpNV.mExternalizedValues[0] == xValue);
        }

        SECTION("restore ballot protocol")
        {
            TestSCP scp2(v0SecretKey.getPublicKey(), qSet);
            scp2.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));
            SCPBallot b(2, xValue);
            SECTION("prepare")
            {
                scp2.mSCP.setStateFromEnvelope(
                    0, scp2.wrapEnvelope(
                           makePrepare(v0SecretKey, qSetHash0, 0, b)));
            }
            SECTION("confirm")
            {
                scp2.mSCP.setStateFromEnvelope(
                    0, scp2.wrapEnvelope(
                           makeConfirm(v0SecretKey, qSetHash0, 0, 2, b, 1, 2)));
            }
            SECTION("externalize")
            {
                scp2.mSCP.setStateFromEnvelope(
                    0, scp2.wrapEnvelope(
                           makeExternalize(v0SecretKey, qSetHash0, 0, b, 2)));
            }
        }
    };

    testTimeouts(scp, test);
}

TEST_CASE("ballot protocol core3", "[scp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    // core3 has an edge case where v-blocking and quorum can be the same
    // v-blocking set size: 2
    // threshold: 2 = 1 + self or 2 others
    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);

    auto test = [&](TestSCP& scp) {
        scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));
        uint256 qSetHash0 = scp.mSCP.getLocalNode()->getQuorumSetHash();

        REQUIRE(xValue < yValue);
        REQUIRE(yValue < zValue);

        auto recvQuorumChecksEx2 = [&](genEnvelope gen, bool withChecks,
                                       bool delayedQuorum, bool checkUpcoming,
                                       bool minQuorum) {
            SCPEnvelope e1 = gen(v1SecretKey);
            SCPEnvelope e2 = gen(v2SecretKey);

            scp.bumpTimerOffset();

            size_t i = scp.mEnvs.size() + 1;
            scp.receiveEnvelope(e1);
            if (withChecks && !delayedQuorum)
            {
                REQUIRE(scp.mEnvs.size() == i);
            }
            if (checkUpcoming)
            {
                REQUIRE(scp.hasBallotTimerUpcoming());
            }
            if (!minQuorum)
            {
                // nothing happens with an extra vote (unless we're in
                // delayedQuorum)
                scp.receiveEnvelope(e2);
                if (withChecks)
                {
                    REQUIRE(scp.mEnvs.size() == i);
                }
            }
        };
        auto recvQuorumChecksEx =
            std::bind(recvQuorumChecksEx2, _1, _2, _3, _4, false);
        auto recvQuorumChecks =
            std::bind(recvQuorumChecksEx, _1, _2, _3, false);

        // no timer is set
        REQUIRE(!scp.hasBallotTimer());

        Value const& aValue = zValue;
        Value const& bValue = xValue;

        SCPBallot A1(1, aValue);
        SCPBallot B1(1, bValue);

        SCPBallot A2 = A1;
        A2.counter++;

        SCPBallot A3 = A2;
        A3.counter++;

        SCPBallot A4 = A3;
        A4.counter++;

        SCPBallot A5 = A4;
        A5.counter++;

        SCPBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

        SCPBallot B2 = B1;
        B2.counter++;

        SCPBallot B3 = B2;
        B3.counter++;

        SECTION("prepared B1 (quorum votes B1) local aValue")
        {
            REQUIRE(scp.bumpState(0, aValue));
            REQUIRE(scp.mEnvs.size() == 1);
            REQUIRE(!scp.hasBallotTimer());

            scp.bumpTimerOffset();
            recvQuorumChecks(makePrepareGen(qSetHash, B1), true, true);
            REQUIRE(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
            REQUIRE(scp.hasBallotTimerUpcoming());
            SECTION("quorum prepared B1")
            {
                scp.bumpTimerOffset();
                recvQuorumChecks(makePrepareGen(qSetHash, B1, &B1), false,
                                 false);
                REQUIRE(scp.mEnvs.size() == 2);
                // nothing happens:
                // computed_h = B1 (2)
                //    does not actually update h as b > computed_h
                //    also skips (3)
                REQUIRE(!scp.hasBallotTimerUpcoming());
                SECTION("quorum bumps to A1")
                {
                    scp.bumpTimerOffset();
                    recvQuorumChecksEx2(makePrepareGen(qSetHash, A1, &B1),
                                        false, false, false, true);

                    REQUIRE(scp.mEnvs.size() == 3);
                    // still does not set h as b > computed_h
                    verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, A1,
                                  &A1, 0, 0, &B1);
                    REQUIRE(!scp.hasBallotTimerUpcoming());

                    scp.bumpTimerOffset();
                    // quorum commits A1
                    recvQuorumChecksEx2(
                        makePrepareGen(qSetHash, A2, &A1, 1, 1, &B1), false,
                        false, false, true);
                    REQUIRE(scp.mEnvs.size() == 4);
                    verifyConfirm(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, 2,
                                  A1, 1, 1);
                    REQUIRE(!scp.hasBallotTimerUpcoming());
                }
            }
        }
        SECTION("prepared A1 with timeout")
        {
            // starts with bValue (smallest)
            REQUIRE(scp.bumpState(0, bValue));
            REQUIRE(scp.mEnvs.size() == 1);

            // setup
            recvQuorumChecks(makePrepareGen(qSetHash, A1, &A1, 0, 1), false,
                             false);
            REQUIRE(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &A1, 1,
                          1);

            // now, receive bumped votes
            recvQuorumChecks(makePrepareGen(qSetHash, A2, &B2, 0, 1, &A1), true,
                             true);
            REQUIRE(scp.mEnvs.size() == 3);
            // p=B2, p'=A1 (1)
            // computed_h = B2 (2)
            //   does not update h as b < computed_h
            // v-blocking ahead -> b = computed_h = B2 (9)
            // h = B2 (2) (now possible)
            // c = 0 (1)
            verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, B2, &A2, 0,
                          2, &B2);
        }
        SECTION("node without self - quorum timeout")
        {
            SIMULATION_CREATE_NODE(NodeNS);
            TestSCP scpNNS(vNodeNSSecretKey.getPublicKey(), qSet);
            scpNNS.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));
            uint256 qSetHashNodeNS =
                scpNNS.mSCP.getLocalNode()->getQuorumSetHash();

            scpNNS.receiveEnvelope(
                makePrepare(v1SecretKey, qSetHash, 0, A2, &B2, 0, 1, &A1));
            scpNNS.receiveEnvelope(
                makePrepare(v2SecretKey, qSetHash, 0, A1, &A1, 1, 1));

            REQUIRE(scpNNS.mEnvs.size() == 2);
            verifyPrepare(scpNNS.mEnvs[1], vNodeNSSecretKey, qSetHashNodeNS, 0,
                          A1, &A1, 1, 1);

            scpNNS.receiveEnvelope(
                makePrepare(v0SecretKey, qSetHash, 0, A2, &B2, 0, 1, &A1));

            REQUIRE(scpNNS.mEnvs.size() == 3);
            verifyPrepare(scpNNS.mEnvs[2], vNodeNSSecretKey, qSetHashNodeNS, 0,
                          B2, &A2, 0, 2, &B2);
        }
    };

    testTimeouts(scp, test);
}

TEST_CASE(
    "follower adoption times out structurally-valid value into empty tx set",
    "[scp][leader-ballot]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    auto const qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);
    scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));

    // xValue is structurally-valid throughout — its tx set is either still in
    // flight or has been downloaded-and-found-invalid.  Seed a wait time past
    // the download timeout so maybeReplaceValueWithEmptyTxSet triggers
    // empty-tx-set replacement at bumpState time.
    scp.startDownload(xValue, OVER_TX_SET_TIMEOUT);
    scp.mValidateValueOverride = xValueStructurallyValidValidationOverride;

    REQUIRE(scp.receiveEnvelope(makePrepare(
                v1SecretKey, qSetHash, 0, SCPBallot(1, xValue))) == SCP::VALID);

    // The emitted ballot should carry the empty-tx-set value derived from
    // xValue, not xValue itself.
    auto const& lastEnv = scp.mEnvs.back();
    REQUIRE(lastEnv.statement.pledges.type() == SCP_ST_PREPARE);
    auto const& ballot = lastEnv.statement.pledges.prepare().ballot;
    REQUIRE(scp.isEmptyTxSetValue(ballot.value));
    REQUIRE(ballot.value == scp.makeEmptyTxSetValueFromValue(xValue));
}

TEST_CASE("ballot protocol self-emits CONFIRM after federated accept-commit on "
          "structurally-valid value",
          "[scp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);
    scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));

    // xValue stays kStructurallyValidValue throughout, with a wait time
    // below the download timeout so maybeReplaceValueWithEmptyTxSet does not
    // replace it with an empty-tx-set value.
    scp.startDownload(xValue, UNDER_TX_SET_TIMEOUT);
    scp.mValidateValueOverride = xValueStructurallyValidValidationOverride;

    SCPBallot xB1(1, xValue);

    // v0 enters ballot protocol with xValue.
    REQUIRE(scp.bumpState(0, xValue));
    REQUIRE(scp.mEnvs.size() == 1);

    // v1, v2 vote-prepare for (1, xValue) → v0 accept-prepared (1, xValue).
    REQUIRE(scp.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, xB1)) ==
            SCP::EnvelopeState::VALID);
    REQUIRE(scp.receiveEnvelope(makePrepare(v2SecretKey, qSetHash, 0, xB1)) ==
            SCP::EnvelopeState::VALID);

    // v1, v2 signal accept-prepared (1, xValue). v0 would normally
    // confirm-prepared here, but setConfirmPrepared stalls on
    // kStructurallyValidValue so c/h stay unset on v0's side.
    REQUIRE(
        scp.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, xB1, &xB1)) ==
        SCP::EnvelopeState::VALID);
    REQUIRE(
        scp.receiveEnvelope(makePrepare(v2SecretKey, qSetHash, 0, xB1, &xB1)) ==
        SCP::EnvelopeState::VALID);

    // v1, v2 vote-to-commit (1, xValue) via nC/nH on their PREPAREs.
    // federatedAccept fires via the "quorum voted-or-accepted" path v0
    // accept-commits, transitions mPhase to CONFIRM, and self-emits a CONFIRM
    // with xValue.
    REQUIRE(scp.receiveEnvelope(
                makePrepare(v1SecretKey, qSetHash, 0, xB1, &xB1, 1, 1)) ==
            SCP::EnvelopeState::VALID);
    REQUIRE(scp.receiveEnvelope(
                makePrepare(v2SecretKey, qSetHash, 0, xB1, &xB1, 1, 1)) ==
            SCP::EnvelopeState::VALID);

    // Last emitted envelope should be a CONFIRM carrying xValue — proves that
    // processEnvelope correctly accepts self-emitted CONFIRMs with
    // kStructurallyValidValue.
    auto const& lastEnv = scp.mEnvs.back();
    REQUIRE(lastEnv.statement.pledges.type() == SCP_ST_CONFIRM);
    auto const& cBallot = lastEnv.statement.pledges.confirm().ballot;
    REQUIRE(cBallot.value == xValue);
    REQUIRE(!scp.isEmptyTxSetValue(cBallot.value));

    // A peer CONFIRM whose value v0 considers kStructurallyValidValue is
    // rejected by processEnvelope
    auto const res = scp.receiveEnvelope(
        makeConfirm(v1SecretKey, qSetHash, 0, 1, xB1, 1, 1));
    REQUIRE(res == SCP::EnvelopeState::INVALID);
}

TEST_CASE("drop tx set on download timeout", "[scp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    // 3 node network with threshold=2 (need any 2 nodes to form quorum)
    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);
    scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));
    uint256 qSetHash0 = scp.mSCP.getLocalNode()->getQuorumSetHash();

    SECTION("timeout during prepare phase")
    {
        // Node v0 starts ballot protocol with xValue
        // Simulate that xValue is awaiting download with timeout exceeded
        scp.startDownload(xValue, OVER_TX_SET_TIMEOUT);

        // Now call bumpState which should trigger
        // maybeReplaceValueWithEmptyTxSet
        REQUIRE(scp.bumpState(0, xValue));
        REQUIRE(scp.mEnvs.size() == 1);

        // The ballot should have an empty-tx-set value, not the original
        // xValue
        auto const& emittedBallot =
            scp.mEnvs[0].statement.pledges.prepare().ballot;

        REQUIRE(emittedBallot.counter == 1);
        REQUIRE(scp.isEmptyTxSetValue(emittedBallot.value));

        // Verify it's the empty-tx-set value derived from xValue
        Value expectedEmptyTxSetValue =
            scp.makeEmptyTxSetValueFromValue(xValue);
        REQUIRE(emittedBallot.value == expectedEmptyTxSetValue);

        verifyPrepare(scp.mEnvs[0], v0SecretKey, qSetHash0, 0,
                      SCPBallot(1, expectedEmptyTxSetValue));
    }

    SECTION("no timeout when wait time under threshold")
    {
        // Node v0 starts ballot protocol with xValue
        REQUIRE(scp.bumpState(0, xValue));
        REQUIRE(scp.mEnvs.size() == 1);

        SCPBallot b1(1, xValue);

        // Simulate that xValue is awaiting download but wait time is still low
        scp.startDownload(xValue, UNDER_TX_SET_TIMEOUT);

        // Try to bump state - should NOT replace with an empty-tx-set value
        REQUIRE(scp.bumpState(0, xValue));
        REQUIRE(scp.mEnvs.size() == 2);

        // Verify ballot still has original xValue, not an empty-tx-set value
        auto const& emittedBallot =
            scp.mEnvs[1].statement.pledges.prepare().ballot;
        REQUIRE(emittedBallot.counter == 2);
        REQUIRE(!scp.isEmptyTxSetValue(emittedBallot.value));
        REQUIRE(emittedBallot.value == xValue);
    }

    SECTION("empty-tx-set value can be prepared and confirmed")
    {
        // Start with xValue and timeout to an empty-tx-set value
        scp.startDownload(xValue, OVER_TX_SET_TIMEOUT);

        REQUIRE(scp.bumpState(0, xValue));
        REQUIRE(scp.mEnvs.size() == 1);

        Value emptyTxSetValue = scp.makeEmptyTxSetValueFromValue(xValue);
        SCPBallot emptyTxSetB1(1, emptyTxSetValue);

        // Verify we emitted an empty-tx-set value
        REQUIRE(scp.isEmptyTxSetValue(
            scp.mEnvs[0].statement.pledges.prepare().ballot.value));
        verifyPrepare(scp.mEnvs[0], v0SecretKey, qSetHash0, 0, emptyTxSetB1);

        // Other nodes also move to the empty-tx-set value
        scp.receiveEnvelope(
            makePrepare(v1SecretKey, qSetHash, 0, emptyTxSetB1));
        scp.receiveEnvelope(
            makePrepare(v2SecretKey, qSetHash, 0, emptyTxSetB1));

        // Should prepare the empty-tx-set value (quorum reached)
        REQUIRE(scp.mEnvs.size() == 2);
        verifyPrepare(scp.mEnvs[1], v0SecretKey, qSetHash0, 0, emptyTxSetB1,
                      &emptyTxSetB1);

        // Quorum confirms prepared empty-tx-set value
        scp.receiveEnvelope(
            makePrepare(v1SecretKey, qSetHash, 0, emptyTxSetB1, &emptyTxSetB1));
        scp.receiveEnvelope(
            makePrepare(v2SecretKey, qSetHash, 0, emptyTxSetB1, &emptyTxSetB1));

        REQUIRE(scp.mEnvs.size() == 3);
        verifyPrepare(scp.mEnvs[2], v0SecretKey, qSetHash0, 0, emptyTxSetB1,
                      &emptyTxSetB1, 1, 1);

        // Accept commit
        scp.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, emptyTxSetB1,
                                        &emptyTxSetB1, 1, 1));
        scp.receiveEnvelope(makePrepare(v2SecretKey, qSetHash, 0, emptyTxSetB1,
                                        &emptyTxSetB1, 1, 1));

        REQUIRE(scp.mEnvs.size() == 4);
        verifyConfirm(scp.mEnvs[3], v0SecretKey, qSetHash0, 0, 1, emptyTxSetB1,
                      1, 1);

        // Externalize the empty-tx-set value
        scp.receiveEnvelope(
            makeConfirm(v1SecretKey, qSetHash, 0, 1, emptyTxSetB1, 1, 1));
        scp.receiveEnvelope(
            makeConfirm(v2SecretKey, qSetHash, 0, 1, emptyTxSetB1, 1, 1));

        REQUIRE(scp.mEnvs.size() == 5);
        verifyExternalize(scp.mEnvs[4], v0SecretKey, qSetHash0, 0, emptyTxSetB1,
                          1);

        // Verify the externalized value is the empty-tx-set value
        REQUIRE(scp.mExternalizedValues.size() == 1);
        REQUIRE(scp.isEmptyTxSetValue(scp.mExternalizedValues[0]));
        REQUIRE(scp.mExternalizedValues[0] == emptyTxSetValue);
    }
}

TEST_CASE("Proper handling of non-current ledger value",
          "[scp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);
    scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));

    // validateValue reports xValue is not for the current ledger.
    scp.mValidateValueOverride = xValueNotCurrentLedgerOverride;

    REQUIRE(scp.bumpState(0, xValue));

    // Do not emit a ballot with a kMaybeValid value
    REQUIRE(scp.mEnvs.size() == 0);
}

TEST_CASE("setConfirmPrepared stalls on kStructurallyValidValue value",
          "[scp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);
    scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));

    // Simulate parallel downloading
    scp.startDownload(xValue, UNDER_TX_SET_TIMEOUT);

    // v0 enters ballot protocol
    REQUIRE(scp.bumpState(0, xValue));
    REQUIRE(scp.mEnvs.size() == 1);
    SCPBallot xB1(1, xValue);

    // v1 and v2 send PREPAREs with prepared — quorum confirms prepared
    REQUIRE(
        scp.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, xB1, &xB1)) ==
        SCP::EnvelopeState::VALID);
    REQUIRE(
        scp.receiveEnvelope(makePrepare(v2SecretKey, qSetHash, 0, xB1, &xB1)) ==
        SCP::EnvelopeState::VALID);

    SECTION("commit gate stalls mCommit but mHighBallot is set")
    {

        // setConfirmPrepared sets mHighBallot (nH > 0) but the commit gate
        // stalls mCommit (nC == 0) because xValue is kStructurallyValidValue.
        // Check the latest emitted PREPARE.
        REQUIRE(scp.mEnvs.size() >= 2);
        auto const& lastPrep = scp.mEnvs.back().statement.pledges.prepare();
        REQUIRE(lastPrep.nH == 1);
        REQUIRE(lastPrep.nC == 0);
    }

    SECTION("proceeds after value becomes validated")
    {
        auto envsBeforeClear = scp.mEnvs.size();

        // Simulate tx set arrival — value becomes fully validated
        scp.clearDownload(xValue);

        // Trigger advanceSlot with envelopes that confirm-prepare at a
        // higher counter, so attemptConfirmPrepared finds newH > mHighBallot.
        // This causes setConfirmPrepared to be called with the now-validated
        // value, setting mCommit.
        SCPBallot xB2(2, xValue);
        REQUIRE(scp.receiveEnvelope(
                    makePrepare(v1SecretKey, qSetHash, 0, xB2, &xB2)) ==
                SCP::EnvelopeState::VALID);
        REQUIRE(scp.receiveEnvelope(
                    makePrepare(v2SecretKey, qSetHash, 0, xB2, &xB2)) ==
                SCP::EnvelopeState::VALID);

        // setConfirmPrepared should now succeed — mCommit set, node
        // progresses. Expect at least one new envelope with nC > 0 or a
        // CONFIRM/EXTERNALIZE.
        REQUIRE(scp.mEnvs.size() > envsBeforeClear);
        bool foundC = false;
        for (size_t i = envsBeforeClear; i < scp.mEnvs.size(); i++)
        {
            auto const& st = scp.mEnvs[i].statement;
            if (st.pledges.type() == SCP_ST_PREPARE)
            {
                if (st.pledges.prepare().nC > 0)
                {
                    foundC = true;
                    break;
                }
            }
            else
            {
                // CONFIRM or EXTERNALIZE also proves we got past the stall
                foundC = true;
                break;
            }
        }
        REQUIRE(foundC);
    }

    SECTION("validation completion resumes the same ballot without new votes")
    {
        auto const before = scp.mEnvs.size();
        REQUIRE(scp.mEnvs.back().statement.pledges.prepare().nC == 0);
        scp.mSCP.revalidateValue(0, xValue);
        REQUIRE(scp.mEnvs.size() == before);

        scp.clearDownload(xValue);
        scp.mSCP.revalidateValue(0, xValue);
        REQUIRE(scp.mEnvs.size() == before + 1);
        verifyPrepare(scp.mEnvs.back(), v0SecretKey,
                      scp.mSCP.getLocalNode()->getQuorumSetHash(), 0, xB1, &xB1,
                      1, 1);

        // Duplicate completions neither emit again nor bump the counter.
        scp.mSCP.revalidateValue(0, xValue);
        REQUIRE(scp.mEnvs.size() == before + 1);
    }

    SECTION("peer commit vote is newer at the same prepared ballot")
    {
        auto withoutCommit =
            makePrepare(v1SecretKey, qSetHash, 0, xB1, &xB1, 0, 1);
        auto withCommit =
            makePrepare(v1SecretKey, qSetHash, 0, xB1, &xB1, 1, 1);
        REQUIRE(scp.receiveEnvelope(withoutCommit) ==
                SCP::EnvelopeState::VALID);
        REQUIRE(scp.receiveEnvelope(withCommit) == SCP::EnvelopeState::VALID);
        REQUIRE(scp.receiveEnvelope(withCommit) == SCP::EnvelopeState::INVALID);
        REQUIRE(scp.receiveEnvelope(withoutCommit) ==
                SCP::EnvelopeState::INVALID);
    }
}

TEST_CASE("incoming PREPARE with structurally valid prepared value is accepted",
          "[scp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);
    scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));

    // v0 enters ballot protocol with yValue
    REQUIRE(scp.bumpState(0, yValue));
    REQUIRE(scp.mEnvs.size() == 1);

    // Set xValue to kStructurallyValidValue
    scp.mValidateValueOverride = xValueStructurallyValidValidationOverride;

    // v1 sends PREPARE with valid ballot value but only structurally valid
    // prepared value.  This should be accepted.
    SCPBallot yB1(1, yValue);
    SCPBallot xB1(1, xValue);
    REQUIRE(
        scp.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, yB1, &xB1)) ==
        SCP::EnvelopeState::VALID);
}

TEST_CASE("incoming PREPARE with non-tx-set-invalid value is dropped",
          "[scp][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    TestSCP scp(v0SecretKey.getPublicKey(), qSet);
    scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qSet));

    // xValue is invalid for some non-tx-set reason (close time, signature,
    // ...). This should NOT be accepted as kStructurallyValidValue; the
    // statement should be dropped.
    scp.mValidateValueOverride = xValueNonTxSetInvalidValidationOverride;

    SCPBallot xB1(1, xValue);

    // Envelope should be rejected as invalid
    REQUIRE(scp.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, xB1)) ==
            SCP::EnvelopeState::INVALID);

    // Envelope was not recorded — recordEnvelope only runs for non-kInvalid.
    REQUIRE(scp.mSCP.getLatestMessage(v1NodeID) == nullptr);
    // No local emit triggered.
    REQUIRE(scp.mEnvs.empty());
}

TEST_CASE("direct ballot proposal and follower adoption",
          "[scp][leader-ballot]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SCPQuorumSet qset;
    qset.threshold = 3;
    qset.validators = {v0NodeID, v1NodeID, v2NodeID};
    auto hash = sha256(xdr::xdr_to_opaque(qset));
    TestSCP scp(v0NodeID, qset);
    scp.storeQuorumSet(std::make_shared<SCPQuorumSet>(qset));
    auto prepare = makePrepare(v1SecretKey, hash, 7, SCPBallot(1, xValue));

    SECTION("leader starts once")
    {
        REQUIRE(scp.mSCP.startBallot(7, scp.wrapValue(xValue)));
        REQUIRE(scp.mEnvs.size() == 1);
        REQUIRE_FALSE(scp.mSCP.startBallot(7, scp.wrapValue(zValue)));
        REQUIRE(scp.mEnvs.size() == 1);
        REQUIRE(scp.mEnvs.front().statement.pledges.prepare().ballot ==
                SCPBallot(1, xValue));
    }
    SECTION("follower adopts a single prepare and never replaces its ballot")
    {
        REQUIRE(scp.receiveEnvelope(prepare) == SCP::VALID);
        REQUIRE(scp.mEnvs.size() == 1);
        REQUIRE(scp.mEnvs.back().statement.pledges.prepare().ballot ==
                SCPBallot(1, xValue));
        REQUIRE_FALSE(scp.mSCP.startBallot(7, scp.wrapValue(zValue)));
        REQUIRE(scp.getSlot(7).getBallotProtocol().getProposal()->getValue() ==
                xValue);
    }
    SECTION("a v-blocking peer ahead raises the initial ballot counter")
    {
        auto ahead = makePrepare(v1SecretKey, hash, 7, SCPBallot(3, xValue));
        REQUIRE(scp.receiveEnvelope(ahead) == SCP::VALID);
        REQUIRE(scp.mSCP.hasBallot(7));
        REQUIRE(scp.mEnvs.back().statement.pledges.prepare().ballot ==
                SCPBallot(3, xValue));
        REQUIRE(scp.getSlot(7).getBallotProtocol().getProposal()->getValue() ==
                xValue);
    }
    SECTION("federated commit state takes precedence over proposal adoption")
    {
        auto externalize = GENERATE(false, true);
        auto committed = externalize ? makeExternalize(v1SecretKey, hash, 7,
                                                       SCPBallot(2, xValue), 2)
                                     : makeConfirm(v1SecretKey, hash, 7, 2,
                                                   SCPBallot(2, xValue), 2, 2);
        REQUIRE(scp.receiveEnvelope(committed) == SCP::VALID);
        REQUIRE(scp.mSCP.hasBallot(7));
        REQUIRE_FALSE(scp.getSlot(7).getBallotProtocol().getProposal());
        REQUIRE(scp.mEnvs.back().statement.pledges.type() == SCP_ST_CONFIRM);
        REQUIRE(scp.mEnvs.back().statement.pledges.confirm().ballot.value ==
                xValue);
        REQUIRE_FALSE(scp.mSCP.startBallot(7, scp.wrapValue(zValue)));
    }
    SECTION("invalid proposals neither adopt nor start")
    {
        scp.mValidateValueOverride = [](uint64, Value const&) {
            return SCPDriver::kInvalidValue;
        };
        REQUIRE(scp.receiveEnvelope(prepare) == SCP::INVALID);
        REQUIRE_FALSE(scp.mSCP.startBallot(7, scp.wrapValue(xValue)));
        REQUIRE_FALSE(scp.mSCP.hasBallot(7));
        REQUIRE(scp.mEnvs.empty());
    }
    SECTION("future values do not make a pristine node vote")
    {
        scp.mValidateValueOverride = [](uint64, Value const&) {
            return SCPDriver::kMaybeValidNotCurrentValue;
        };
        REQUIRE(scp.receiveEnvelope(prepare) == SCP::VALID);
        REQUIRE_FALSE(scp.mSCP.hasBallot(7));
        REQUIRE_FALSE(scp.mSCP.isSlotFullyValidated(7));
        REQUIRE(scp.mEnvs.empty());
    }
    SECTION("watchers do not adopt")
    {
        TestSCP watcher(v0NodeID, qset, false);
        watcher.storeQuorumSet(std::make_shared<SCPQuorumSet>(qset));
        REQUIRE(watcher.receiveEnvelope(prepare) == SCP::VALID);
        REQUIRE_FALSE(watcher.mSCP.hasBallot(7));
        REQUIRE(watcher.mEnvs.empty());
    }
    SECTION("restored ballots cannot be replaced by a trigger")
    {
        auto restored = makePrepare(v0SecretKey, hash, 7, SCPBallot(3, xValue));
        scp.mSCP.setStateFromEnvelope(7, scp.wrapEnvelope(restored));
        REQUIRE(scp.mSCP.hasBallot(7));
        REQUIRE_FALSE(scp.mSCP.startBallot(7, scp.wrapValue(zValue)));
        REQUIRE(scp.mEnvs.empty());
    }
    SECTION("nomination is rejected without creating a slot")
    {
        auto nominate = makeNominate(v1SecretKey, hash, 7, {xValue}, {});
        REQUIRE(scp.receiveEnvelope(nominate) == SCP::INVALID);
        REQUIRE(scp.mSCP.getKnownSlotsCount() == 0);
        REQUIRE(scp.mEnvs.empty());
    }
    SECTION("download timeout retains original proposal for a later bump")
    {
        scp.startDownload(xValue, OVER_TX_SET_TIMEOUT);
        REQUIRE(scp.receiveEnvelope(prepare) == SCP::VALID);
        REQUIRE(scp.mEnvs.back().statement.pledges.prepare().ballot.value ==
                scp.makeEmptyTxSetValueFromValue(xValue));
        REQUIRE(scp.getSlot(7).getBallotProtocol().getProposal()->getValue() ==
                xValue);
        scp.clearDownload(xValue);
        REQUIRE(scp.getSlot(7).abandonBallot());
        REQUIRE(scp.mEnvs.back().statement.pledges.prepare().ballot ==
                SCPBallot(2, xValue));
    }
}

TEST_CASE("one leader drives a five node ballot without nomination",
          "[scp][leader-ballot]")
{
    setupValues();
    std::vector<NodeID> ids;
    for (int i = 0; i < 5; ++i)
    {
        ids.push_back(
            SecretKey::fromSeed(sha256("leader-ballot-" + std::to_string(i)))
                .getPublicKey());
    }
    SCPQuorumSet qset;
    qset.threshold = 4;
    qset.validators.assign(ids.begin(), ids.end());
    std::vector<std::unique_ptr<TestSCP>> nodes;
    for (auto const& id : ids)
    {
        nodes.emplace_back(std::make_unique<TestSCP>(id, qset));
        nodes.back()->mPriorityLookup = [&](NodeID const& node) {
            return node == ids[0] ? uint64(100) : uint64(1);
        };
    }
    for (auto& node : nodes)
    {
        for (auto& other : nodes)
        {
            node->storeQuorumSet(std::make_shared<SCPQuorumSet>(
                other->mSCP.getLocalQuorumSet()));
        }
        REQUIRE(node->mSCP.electLeader(7, xValue) == ids[0]);
    }
    REQUIRE(nodes[0]->mSCP.startBallot(7, nodes[0]->wrapValue(xValue)));
    std::vector<size_t> delivered(nodes.size(), 0);
    bool progress = true;
    size_t messages = 0;
    while (progress)
    {
        progress = false;
        for (size_t i = 0; i < nodes.size(); ++i)
        {
            while (delivered[i] < nodes[i]->mEnvs.size())
            {
                auto envelope = nodes[i]->mEnvs[delivered[i]++];
                REQUIRE(envelope.statement.pledges.type() != SCP_ST_NOMINATE);
                REQUIRE(++messages < 100);
                for (size_t j = 0; j < nodes.size(); ++j)
                {
                    if (i != j)
                        nodes[j]->receiveEnvelope(envelope);
                }
                progress = true;
            }
        }
    }
    for (auto& node : nodes)
    {
        REQUIRE(node->mExternalizedValues.at(7) == xValue);
        REQUIRE_FALSE(node->hasBallotTimer());
        REQUIRE(node->mEnvs.back().statement.pledges.type() ==
                SCP_ST_EXTERNALIZE);
    }
}
}
