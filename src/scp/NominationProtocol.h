// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "lib/json/json-forwards.h"
#include "scp/SCP.h"
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace stellar
{
class NominationProtocol
{
  protected:
    Slot& mSlot;

    int32 mRoundNumber;

    ValueWrapperPtrSet mVotes;                                  // X
    ValueWrapperPtrSet mAccepted;                               // Y
    ValueWrapperPtrSet mCandidates;                             // Z
    std::map<NodeID, SCPEnvelopeWrapperPtr> mLatestNominations; // N

    SCPEnvelopeWrapperPtr mLastEnvelope; // last envelope emitted by this node

    // nodes from quorum set that have the highest priority this round
    std::set<NodeID> mRoundLeaders;

    // true if 'nominate' was called
    bool mNominationStarted;

    // the latest (if any) candidate value
    ValueWrapperPtr mLatestCompositeCandidate;

    // the value from the previous slot
    Value mPreviousValue;

    // The seed used for leader election this slot. Leader selection is
    // pipelined so that slot N's leaders are seeded by hash(N-2) rather than
    // the immediately preceding value, which makes the schedule knowable a
    // full ledger ahead of time (see docs/direct-leader-flooding.md). This is
    // constant across rounds for a given slot (only mRoundNumber varies).
    Value mLeaderElectionSeed;

    bool isNewerStatement(NodeID const& nodeID, SCPNomination const& st);

    // returns true if 'p' is a subset of 'v'
    // also sets 'notEqual' if p and v differ
    // note: p and v must be sorted
    static bool isSubsetHelper(xdr::xvector<Value> const& p,
                               xdr::xvector<Value> const& v, bool& notEqual);

    SCPDriver::ValidationLevel validateValue(Value const& v);
    ValueWrapperPtr extractValidValue(Value const& value);

    bool isSane(SCPStatement const& st);

    void recordEnvelope(SCPEnvelopeWrapperPtr env);

    void emitNomination();

    // returns true if v is in the accepted list from the statement
    static bool acceptPredicate(Value const& v, SCPStatement const& st);

    // applies 'processor' to all values from the passed in nomination
    static void applyAll(SCPNomination const& nom,
                         std::function<void(Value const&)> processor);

    // updates the set of nodes that have priority over the others
    void updateRoundLeaders();

    // computes Gi(K, prevValue, mRoundNumber, value)
    uint64 hashValue(Value const& value);

    // returns the highest value that we don't have yet, that we should
    // vote for, extracted from a nomination.
    // returns nullptr if no new value was found
    ValueWrapperPtr getNewValueFromNomination(SCPNomination const& nom);

  public:
    static bool isNewerStatement(SCPNomination const& oldst,
                                 SCPNomination const& st);

    NominationProtocol(Slot& slot);

    SCP::EnvelopeState processEnvelope(SCPEnvelopeWrapperPtr envelope);

    static std::vector<Value> getStatementValues(SCPStatement const& st);

    // attempts to nominate a value for consensus.
    // `leaderElectionSeed` seeds leader election for this slot (see
    // mLeaderElectionSeed); `previousValue` is still used for value selection.
    bool nominate(ValueWrapperPtr value, Value const& previousValue,
                  Value const& leaderElectionSeed, bool timedout);

    // stops the nomination protocol
    void stopNomination();

    // return the current leaders
    std::set<NodeID> const& getLeaders() const;

    // Computes the set of leaders elected for a single nomination round from
    // explicit inputs, rather than from member state. This is the pure core of
    // the leader-election algorithm shared by live nomination
    // (updateRoundLeaders) and the ahead-of-time leader schedule
    // (computeLeaderSchedule / HerderSCPDriver::computeLeaderSchedule). `qset`
    // must already be normalized with `localID` excluded.
    static std::set<NodeID>
    computeRoundLeaders(SCPDriver& driver, Value const& seed, uint64 slotIndex,
                        int32_t roundNumber, SCPQuorumSet const& qset,
                        NodeID const& localID);

    // Computes the ordered list of up to `count` upcoming leaders for
    // `slotIndex` ahead of time, given the leader-election `seed`. Walks
    // nomination rounds 1, 2, ... accumulating each round's leaders (skipping
    // rounds that elect no one, exactly as the live fast-timeout does) until
    // `count` distinct leaders are collected or no more can be elected. The
    // resulting set matches the leaders SCP elects live for `slotIndex` when
    // fed the same seed; the ordering (by round, then NodeID within a round)
    // is deterministic across nodes that share the same qset and weights.
    static std::vector<NodeID>
    computeLeaderSchedule(SCPDriver& driver, Value const& seed,
                          uint64 slotIndex, size_t count,
                          SCPQuorumSet const& qset, NodeID const& localID);

    ValueWrapperPtr const&
    getLatestCompositeCandidate() const
    {
        return mLatestCompositeCandidate;
    }

    Json::Value getJsonInfo();

    SCP::QuorumInfoNodeState getState(NodeID const& node,
                                      bool selfAlreadyMovedOn);

    SCPEnvelope const*
    getLastMessageSend() const
    {
        return mLastEnvelope ? &mLastEnvelope->getEnvelope() : nullptr;
    }

    void setStateFromEnvelope(SCPEnvelopeWrapperPtr e);

    bool processCurrentState(std::function<bool(SCPEnvelope const&)> const& f,
                             bool forceSelf) const;

    // returns the latest message from a node
    // or nullptr if not found
    SCPEnvelope const* getLatestMessage(NodeID const& id) const;

  private:
    // The number of times the timer has expired
    // Used for the quorum endpoint.
    uint32_t mTimerExpCount;

    // Strip any upgrades that `value` may have, modifying it in place.  Does
    // nothing if `value` has no upgrades.
    void stripUpgrades(ValueWrapperPtr& value) const;
};
}
