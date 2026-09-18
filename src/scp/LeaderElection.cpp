// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/LeaderElection.h"
#include "scp/LocalNode.h"
#include "util/XDROperators.h"
#include <stdexcept>

namespace stellar
{
std::set<NodeID>
predictLeaders(SCPDriver& driver, uint64 slot, Value const& previousValue,
               SCPQuorumSet const& qset, NodeID const& localID,
               bool localIsValidator, uint32 rounds)
{
    std::set<NodeID> candidates;
    LocalNode::forAllNodes(qset, [&](NodeID const& node) {
        candidates.insert(node);
        return true;
    });
    if (localIsValidator)
    {
        candidates.insert(localID);
    }
    for (auto it = candidates.begin(); it != candidates.end();)
    {
        if (driver.getNodeWeight(*it) == 0)
        {
            it = candidates.erase(it);
        }
        else
        {
            ++it;
        }
    }
    std::set<NodeID> leaders;
    int32 round = 0;
    for (uint32 i = 0; i < rounds && leaders.size() < candidates.size(); ++i)
    {
        bool advanced = false;
        for (int attempts = 0; attempts < 1000; ++attempts)
        {
            ++round;
            uint64 top = 0;
            std::set<NodeID> elected;
            for (auto const& node : candidates)
            {
                auto weight = driver.getNodeWeight(node);
                if (driver.computeHashNode(slot, previousValue, false, round,
                                           node) > weight)
                {
                    continue;
                }
                auto priority = driver.computeHashNode(slot, previousValue,
                                                       true, round, node);
                if (priority > top)
                {
                    elected.clear();
                    top = priority;
                }
                if (priority == top && priority != 0)
                {
                    elected.insert(node);
                }
            }
            auto before = leaders.size();
            leaders.insert(elected.begin(), elected.end());
            if (leaders.size() != before)
            {
                advanced = true;
                break;
            }
        }
        if (!advanced)
        {
            throw std::runtime_error("Leader election failed to advance");
        }
    }
    return leaders;
}
}
