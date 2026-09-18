// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "scp/SCPDriver.h"

namespace stellar
{
// A read-only election. Agreement requires the same candidate set, weights,
// previous value and slot at every validator. Quorum thresholds do not weight
// this election: in particular, there is no preference for the local node.
std::set<NodeID> predictLeaders(SCPDriver& driver, uint64 slot,
                                Value const& previousValue,
                                SCPQuorumSet const& qset, NodeID const& localID,
                                bool localIsValidator, uint32 rounds);
}
