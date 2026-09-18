// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "SCPDriver.h"

#include <algorithm>

#include "crypto/Hex.h"
#include "crypto/KeyUtils.h"
#include "crypto/SecretKey.h"
#include "util/GlobalChecks.h"
#include "util/numeric.h"
#include "xdrpp/marshal.h"

namespace stellar
{

SCPEnvelopeWrapper::SCPEnvelopeWrapper(SCPEnvelope const& e) : mEnvelope(e)
{
}

SCPEnvelopeWrapper::~SCPEnvelopeWrapper()
{
}

ValueWrapper::ValueWrapper(Value const& value) : mValue(value)
{
}

ValueWrapper::~ValueWrapper()
{
}

SCPEnvelopeWrapperPtr
SCPDriver::wrapEnvelope(SCPEnvelope const& envelope)
{
    auto res = std::make_shared<SCPEnvelopeWrapper>(envelope);
    return res;
}

ValueWrapperPtr
SCPDriver::wrapValue(Value const& value)
{
    auto res = std::make_shared<ValueWrapper>(value);
    return res;
}

std::string
SCPDriver::getValueString(Value const& v) const
{
    Hash valueHash = getHashOf({xdr::xdr_to_opaque(v)});

    return hexAbbrev(valueHash);
}

std::string
SCPDriver::toStrKey(NodeID const& pk, bool fullKey) const
{
    return fullKey ? KeyUtils::toStrKey(pk) : toShortString(pk);
}

std::string
SCPDriver::toShortString(NodeID const& pk) const
{
    return KeyUtils::toShortString(pk);
}

// values used to switch hash function between priority and neighborhood checks
static uint32 const hash_N = 1;
static uint32 const hash_P = 2;

uint64
SCPDriver::hashHelper(
    uint64 slotIndex, Value const& prev,
    std::function<void(std::vector<xdr::opaque_vec<>>&)> extra)
{
    std::vector<xdr::opaque_vec<>> vals;
    vals.emplace_back(xdr::xdr_to_opaque(slotIndex));
    vals.emplace_back(xdr::xdr_to_opaque(prev));
    extra(vals);
    Hash t = getHashOf(vals);
    uint64 res = 0;
    for (size_t i = 0; i < sizeof(res); i++)
    {
        res = (res << 8) | t[i];
    }
    return res;
}

uint64
SCPDriver::computeHashNode(uint64 slotIndex, Value const& prev, bool isPriority,
                           int32_t roundNumber, NodeID const& nodeID)
{
#ifdef BUILD_TESTS
    if (mPriorityLookupForTesting)
    {
        return isPriority ? mPriorityLookupForTesting(nodeID) : 0;
    }
#endif
    return hashHelper(
        slotIndex, prev, [&](std::vector<xdr::opaque_vec<>>& vals) {
            vals.emplace_back(xdr::xdr_to_opaque(isPriority ? hash_P : hash_N));
            vals.emplace_back(xdr::xdr_to_opaque(roundNumber));
            vals.emplace_back(xdr::xdr_to_opaque(nodeID));
        });
}

// if a validator is repeated multiple times its weight is only the
// weight of the first occurrence
uint64
SCPDriver::getNodeWeight(NodeID const& nodeID) const
{
    // Identical candidate sets must yield identical elections at every node.
    // Quorum thresholds and the observer's identity do not affect weights.
    return UINT64_MAX;
}

}
