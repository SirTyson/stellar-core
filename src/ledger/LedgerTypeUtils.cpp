// Copyright 2023 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerTypeUtils.h"
#include "util/GlobalChecks.h"

namespace stellar
{

#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
uint32_t
getExpirationLedger(LedgerEntry const& e)
{
    releaseAssert(isSorobanEntry(e.data));
    if (e.data.type() == CONTRACT_DATA)
    {
        return e.data.contractData().expirationLedgerSeq;
    }

    return e.data.contractCode().expirationLedgerSeq;
}

void
setExpirationLedger(LedgerEntry& e, uint32_t lifetime)
{
    releaseAssert(isSorobanEntry(e.data));
    if (e.data.type() == CONTRACT_DATA)
    {
        e.data.contractData().expirationLedgerSeq = lifetime;
    }
    else
    {
        e.data.contractCode().expirationLedgerSeq = lifetime;
    }
}

void
setLeType(LedgerEntry& e, ContractLedgerEntryType leType)
{
    releaseAssert(isSorobanEntry(e.data));
    if (e.data.type() == CONTRACT_DATA)
    {
        e.data.contractData().body.leType(leType);
    }
    else
    {
        e.data.contractCode().body.leType(leType);
    }
}

void
setLeType(LedgerKey& k, ContractLedgerEntryType leType)
{
    releaseAssert(isSorobanEntry(k));
    if (k.type() == CONTRACT_DATA)
    {
        k.contractData().leType = leType;
    }
    else
    {
        k.contractCode().leType = leType;
    }
}

ContractLedgerEntryType
getLeType(LedgerKey const& k)
{
    releaseAssert(isSorobanEntry(k));
    if (k.type() == CONTRACT_CODE)
    {
        return k.contractCode().leType;
    }

    return k.contractData().leType;
}

ContractLedgerEntryType
getLeType(LedgerEntry::_data_t const& e)
{
    releaseAssert(isSorobanEntry(e));
    if (e.type() == CONTRACT_CODE)
    {
        return e.contractCode().body.leType();
    }

    return e.contractData().body.leType();
}

LedgerEntry
lifetimeExtensionFromDataEntry(LedgerEntry const& le)
{
    releaseAssert(isSorobanDataEntry(le.data));
    LedgerEntry extLe;
    if (le.data.type() == CONTRACT_CODE)
    {
        extLe.data.type(CONTRACT_CODE);
        extLe.data.contractCode().expirationLedgerSeq = getExpirationLedger(le);
        extLe.data.contractCode().body.leType(LIFETIME_EXTENSION);
    }
    else
    {
        extLe.data.type(CONTRACT_DATA);
        extLe.data.contractData().expirationLedgerSeq = getExpirationLedger(le);
        extLe.data.contractData().body.leType(LIFETIME_EXTENSION);
    }

    return extLe;
}
#endif

bool
autoBumpEnabled(LedgerEntry const& e)
{
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
    releaseAssert(isSorobanDataEntry(e.data));

    // CONTRACT_CODE always has autobump enabled. For CONTRACT_DATA, check if
    // the NO_AUTOBUMP flag set
    return e.data.type() == CONTRACT_CODE ||
           !(e.data.contractData().body.data().flags &
             ContractDataFlags::NO_AUTOBUMP);
#endif
    return false;
}

template <typename T>
bool
isSorobanExtEntry(T const& e)
{
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
    return isSorobanEntry(e) && getLeType(e) == LIFETIME_EXTENSION;
#endif
    return false;
}

template bool
isSorobanExtEntry<LedgerEntry::_data_t>(LedgerEntry::_data_t const& e);
template bool isSorobanExtEntry<LedgerKey>(LedgerKey const& e);

template <typename T>
bool
isSorobanDataEntry(T const& e)
{
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
    return isSorobanEntry(e) && getLeType(e) == DATA_ENTRY;
#endif
    return false;
}

template bool
isSorobanDataEntry<LedgerEntry::_data_t>(LedgerEntry::_data_t const& e);
template bool isSorobanDataEntry<LedgerKey>(LedgerKey const& e);
};