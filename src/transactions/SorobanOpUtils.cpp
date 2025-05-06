// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/SorobanOpUtils.h"
#include "TransactionUtils.h"
#include "bucket/HotArchiveBucket.h"
#include "ledger/LedgerManagerImpl.h"
#include "ledger/LedgerTypeUtils.h"
#include "main/AppConnector.h"
#include "transactions/MutableTransactionResult.h"
#include "util/ProtocolVersion.h"
#include <Tracy.hpp>

namespace stellar
{

bool
SorobanOpUtils::restoreFootprintEntries(
    AppConnector& app, AbstractLedgerTxn& ltx, TransactionFrame const& parentTx,
    DiagnosticEventBuffer& diagnosticEvents,
    rust::Vec<CxxLedgerEntryRentChange>& rustEntryRentChanges,
    uint32_t& ledgerReadByte, uint32_t& ledgerWriteByte)
{
    ZoneScoped;

    auto const& resources = parentTx.sorobanResources();
    auto const& footprint = resources.footprint;
    auto ledgerSeq = ltx.loadHeader().current().ledgerSeq;
    auto const& sorobanConfig = app.getSorobanNetworkConfigForApply();
    auto const& appConfig = app.getConfig();
    auto hotArchive = app.copySearchableHotArchiveBucketListSnapshot();

    auto const& archivalSettings = sorobanConfig.stateArchivalSettings();

    // Extend the TTL on the restored entry to minimum TTL, including
    // the current ledger.
    uint32_t restoredLiveUntilLedger =
        ledgerSeq + archivalSettings.minPersistentTTL - 1;

    for (auto const& lk : footprint.readWrite)
    {
        std::shared_ptr<HotArchiveBucketEntry const> hotArchiveEntry{nullptr};
        auto ttlKey = getTTLKey(lk);
        {
            // First check the live BucketList
            auto constTTLLtxe = ltx.loadWithoutRecord(ttlKey);
            if (!constTTLLtxe)
            {
                // Next check the hot archive if protocol >= 23
                if (protocolVersionStartsFrom(
                        ltx.getHeader().ledgerVersion,
                        HotArchiveBucket::
                            FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION))
                {
                    hotArchiveEntry = hotArchive->load(lk);
                    if (!hotArchiveEntry)
                    {
                        // Entry doesn't exist, skip
                        continue;
                    }
                }
                else
                {
                    // Entry doesn't exist, skip
                    continue;
                }
            }
            // Skip entry if it's already live.
            else if (isLive(constTTLLtxe.current(), ledgerSeq))
            {
                continue;
            }
        }

        // We must load the ContractCode/ContractData entry for fee purposes, as
        // restore is considered a write
        uint32_t entrySize = 0;
        if (hotArchiveEntry)
        {
            entrySize = static_cast<uint32>(
                xdr::xdr_size(hotArchiveEntry->archivedEntry()));
        }
        else
        {
            auto constEntryLtxe = ltx.loadWithoutRecord(lk);

            // We checked for TTLEntry existence above
            releaseAssertOrThrow(constEntryLtxe);

            entrySize =
                static_cast<uint32>(xdr::xdr_size(constEntryLtxe.current()));
        }

        ledgerReadByte += entrySize;
        if (resources.readBytes < ledgerReadByte)
        {
            diagnosticEvents.pushApplyTimeDiagnosticError(
                SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
                "operation byte-read resources exceeds amount specified",
                {makeU64SCVal(ledgerReadByte),
                 makeU64SCVal(resources.readBytes)});
            return false;
        }

        // To maintain consistency with InvokeHostFunction, TTLEntry
        // writes come out of refundable fee, so only add entrySize
        ledgerWriteByte += entrySize;
        if (!validateContractLedgerEntry(lk, entrySize, sorobanConfig,
                                         appConfig, parentTx, diagnosticEvents))
        {
            return false;
        }

        if (resources.writeBytes < ledgerWriteByte)
        {
            diagnosticEvents.pushApplyTimeDiagnosticError(
                SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
                "operation byte-write resources exceeds amount specified",
                {makeU64SCVal(ledgerWriteByte),
                 makeU64SCVal(resources.writeBytes)});
            return false;
        }

        rustEntryRentChanges.emplace_back();
        auto& rustChange = rustEntryRentChanges.back();
        rustChange.is_persistent = true;
        // Treat the entry as if it hasn't existed before restoration
        // for the rent fee purposes.
        rustChange.old_size_bytes = 0;
        rustChange.old_live_until_ledger = 0;
        rustChange.new_size_bytes = entrySize;
        rustChange.new_live_until_ledger = restoredLiveUntilLedger;

        if (hotArchiveEntry)
        {
            ltx.restoreFromHotArchive(hotArchiveEntry->archivedEntry(),
                                      restoredLiveUntilLedger);
        }
        else
        {
            // Entry exists in the live BucketList if we get this this point due
            // to the constTTLLtxe loadWithoutRecord logic above.
            ltx.restoreFromLiveBucketList(lk, restoredLiveUntilLedger);
        }
    }

    return true;
}
}