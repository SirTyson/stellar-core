// Copyright 2023 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/RestoreFootprintOpFrame.h"
#include "TransactionUtils.h"
#include "ledger/LedgerManagerImpl.h"
#include "ledger/LedgerTypeUtils.h"
#include "medida/meter.h"
#include "medida/timer.h"
#include "transactions/MutableTransactionResult.h"
#include "transactions/SorobanOpUtils.h"
#include <Tracy.hpp>

namespace stellar
{

struct RestoreFootprintMetrics
{
    SorobanMetrics& mMetrics;

    uint32_t mLedgerReadByte{0};
    uint32_t mLedgerWriteByte{0};

    RestoreFootprintMetrics(SorobanMetrics& metrics) : mMetrics(metrics)
    {
    }

    ~RestoreFootprintMetrics()
    {
        mMetrics.mRestoreFpOpReadLedgerByte.Mark(mLedgerReadByte);
        mMetrics.mRestoreFpOpWriteLedgerByte.Mark(mLedgerWriteByte);
    }
    medida::TimerContext
    getExecTimer()
    {
        return mMetrics.mRestoreFpOpExec.TimeScope();
    }
};

RestoreFootprintOpFrame::RestoreFootprintOpFrame(
    Operation const& op, TransactionFrame const& parentTx)
    : OperationFrame(op, parentTx)
    , mRestoreFootprintOp(mOperation.body.restoreFootprintOp())
{
}

bool
RestoreFootprintOpFrame::isOpSupported(LedgerHeader const& header) const
{
    return header.ledgerVersion >= 20;
}

bool
RestoreFootprintOpFrame::doApply(AppConnector& app, AbstractLedgerTxn& ltx,
                                 Hash const& sorobanBasePrngSeed,
                                 OperationResult& res,
                                 std::shared_ptr<SorobanTxData> sorobanData,
                                 OpEventManager& opEventManager) const
{
    ZoneNamedN(applyZone, "RestoreFootprintOpFrame apply", true);

    RestoreFootprintMetrics metrics(app.getSorobanMetrics());
    auto timeScope = metrics.getExecTimer();

    auto& diagnosticEvents = opEventManager.getDiagnosticEventsBuffer();
    auto const& resources = mParentTx.sorobanResources();
    auto const& footprint = resources.footprint;
    rust::Vec<CxxLedgerEntryRentChange> rustEntryRentChanges;
    rustEntryRentChanges.reserve(footprint.readWrite.size());

    if (!SorobanOpUtils::restoreFootprintEntries(
            app, ltx, mParentTx, diagnosticEvents, rustEntryRentChanges,
            metrics.mLedgerReadByte, metrics.mLedgerWriteByte))
    {
        innerResult(res).code(RESTORE_FOOTPRINT_RESOURCE_LIMIT_EXCEEDED);
        return false;
    }

    uint32_t ledgerVersion = ltx.loadHeader().current().ledgerVersion;
    auto const& sorobanConfig = app.getSorobanNetworkConfigForApply();
    int64_t rentFee = rust_bridge::compute_rent_fee(
        app.getConfig().CURRENT_LEDGER_PROTOCOL_VERSION, ledgerVersion,
        rustEntryRentChanges, sorobanConfig.rustBridgeRentFeeConfiguration(),
        ltx.loadHeader().current().ledgerSeq);

    if (!sorobanData->consumeRefundableSorobanResources(
            0, rentFee, ledgerVersion, sorobanConfig, app.getConfig(),
            mParentTx, diagnosticEvents))
    {
        innerResult(res).code(RESTORE_FOOTPRINT_INSUFFICIENT_REFUNDABLE_FEE);
        return false;
    }
    innerResult(res).code(RESTORE_FOOTPRINT_SUCCESS);
    return true;
}

bool
RestoreFootprintOpFrame::doCheckValidForSoroban(
    SorobanNetworkConfig const& networkConfig, Config const& appConfig,
    uint32_t ledgerVersion, OperationResult& res,
    DiagnosticEventBuffer* diagnosticEvents) const
{
    auto const& footprint = mParentTx.sorobanResources().footprint;
    if (!footprint.readOnly.empty())
    {
        innerResult(res).code(RESTORE_FOOTPRINT_MALFORMED);
        pushValidationTimeDiagnosticError(
            diagnosticEvents, SCE_STORAGE, SCEC_INVALID_INPUT,
            "read-only footprint must be empty for RestoreFootprint operation",
            {});
        return false;
    }

    for (auto const& lk : footprint.readWrite)
    {
        if (!isPersistentEntry(lk))
        {
            innerResult(res).code(RESTORE_FOOTPRINT_MALFORMED);
            pushValidationTimeDiagnosticError(
                diagnosticEvents, SCE_STORAGE, SCEC_INVALID_INPUT,
                "only persistent Soroban entries can be restored", {});
            return false;
        }
    }

    return true;
}

bool
RestoreFootprintOpFrame::doCheckValid(uint32_t ledgerVersion,
                                      OperationResult& res) const
{
    throw std::runtime_error(
        "RestoreFootprintOpFrame::doCheckValid needs Config");
}

void
RestoreFootprintOpFrame::insertLedgerKeysToPrefetch(
    UnorderedSet<LedgerKey>& keys) const
{
}

bool
RestoreFootprintOpFrame::isSoroban() const
{
    return true;
}

ThresholdLevel
RestoreFootprintOpFrame::getThresholdLevel() const
{
    return ThresholdLevel::LOW;
}
}
