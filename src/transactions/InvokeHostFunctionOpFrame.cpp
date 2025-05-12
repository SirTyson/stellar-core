// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

// clang-format off
// This needs to be included first
#include "rust/RustVecXdrMarshal.h"
#include "TransactionUtils.h"
#include "util/GlobalChecks.h"
#include "util/ProtocolVersion.h"
#include "xdr/Stellar-ledger-entries.h"
#include <cstdint>
#include <json/json.h>
#include <medida/metrics_registry.h>
#include <xdrpp/types.h>
#include "xdr/Stellar-contract.h"
// clang-format on

#include "ledger/LedgerTxnImpl.h"
#include "rust/CppShims.h"
#include "xdr/Stellar-transaction.h"
#include <stdexcept>
#include <xdrpp/xdrpp/printer.h>

#include "ledger/LedgerManagerImpl.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTypeUtils.h"
#include "rust/RustBridge.h"
#include "transactions/InvokeHostFunctionOpFrame.h"
#include "transactions/MutableTransactionResult.h"
#include <Tracy.hpp>
#include <crypto/SHA.h>

namespace stellar
{
namespace
{
CxxLedgerInfo
getLedgerInfo(AbstractLedgerTxn& ltx, AppConnector& app,
              SorobanNetworkConfig const& sorobanConfig)
{
    CxxLedgerInfo info{};
    auto const& hdr = ltx.loadHeader().current();
    info.base_reserve = hdr.baseReserve;
    info.protocol_version = hdr.ledgerVersion;
    info.sequence_number = hdr.ledgerSeq;
    info.timestamp = hdr.scpValue.closeTime;
    info.memory_limit = sorobanConfig.txMemoryLimit();
    info.min_persistent_entry_ttl =
        sorobanConfig.stateArchivalSettings().minPersistentTTL;
    info.min_temp_entry_ttl =
        sorobanConfig.stateArchivalSettings().minTemporaryTTL;
    info.max_entry_ttl = sorobanConfig.stateArchivalSettings().maxEntryTTL;

    auto cpu = sorobanConfig.cpuCostParams();
    auto mem = sorobanConfig.memCostParams();

    info.cpu_cost_params = toCxxBuf(cpu);
    info.mem_cost_params = toCxxBuf(mem);

    auto& networkID = app.getNetworkID();
    info.network_id.reserve(networkID.size());
    for (auto c : networkID)
    {
        info.network_id.emplace_back(static_cast<unsigned char>(c));
    }
    return info;
}

DiagnosticEvent
metricsEvent(bool success, std::string&& topic, uint64_t value)
{
    DiagnosticEvent de;
    de.inSuccessfulContractCall = success;
    de.event.type = ContractEventType::DIAGNOSTIC;
    SCVec topics = {
        makeSymbolSCVal("core_metrics"),
        makeSymbolSCVal(std::move(topic)),
    };
    de.event.body.v0().topics = topics;
    de.event.body.v0().data = makeU64SCVal(value);
    return de;
}
}

HostFunctionMetrics::HostFunctionMetrics(SorobanMetrics& metrics)
    : mMetrics(metrics)
{
}

void
HostFunctionMetrics::noteReadEntry(bool isCodeEntry, uint32_t keySize,
                                   uint32_t entrySize)
{
    mReadEntry++;
    mReadKeyByte += keySize;
    mMaxReadWriteKeyByte = std::max(mMaxReadWriteKeyByte, keySize);
    mLedgerReadByte += entrySize;
    if (isCodeEntry)
    {
        mReadCodeByte += entrySize;
        mMaxReadWriteCodeByte = std::max(mMaxReadWriteCodeByte, entrySize);
    }
    else
    {
        mReadDataByte += entrySize;
        mMaxReadWriteDataByte = std::max(mMaxReadWriteDataByte, entrySize);
    }
}

void
HostFunctionMetrics::noteWriteEntry(bool isCodeEntry, uint32_t keySize,
                                    uint32_t entrySize)
{
    mWriteEntry++;
    mMaxReadWriteKeyByte = std::max(mMaxReadWriteKeyByte, keySize);
    mLedgerWriteByte += entrySize;
    if (isCodeEntry)
    {
        mWriteCodeByte += entrySize;
        mMaxReadWriteCodeByte = std::max(mMaxReadWriteCodeByte, entrySize);
    }
    else
    {
        mWriteDataByte += entrySize;
        mMaxReadWriteDataByte = std::max(mMaxReadWriteDataByte, entrySize);
    }
}

HostFunctionMetrics::~HostFunctionMetrics()
{
    mMetrics.mHostFnOpReadEntry.Mark(mReadEntry);
    mMetrics.mHostFnOpWriteEntry.Mark(mWriteEntry);

    mMetrics.mHostFnOpReadKeyByte.Mark(mReadKeyByte);
    mMetrics.mHostFnOpWriteKeyByte.Mark(mWriteKeyByte);

    mMetrics.mHostFnOpReadLedgerByte.Mark(mLedgerReadByte);
    mMetrics.mHostFnOpReadDataByte.Mark(mReadDataByte);
    mMetrics.mHostFnOpReadCodeByte.Mark(mReadCodeByte);

    mMetrics.mHostFnOpWriteLedgerByte.Mark(mLedgerWriteByte);
    mMetrics.mHostFnOpWriteDataByte.Mark(mWriteDataByte);
    mMetrics.mHostFnOpWriteCodeByte.Mark(mWriteCodeByte);

    mMetrics.mHostFnOpEmitEvent.Mark(mEmitEvent);
    mMetrics.mHostFnOpEmitEventByte.Mark(mEmitEventByte);

    mMetrics.mHostFnOpCpuInsn.Mark(mCpuInsn);
    mMetrics.mHostFnOpMemByte.Mark(mMemByte);
    mMetrics.mHostFnOpInvokeTimeNsecs.Update(
        std::chrono::nanoseconds(mInvokeTimeNsecs));
    mMetrics.mHostFnOpCpuInsnExclVm.Mark(mCpuInsnExclVm);
    mMetrics.mHostFnOpInvokeTimeNsecsExclVm.Update(
        std::chrono::nanoseconds(mInvokeTimeNsecsExclVm));
    mMetrics.mHostFnOpInvokeTimeFsecsCpuInsnRatio.Update(
        mInvokeTimeNsecs * 1000000 / std::max(mCpuInsn, uint64_t(1)));
    mMetrics.mHostFnOpInvokeTimeFsecsCpuInsnRatioExclVm.Update(
        mInvokeTimeNsecsExclVm * 1000000 /
        std::max(mCpuInsnExclVm, uint64_t(1)));
    mMetrics.mHostFnOpDeclaredInsnsUsageRatio.Update(
        mCpuInsn * 1000000 / std::max(mDeclaredCpuInsn, uint64_t(1)));

    mMetrics.mHostFnOpMaxRwKeyByte.Mark(mMaxReadWriteKeyByte);
    mMetrics.mHostFnOpMaxRwDataByte.Mark(mMaxReadWriteDataByte);
    mMetrics.mHostFnOpMaxRwCodeByte.Mark(mMaxReadWriteCodeByte);
    mMetrics.mHostFnOpMaxEmitEventByte.Mark(mMaxEmitEventByte);

    mMetrics.accumulateModelledCpuInsns(mCpuInsn, mCpuInsnExclVm,
                                        mInvokeTimeNsecs);

    if (mSuccess)
    {
        mMetrics.mHostFnOpSuccess.Mark();
    }
    else
    {
        mMetrics.mHostFnOpFailure.Mark();
    }
}

medida::TimerContext
HostFunctionMetrics::getExecTimer()
{
    return mMetrics.mHostFnOpExec.TimeScope();
}

InvokeHostFunctionOpFrame::InvokeHostFunctionOpFrame(
    Operation const& op, TransactionFrame const& parentTx)
    : OperationFrame(op, parentTx)
    , mInvokeHostFunction(mOperation.body.invokeHostFunctionOp())
{
}

bool
InvokeHostFunctionOpFrame::isOpSupported(LedgerHeader const& header) const
{
    return header.ledgerVersion >= 20;
}

void
InvokeHostFunctionOpFrame::maybePopulateDiagnosticEvents(
    Config const& cfg, InvokeHostFunctionOutput const& output,
    HostFunctionMetrics const& metrics, DiagnosticEventBuffer& buffer) const
{
    if (cfg.ENABLE_SOROBAN_DIAGNOSTIC_EVENTS)
    {
        xdr::xvector<DiagnosticEvent> diagnosticEvents;
        diagnosticEvents.reserve(output.diagnostic_events.size() + 20);
        for (auto const& e : output.diagnostic_events)
        {
            DiagnosticEvent evt;
            xdr::xdr_from_opaque(e.data, evt);
            diagnosticEvents.emplace_back(evt);
            CLOG_DEBUG(Tx, "Soroban diagnostic event: {}",
                       xdr::xdr_to_string(evt));
        }

        // add additional diagnostic events for metrics
        diagnosticEvents.emplace_back(
            metricsEvent(metrics.mSuccess, "read_entry", metrics.mReadEntry));
        diagnosticEvents.emplace_back(
            metricsEvent(metrics.mSuccess, "write_entry", metrics.mWriteEntry));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "ledger_read_byte", metrics.mLedgerReadByte));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "ledger_write_byte", metrics.mLedgerWriteByte));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "read_key_byte", metrics.mReadKeyByte));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "write_key_byte", metrics.mWriteKeyByte));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "read_data_byte", metrics.mReadDataByte));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "write_data_byte", metrics.mWriteDataByte));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "read_code_byte", metrics.mReadCodeByte));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "write_code_byte", metrics.mWriteCodeByte));
        diagnosticEvents.emplace_back(
            metricsEvent(metrics.mSuccess, "emit_event", metrics.mEmitEvent));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "emit_event_byte", metrics.mEmitEventByte));
        diagnosticEvents.emplace_back(
            metricsEvent(metrics.mSuccess, "cpu_insn", metrics.mCpuInsn));
        diagnosticEvents.emplace_back(
            metricsEvent(metrics.mSuccess, "mem_byte", metrics.mMemByte));
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "invoke_time_nsecs", metrics.mInvokeTimeNsecs));
        // skip publishing `cpu_insn_excl_vm` and `invoke_time_nsecs_excl_vm`,
        // we are mostly interested in those internally
        diagnosticEvents.emplace_back(metricsEvent(
            metrics.mSuccess, "max_rw_key_byte", metrics.mMaxReadWriteKeyByte));
        diagnosticEvents.emplace_back(
            metricsEvent(metrics.mSuccess, "max_rw_data_byte",
                         metrics.mMaxReadWriteDataByte));
        diagnosticEvents.emplace_back(
            metricsEvent(metrics.mSuccess, "max_rw_code_byte",
                         metrics.mMaxReadWriteCodeByte));
        diagnosticEvents.emplace_back(metricsEvent(metrics.mSuccess,
                                                   "max_emit_event_byte",
                                                   metrics.mMaxEmitEventByte));

        buffer.pushDiagnosticEvents(diagnosticEvents);
    }
}

bool
InvokeHostFunctionOpFrame::ApplyHelper::handleArchivedEntry(
    LedgerKey const& lk, LedgerEntry const& le, bool isReadOnly,
    uint32_t restoredLiveUntilLedger, bool isHotArchiveEntry)
{
    // autorestore support started in p23. Entry must be in the read write
    // footprint.
    if (!isReadOnly &&
        protocolVersionStartsFrom(
            mAppConfig.CURRENT_LEDGER_PROTOCOL_VERSION,
            HotArchiveBucket::FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION))
    {
        // In the auto restore case, we need to perform what are really 2
        // separate operations from a fee and rust host perspective:
        // 1. Restore the entry
        // 2. Pass the restored entry on to the rust host as a read-write entry
        //
        // To accomplish step 1, we'll add a rust change for the rent
        // calculation only and charge for disk reads. After charging for reads,
        // we'll then add the entry to the buffer with the updated TTL value for
        // step 2.

        auto leBuf = toCxxBuf(le);
        auto entrySize = static_cast<uint32>(leBuf.data->size());
        auto keySize = static_cast<uint32>(xdr::xdr_size(lk));

        // Charge for the restoration reads. TTLEntry writes come out of
        // refundable fee, so only meter the actual code/data entry here.
        mMetrics.noteReadEntry(isContractCodeEntry(lk), keySize, entrySize);
        if (!validateContractLedgerEntry(lk, entrySize, mSorobanConfig,
                                         mAppConfig, mOpFrame.mParentTx,
                                         mDiagnosticEvents))
        {
            mOpFrame.innerResult(mRes).code(
                INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
            return false;
        }

        if (mResources.diskReadBytes < mMetrics.mLedgerReadByte)
        {
            mDiagnosticEvents.pushApplyTimeDiagnosticError(
                SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
                "operation byte-read resources exceeds amount specified",
                {makeU64SCVal(mMetrics.mLedgerReadByte),
                 makeU64SCVal(mResources.diskReadBytes)});

            mOpFrame.innerResult(mRes).code(
                INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
            return false;
        }

        // After charging for the disk read, charge for rent.
        mAutorestoreRustEntryRentChanges.emplace_back();
        auto& rustChange = mAutorestoreRustEntryRentChanges.back();
        rustChange.is_persistent = true;
        rustChange.old_size_bytes = 0;
        rustChange.old_live_until_ledger = 0;
        rustChange.new_size_bytes = entrySize;
        rustChange.new_live_until_ledger = restoredLiveUntilLedger;

        // Restore the entry to the live BucketList
        LedgerTxnEntry ttlEntry;
        if (isHotArchiveEntry)
        {
            ttlEntry = mLtx.restoreFromHotArchive(le, restoredLiveUntilLedger);
        }
        else
        {
            ttlEntry =
                mLtx.restoreFromLiveBucketList(le, restoredLiveUntilLedger);
        }

        // Finally, add the entries to the Cxx buffer as if they were live. If
        // the restored entry is rent-bumped or changes size during the actual
        // invocation, these additional fees will be covered by the invocation
        // logic. At the end of doApply, we will charge for writes based on the
        // final size of the entry, since this is what gets written to the
        // ledger. Note that we charge minimum rent and read fees based on the
        // original restored size of the entry, not the final size.
        mLedgerEntryCxxBufs.emplace_back(std::move(leBuf));
        auto ttlBuf = toCxxBuf(ttlEntry.current().data.ttl());
        mTtlEntryCxxBufs.emplace_back(std::move(ttlBuf));

        return true;
    }

    // Before p23, archived entries are never valid
    if (lk.type() == CONTRACT_CODE)
    {
        mDiagnosticEvents.pushApplyTimeDiagnosticError(
            SCE_VALUE, SCEC_INVALID_INPUT,
            "trying to access an archived contract code entry",
            {makeBytesSCVal(lk.contractCode().hash)});
    }
    else if (lk.type() == CONTRACT_DATA)
    {
        mDiagnosticEvents.pushApplyTimeDiagnosticError(
            SCE_VALUE, SCEC_INVALID_INPUT,
            "trying to access an archived contract data entry",
            {makeAddressSCVal(lk.contractData().contract),
             lk.contractData().key});
    }

    mOpFrame.innerResult(mRes).code(INVOKE_HOST_FUNCTION_ENTRY_ARCHIVED);
    return false;
}

InvokeHostFunctionOpFrame::ApplyHelper::ApplyHelper(
    AppConnector& app, AbstractLedgerTxn& ltx, Hash const& sorobanBasePrngSeed,
    OperationResult& res, std::shared_ptr<SorobanTxData> sorobanData,
    OpEventManager& opEventManager, InvokeHostFunctionOpFrame const& opFrame)
    : mApp(app)
    , mLtx(ltx)
    , mRes(res)
    , mSorobanData(sorobanData)
    , mOpEventManager(opEventManager)
    , mOpFrame(opFrame)
    , mSorobanBasePrngSeed(sorobanBasePrngSeed)
    , mResources(mOpFrame.mParentTx.sorobanResources())
    , mSorobanConfig(app.getSorobanNetworkConfigForApply())
    , mAppConfig(app.getConfig())
    , mMetrics(app.getSorobanMetrics())
    , mHotArchive(app.copySearchableHotArchiveBucketListSnapshot())
    , mDiagnosticEvents(mOpEventManager.getDiagnosticEventsBuffer())
{
    mMetrics.mDeclaredCpuInsn = mResources.instructions;

    auto const& footprint = mResources.footprint;
    auto footprintLength =
        footprint.readOnly.size() + footprint.readWrite.size();

    // Get the entries for the footprint
    mLedgerEntryCxxBufs.reserve(footprintLength);
    mTtlEntryCxxBufs.reserve(footprintLength);
}

bool
InvokeHostFunctionOpFrame::ApplyHelper::addReads(
    xdr::xvector<LedgerKey> const& keys, bool isReadOnly)
{
    auto ledgerSeq = mLtx.loadHeader().current().ledgerSeq;
    auto restoredLiveUntilLedger =
        ledgerSeq + mSorobanConfig.stateArchivalSettings().minPersistentTTL - 1;
    for (auto const& lk : keys)
    {
        uint32_t keySize = static_cast<uint32_t>(xdr::xdr_size(lk));
        uint32_t entrySize = 0u;
        std::optional<TTLEntry> ttlEntry;
        bool sorobanEntryLive = false;

        // For soroban entries, check if the entry is expired before loading
        if (isSorobanEntry(lk))
        {
            auto ttlKey = getTTLKey(lk);

            // handleArchiveEntry may need to load the TTL key to write the
            // restored TTL, so make sure ttlLtxe destrects before calling
            // handleArchiveEntry
            std::optional<LedgerEntry> ttlEntryOp;
            {
                auto ttlLtxe = mLtx.loadWithoutRecord(ttlKey);
                if (ttlLtxe)
                {
                    ttlEntryOp = ttlLtxe.current();
                }
            }

            if (ttlEntryOp)
            {
                if (!isLive(ttlEntryOp.value(), ledgerSeq))
                {
                    // For temporary entries, treat the expired entry as
                    // if the key did not exist
                    if (!isTemporaryEntry(lk))
                    {
                        auto leLtxe = mLtx.loadWithoutRecord(lk);
                        if (!handleArchivedEntry(lk, leLtxe.current(),
                                                 isReadOnly,
                                                 restoredLiveUntilLedger,
                                                 /*isHotArchiveEntry=*/false))
                        {
                            return false;
                        }

                        continue;
                    }
                }
                else
                {
                    sorobanEntryLive = true;
                    ttlEntry = ttlEntryOp->data.ttl();
                }
            }
            // If ttlLtxe doesn't exist, this is a new Soroban entry
            // Starting in protocol 23, we must check the Hot Archive for
            // new keys. If a new key is actually archived, fail the op.
            else if (isPersistentEntry(lk) &&
                     protocolVersionStartsFrom(
                         mLtx.getHeader().ledgerVersion,
                         HotArchiveBucket::
                             FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION))
            {
                auto archiveEntry = mHotArchive->load(lk);
                if (archiveEntry)
                {
                    releaseAssert(
                        archiveEntry->type() ==
                        HotArchiveBucketEntryType::HOT_ARCHIVE_ARCHIVED);
                    if (!handleArchivedEntry(lk, archiveEntry->archivedEntry(),
                                             isReadOnly,
                                             restoredLiveUntilLedger,
                                             /*isHotArchiveEntry=*/true))
                    {
                        return false;
                    }

                    continue;
                }
            }
        }

        if (!isSorobanEntry(lk) || sorobanEntryLive)
        {
            auto ltxe = mLtx.loadWithoutRecord(lk);
            if (ltxe)
            {
                auto leBuf = toCxxBuf(ltxe.current());
                entrySize = static_cast<uint32_t>(leBuf.data->size());

                // For entry types that don't have an ttlEntry (i.e.
                // Accounts), the rust host expects an "empty" CxxBuf such
                // that the buffer has a non-null pointer that points to an
                // empty byte vector
                auto ttlBuf =
                    ttlEntry ? toCxxBuf(*ttlEntry)
                             : CxxBuf{std::make_unique<std::vector<uint8_t>>()};

                mLedgerEntryCxxBufs.emplace_back(std::move(leBuf));
                mTtlEntryCxxBufs.emplace_back(std::move(ttlBuf));
            }
            else if (isSorobanEntry(lk))
            {
                releaseAssertOrThrow(!ttlEntry);
            }
        }

        // TODO: When we switch to in-memory read resource, this block should be
        // changed to classic only, since we charge for reads of archived state
        // (i.e. disk state) in handleArchivedEntry.
        mMetrics.noteReadEntry(isContractCodeEntry(lk), keySize, entrySize);
        if (!validateContractLedgerEntry(lk, entrySize, mSorobanConfig,
                                         mAppConfig, mOpFrame.mParentTx,
                                         mDiagnosticEvents))
        {
            mOpFrame.innerResult(mRes).code(
                INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
            return false;
        }

        if (mResources.diskReadBytes < mMetrics.mLedgerReadByte)
        {
            mDiagnosticEvents.pushApplyTimeDiagnosticError(
                SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
                "operation byte-read resources exceeds amount specified",
                {makeU64SCVal(mMetrics.mLedgerReadByte),
                 makeU64SCVal(mResources.diskReadBytes)});

            mOpFrame.innerResult(mRes).code(
                INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
            return false;
        }
    }
    return true;
}

bool
InvokeHostFunctionOpFrame::ApplyHelper::apply()
{
    ZoneNamedN(applyZone, "InvokeHostFunctionOpFrame apply", true);
    auto timeScope = mMetrics.getExecTimer();
    auto const& footprint = mResources.footprint;

    if (!addReads(footprint.readOnly, /*isReadOnly=*/true))
    {
        // Error code set in addReads
        return false;
    }

    if (!addReads(footprint.readWrite, /*isReadOnly=*/false))
    {
        // Error code set in addReads
        return false;
    }

    rust::Vec<CxxBuf> authEntryCxxBufs;
    authEntryCxxBufs.reserve(mOpFrame.mInvokeHostFunction.auth.size());
    for (auto const& authEntry : mOpFrame.mInvokeHostFunction.auth)
    {
        authEntryCxxBufs.emplace_back(toCxxBuf(authEntry));
    }

    InvokeHostFunctionOutput out{};
    out.success = false;
    try
    {
        CxxBuf basePrngSeedBuf{};
        basePrngSeedBuf.data = std::make_unique<std::vector<uint8_t>>();
        basePrngSeedBuf.data->assign(mSorobanBasePrngSeed.begin(),
                                     mSorobanBasePrngSeed.end());
        auto moduleCache = mApp.getModuleCache();
        out = rust_bridge::invoke_host_function(
            mAppConfig.CURRENT_LEDGER_PROTOCOL_VERSION,
            mAppConfig.ENABLE_SOROBAN_DIAGNOSTIC_EVENTS,
            mResources.instructions,
            toCxxBuf(mOpFrame.mInvokeHostFunction.hostFunction),
            toCxxBuf(mResources), toCxxBuf(mOpFrame.getSourceID()),
            authEntryCxxBufs, getLedgerInfo(mLtx, mApp, mSorobanConfig),
            mLedgerEntryCxxBufs, mTtlEntryCxxBufs, basePrngSeedBuf,
            mSorobanConfig.rustBridgeRentFeeConfiguration(), *moduleCache);
        mMetrics.mCpuInsn = out.cpu_insns;
        mMetrics.mMemByte = out.mem_bytes;
        mMetrics.mInvokeTimeNsecs = out.time_nsecs;
        mMetrics.mCpuInsnExclVm = out.cpu_insns_excluding_vm_instantiation;
        mMetrics.mInvokeTimeNsecsExclVm =
            out.time_nsecs_excluding_vm_instantiation;
        if (!out.success)
        {
            mOpFrame.maybePopulateDiagnosticEvents(mAppConfig, out, mMetrics,
                                                   mDiagnosticEvents);
        }
    }
    catch (std::exception& e)
    {
        // Host invocations should never throw an exception, so encountering
        // one would be an internal error.
        out.is_internal_error = true;
        CLOG_DEBUG(Tx, "Exception caught while invoking host fn: {}", e.what());
    }

    if (!out.success)
    {
        if (out.is_internal_error)
        {
            throw std::runtime_error(
                "Got internal error during Soroban host invocation.");
        }
        if (mResources.instructions < out.cpu_insns)
        {
            mDiagnosticEvents.pushApplyTimeDiagnosticError(
                SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
                "operation instructions exceeds amount specified",
                {makeU64SCVal(out.cpu_insns),
                 makeU64SCVal(mResources.instructions)});
            mOpFrame.innerResult(mRes).code(
                INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
        }
        else if (mSorobanConfig.txMemoryLimit() < out.mem_bytes)
        {
            mDiagnosticEvents.pushApplyTimeDiagnosticError(
                SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
                "operation memory usage exceeds network config limit",
                {makeU64SCVal(out.mem_bytes),
                 makeU64SCVal(mSorobanConfig.txMemoryLimit())});
            mOpFrame.innerResult(mRes).code(
                INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
        }
        else
        {
            mOpFrame.innerResult(mRes).code(INVOKE_HOST_FUNCTION_TRAPPED);
        }
        return false;
    }

    // Create or update every entry returned.
    UnorderedSet<LedgerKey> createdAndModifiedKeys;
    UnorderedSet<LedgerKey> createdKeys;
    for (auto const& buf : out.modified_ledger_entries)
    {
        LedgerEntry le;
        xdr::xdr_from_opaque(buf.data, le);
        if (!validateContractLedgerEntry(LedgerEntryKey(le), buf.data.size(),
                                         mSorobanConfig, mAppConfig,
                                         mOpFrame.mParentTx, mDiagnosticEvents))
        {
            mOpFrame.innerResult(mRes).code(
                INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
            return false;
        }

        auto lk = LedgerEntryKey(le);
        createdAndModifiedKeys.insert(lk);

        uint32_t keySize = static_cast<uint32_t>(xdr::xdr_size(lk));
        uint32_t entrySize = static_cast<uint32_t>(buf.data.size());

        // ttlEntry write fees come out of refundableFee, already
        // accounted for by the host
        if (lk.type() != TTL)
        {
            mMetrics.noteWriteEntry(isContractCodeEntry(lk), keySize, entrySize);
            if (mResources.writeBytes < mMetrics.mLedgerWriteByte)
            {
                mDiagnosticEvents.pushApplyTimeDiagnosticError(
                    SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
                    "operation byte-write resources exceeds amount specified",
                    {makeU64SCVal(mMetrics.mLedgerWriteByte),
                     makeU64SCVal(mResources.writeBytes)});
                mOpFrame.innerResult(mRes).code(
                    INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
                return false;
            }
        }

        auto ltxe = mLtx.load(lk);
        if (ltxe)
        {
            ltxe.current() = le;
        }
        else
        {
            mLtx.create(le);
            createdKeys.insert(lk);
        }
    }

    // Check that each newly created ContractCode or ContractData entry also
    // creates an ttlEntry
    for (auto const& key : createdKeys)
    {
        if (isSorobanEntry(key))
        {
            auto ttlKey = getTTLKey(key);
            releaseAssertOrThrow(createdKeys.find(ttlKey) != createdKeys.end());
        }
        else
        {
            releaseAssertOrThrow(key.type() == TTL);
        }
    }

    // Erase every entry not returned.
    // NB: The entries that haven't been touched are passed through
    // from host, so this should never result in removing an entry
    // that hasn't been removed by host explicitly.
    for (auto const& lk : footprint.readWrite)
    {
        if (createdAndModifiedKeys.find(lk) == createdAndModifiedKeys.end())
        {
            auto ltxe = mLtx.load(lk);
            if (ltxe)
            {
                releaseAssertOrThrow(isSorobanEntry(lk));
                mLtx.erase(lk);

                // Also delete associated ttlEntry
                auto ttlLK = getTTLKey(lk);
                auto ttlLtxe = mLtx.load(ttlLK);
                releaseAssertOrThrow(ttlLtxe);
                mLtx.erase(ttlLK);
            }
        }
    }

    // Append events to the enclosing TransactionFrame, where
    // they'll be picked up and transferred to the TxMeta.
    InvokeHostFunctionSuccessPreImage success{};
    success.events.reserve(out.contract_events.size());
    for (auto const& buf : out.contract_events)
    {
        mMetrics.mEmitEvent++;
        uint32_t eventSize = static_cast<uint32_t>(buf.data.size());
        mMetrics.mEmitEventByte += eventSize;
        mMetrics.mMaxEmitEventByte =
            std::max(mMetrics.mMaxEmitEventByte, eventSize);
        if (mSorobanConfig.txMaxContractEventsSizeBytes() <
            mMetrics.mEmitEventByte)
        {
            mDiagnosticEvents.pushApplyTimeDiagnosticError(
                SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
                "total events size exceeds network config maximum",
                {makeU64SCVal(mMetrics.mEmitEventByte),
                 makeU64SCVal(mSorobanConfig.txMaxContractEventsSizeBytes())});
            mOpFrame.innerResult(mRes).code(
                INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
            return false;
        }
        ContractEvent evt;
        xdr::xdr_from_opaque(buf.data, evt);
        success.events.emplace_back(evt);
    }

    mOpFrame.maybePopulateDiagnosticEvents(mAppConfig, out, mMetrics,
                                           mDiagnosticEvents);

    mMetrics.mEmitEventByte +=
        static_cast<uint32>(out.result_value.data.size());
    if (mSorobanConfig.txMaxContractEventsSizeBytes() < mMetrics.mEmitEventByte)
    {
        mDiagnosticEvents.pushApplyTimeDiagnosticError(
            SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
            "return value pushes events size above network config maximum",
            {makeU64SCVal(mMetrics.mEmitEventByte),
             makeU64SCVal(mSorobanConfig.txMaxContractEventsSizeBytes())});
        mOpFrame.innerResult(mRes).code(
            INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED);
        return false;
    }

    // Calculate refundable fees (rent) for autorestored entries.
    int64_t autorestoreFee = 0;

    auto const& header = mLtx.getHeader();
    auto ledgerSeq = header.ledgerSeq;
    auto ledgerVersion = header.ledgerVersion;
    if (!mAutorestoreRustEntryRentChanges.empty())
    {
        releaseAssertOrThrow(protocolVersionStartsFrom(
            ledgerVersion,
            HotArchiveBucket::FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION));
        autorestoreFee = rust_bridge::compute_rent_fee(
            mAppConfig.CURRENT_LEDGER_PROTOCOL_VERSION, ledgerVersion,
            mAutorestoreRustEntryRentChanges,
            mSorobanConfig.rustBridgeRentFeeConfiguration(), ledgerSeq);
    }

    if (!mSorobanData->consumeRefundableSorobanResources(
            mMetrics.mEmitEventByte, out.rent_fee + autorestoreFee,
            ledgerVersion, mSorobanConfig, mAppConfig, mOpFrame.mParentTx,
            mDiagnosticEvents))
    {
        mOpFrame.innerResult(mRes).code(
            INVOKE_HOST_FUNCTION_INSUFFICIENT_REFUNDABLE_FEE);
        return false;
    }

    xdr::xdr_from_opaque(out.result_value.data, success.returnValue);
    mOpFrame.innerResult(mRes).code(INVOKE_HOST_FUNCTION_SUCCESS);
    mOpFrame.innerResult(mRes).success() = xdrSha256(success);

    mOpEventManager.pushContractEvents(success.events);
    mSorobanData->setReturnValue(success.returnValue);
    mMetrics.mSuccess = true;
    return true;
}

bool
InvokeHostFunctionOpFrame::doApply(AppConnector& app, AbstractLedgerTxn& ltx,
                                   Hash const& sorobanBasePrngSeed,
                                   OperationResult& res,
                                   std::shared_ptr<SorobanTxData> sorobanData,
                                   OpEventManager& opEventManager) const
{
    releaseAssertOrThrow(sorobanData);

    // Create ApplyHelper and delegate processing to it
    ApplyHelper helper(app, ltx, sorobanBasePrngSeed, res, sorobanData,
                       opEventManager, *this);
    return helper.apply();
}

bool
InvokeHostFunctionOpFrame::doCheckValidForSoroban(
    SorobanNetworkConfig const& networkConfig, Config const& appConfig,
    uint32_t ledgerVersion, OperationResult& res,
    DiagnosticEventBuffer* diagnosticEvents) const
{
    // check wasm size if uploading contract
    auto const& hostFn = mInvokeHostFunction.hostFunction;
    if (hostFn.type() == HOST_FUNCTION_TYPE_UPLOAD_CONTRACT_WASM &&
        hostFn.wasm().size() > networkConfig.maxContractSizeBytes())
    {
        pushValidationTimeDiagnosticError(
            diagnosticEvents, SCE_BUDGET, SCEC_EXCEEDED_LIMIT,
            "uploaded Wasm size exceeds network config maximum contract size",
            {makeU64SCVal(hostFn.wasm().size()),
             makeU64SCVal(networkConfig.maxContractSizeBytes())});
        return false;
    }
    if (hostFn.type() == HOST_FUNCTION_TYPE_CREATE_CONTRACT)
    {
        auto const& preimage = hostFn.createContract().contractIDPreimage;
        if (preimage.type() == CONTRACT_ID_PREIMAGE_FROM_ASSET &&
            !isAssetValid(preimage.fromAsset(), ledgerVersion))
        {
            pushValidationTimeDiagnosticError(
                diagnosticEvents, SCE_VALUE, SCEC_INVALID_INPUT,
                "invalid asset to create contract from");
            return false;
        }
    }
    return true;
}

bool
InvokeHostFunctionOpFrame::doCheckValid(uint32_t ledgerVersion,
                                        OperationResult& res) const
{
    throw std::runtime_error(
        "InvokeHostFunctionOpFrame::doCheckValid needs Config");
}

void
InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch(
    UnorderedSet<LedgerKey>& keys) const
{
}

bool
InvokeHostFunctionOpFrame::isSoroban() const
{
    return true;
}
}
