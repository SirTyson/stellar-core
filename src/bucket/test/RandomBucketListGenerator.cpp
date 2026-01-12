// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/test/RandomBucketListGenerator.h"
#include "bucket/BucketIndexUtils.h"
#include "bucket/BucketInputIterator.h"
#include "bucket/BucketManager.h"
#include "bucket/BucketOutputIterator.h"
#include "crypto/Hex.h"
#include "ledger/LedgerTypeUtils.h"
#include "ledger/test/LedgerTestUtils.h"
#include "main/Application.h"
#include "main/Config.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "util/ProtocolVersion.h"
#include <filesystem>
#include <fmt/format.h>
#include <optional>

namespace stellar
{

namespace
{
// Linear interpolation of protocol versions across BucketList levels.
// Returns minVersion at the bottom level and maxVersion at the top level.
uint32_t
interpolateVersion(uint32_t level, uint32_t numLevels, uint32_t minVersion,
                   uint32_t maxVersion)
{
    return (maxVersion - minVersion) * (numLevels - 1 - level) /
               (numLevels - 1) +
           minVersion;
}

// Returns how many more entries can be scheduled for a bucket location.
// DELETE and RECREATE events create 2 entries for Soroban (parent + TTL).
size_t
getRemainingCapacity(
    BucketLocation const& loc, std::vector<LevelPlan> const& plans,
    std::map<BucketLocation, std::vector<PendingEvent>> const& pendingEvents)
{
    auto const& plan = plans[loc.level];
    size_t target = loc.isCurr ? plan.currEntryCount : plan.snapEntryCount;

    // Estimate how many entries the scheduled events will create
    size_t estimatedEntries = 0;
    for (auto const& event : pendingEvents.at(loc))
    {
        // DELETE and RECREATE events create 2 entries for Soroban (parent +
        // TTL).
        bool isSoroban = isSorobanEntry(LedgerEntryKey(event.lastEntryValue));
        if (isSoroban && (event.type == EventType::DELETE ||
                          event.type == EventType::RECREATE))
        {
            estimatedEntries += 2;
        }
        else
        {
            estimatedEntries += 1;
        }
    }

    return (target > estimatedEntries) ? target - estimatedEntries : 0;
}

// Hot archive version - each event creates exactly 1 entry
size_t
getRemainingCapacity(
    BucketLocation const& loc, std::vector<LevelPlan> const& plans,
    std::map<BucketLocation, std::vector<HotArchivePendingEvent>> const&
        pendingEvents)
{
    auto const& plan = plans[loc.level];
    size_t target = loc.isCurr ? plan.currEntryCount : plan.snapEntryCount;
    size_t scheduled = pendingEvents.at(loc).size();
    return (target > scheduled) ? target - scheduled : 0;
}

// Selects a random bucket location weighted by remaining capacity and schedules
// the event. minLocation specifies the current bucket being processed, where
// events are scheduled to buckets "above" it. Returns true if the event was
// scheduled, false if dropped (no remaining capacity).
template <typename EventT, typename PendingEventMap>
bool
scheduleLiveBucketListEventAtWeightedLocation(
    EventT event, BucketLocation const& minLocation,
    std::vector<LevelPlan> const& plans, PendingEventMap& pendingEvents)
{
    // Build weighted candidate list of buckets with remaining capacity.
    std::vector<std::pair<BucketLocation, size_t>> candidates;
    size_t totalWeight = 0;

    auto tryAddCandidate = [&](BucketLocation const& loc) {
        size_t cap = getRemainingCapacity(loc, plans, pendingEvents);
        if (cap > 0)
        {
            candidates.emplace_back(loc, cap);
            totalWeight += cap;
        }
    };

    for (uint32_t level = 0; level < minLocation.level; ++level)
    {
        tryAddCandidate({level, true});
        tryAddCandidate({level, false});
    }

    // If processing snap, can also schedule to curr at the same level
    if (!minLocation.isCurr)
    {
        tryAddCandidate({minLocation.level, true});
    }

    if (candidates.empty())
    {
        return false;
    }

    // Weighted random selection from candidates.
    size_t roll = rand_uniform<size_t>(0, totalWeight - 1);
    size_t cumulative = 0;
    for (auto const& [loc, weight] : candidates)
    {
        cumulative += weight;
        if (roll < cumulative)
        {
            pendingEvents.at(loc).push_back(std::move(event));
            return true;
        }
    }

    pendingEvents.at(candidates.back().first).push_back(std::move(event));
    return true;
}

// Counts non-meta entries in a bucket.
template <typename BucketT>
size_t
countBucketEntries(std::shared_ptr<BucketT> const& bucket)
{
    if (bucket->isEmpty())
    {
        return 0;
    }

    size_t count = 0;
    for (BucketInputIterator<BucketT> iter(bucket); iter; ++iter)
    {
        ++count;
    }
    return count;
}

// Validates that each bucket's entry count roughly matches the plan.
template <typename BucketT>
void
validateEntryCounts(std::vector<std::shared_ptr<BucketT>> const& currBuckets,
                    std::vector<std::shared_ptr<BucketT>> const& snapBuckets,
                    std::vector<LevelPlan> const& plans)
{
    // Allow some deviation, as we guarantee at least 10 INIT entries per bucket
    // regardless of capacity, and can sometimes under schedule due to restores.
    constexpr double kTolerance = 0.05;

    auto checkBucket = [&](std::shared_ptr<BucketT> const& bucket,
                           size_t expected, uint32_t level,
                           std::string const& name) {
        size_t count = countBucketEntries<BucketT>(bucket);
        size_t minCount = static_cast<size_t>(expected * (1.0 - kTolerance));
        size_t maxCount = static_cast<size_t>(expected * (1.0 + kTolerance));
        if (count < minCount || count > maxCount)
        {
            throw std::runtime_error(
                fmt::format("Level {} {} bucket has {} entries, expected {}-{}",
                            level, name, count, minCount, maxCount));
        }
    };

    for (uint32_t level = 0; level < plans.size(); ++level)
    {
        auto const& plan = plans[level];
        checkBucket(currBuckets[level], plan.currEntryCount, level, "curr");
        checkBucket(snapBuckets[level], plan.snapEntryCount, level, "snap");
    }
}

template <typename BucketT>
void
validateProtocols(std::vector<std::shared_ptr<BucketT>> const& currBuckets,
                  std::vector<std::shared_ptr<BucketT>> const& snapBuckets,
                  uint32_t minProtocolVersion)
{
    // Check monotonicity (protocol versions increase from bottom to top),
    // starting at the min version and ending at the max supported current
    // version.
    bool hasCurrentVersion = false;
    bool checkedFirstBucket = false;
    uint32_t prevVersion = 0;

    auto checkBucket = [&](std::shared_ptr<BucketT> const& bucket) {
        auto version = bucket->getBucketVersion();
        if (!checkedFirstBucket)
        {
            if (version != minProtocolVersion)
            {
                throw std::runtime_error(fmt::format(
                    "First non-empty bucket has version {}, expected {}",
                    version, minProtocolVersion));
            }
            checkedFirstBucket = true;
        }
        if (version < prevVersion)
        {
            throw std::runtime_error("Protocol versions not monotonic");
        }
        prevVersion = version;
        if (version == Config::CURRENT_LEDGER_PROTOCOL_VERSION)
        {
            hasCurrentVersion = true;
        }
    };

    // Process oldest to newest: snap before curr within each level
    for (int32_t level = BucketListBase<BucketT>::kNumLevels - 1; level >= 0;
         --level)
    {
        checkBucket(snapBuckets[level]);
        checkBucket(currBuckets[level]);
    }

    if (!hasCurrentVersion)
    {
        throw std::runtime_error("No bucket with current protocol version");
    }
}

std::string
lifecycleToString(LiveLifecycle lifecycle)
{
    switch (lifecycle)
    {
    case LiveLifecycle::CREATE_ONLY:
        return "CREATE_ONLY";
    case LiveLifecycle::UPDATE:
        return "UPDATE";
    case LiveLifecycle::DELETE:
        return "DELETE";
    case LiveLifecycle::RECREATE:
        return "RECREATE";
    }

    releaseAssert(false);
}

// Validates that each entry type has minimum counts for each lifecycle.
void
validateLifecycleCounts(LiveBucketStats const& stats)
{
    std::vector<LiveLifecycle> const lifecycles = {
        LiveLifecycle::CREATE_ONLY, LiveLifecycle::UPDATE,
        LiveLifecycle::DELETE, LiveLifecycle::RECREATE};

    for (auto const& [entryType, counts] : stats.lifecycleCounts)
    {
        for (auto lifecycle : lifecycles)
        {
            size_t count = counts.count(lifecycle) ? counts.at(lifecycle) : 0;
            if (count < MIN_ENTRIES_PER_CATEGORY)
            {
                throw std::runtime_error(
                    fmt::format("{} {} count {} < {}", toString(entryType),
                                lifecycleToString(lifecycle), count,
                                MIN_ENTRIES_PER_CATEGORY));
            }
        }
    }
}

template <typename BucketT, typename ClockT>
void
ensureBucketIndexed(BucketManager& bm,
                    std::shared_ptr<BucketT> const& bucket,
                    std::filesystem::path const& indexPath,
                    std::filesystem::path const& bucketPath, uint256 const& hash,
                    ClockT& clock)
{
    if (!bucket || bucket->isEmpty() || bucket->isIndexed())
    {
        return;
    }

    if (std::filesystem::exists(indexPath))
    {
        auto index = loadIndex<BucketT>(bm, indexPath, bucket->getSize());
        if (index)
        {
            bucket->setIndex(std::move(index));
        }
    }

    if (!bucket->isIndexed())
    {
        auto index = createIndex<BucketT>(bm, bucketPath, hash,
                                          clock.getIOContext(), nullptr);
        bucket->setIndex(std::move(index));
    }
}

} // namespace

// ============================================================================
// RandomBucketListGenerator
// ============================================================================

RandomBucketListGenerator::RandomBucketListGenerator(Application& app)
    : mApp(app)
{
    mLiveCurrBuckets.resize(LiveBucketList::kNumLevels);
    mLiveSnapBuckets.resize(LiveBucketList::kNumLevels);
    mHotArchiveCurrBuckets.resize(HotArchiveBucketList::kNumLevels);
    mHotArchiveSnapBuckets.resize(HotArchiveBucketList::kNumLevels);

    buildPlans();

    // Initialize pending events maps with empty vectors for all bucket
    // locations
    auto initPendingEvents = [](auto& pendingEvents) {
        for (uint32_t level = 0; level < LiveBucketList::kNumLevels; ++level)
        {
            pendingEvents[{level, true}] = {};
            pendingEvents[{level, false}] = {};
        }
    };
    initPendingEvents(mPendingEvents);
    initPendingEvents(mHotArchivePendingEvents);
}

void
RandomBucketListGenerator::generate()
{
    generateBucketList<LiveBucket>(mLiveCurrBuckets, mLiveSnapBuckets,
                                   mLivePlans, "Live");
    validateLiveStructure();

    // Collect soroban entries from the Live BucketList so we know what we can
    // populate the hot archive with.
    collectArchivableEntries();

    generateBucketList<HotArchiveBucket>(mHotArchiveCurrBuckets,
                                         mHotArchiveSnapBuckets,
                                         mHotArchivePlans, "Hot archive");
    validateHotArchiveStructure();

    validateCrossReferenceConsistency();
}

// Generates the "plans" for the BucketLists. This includes the protocol
// versions and entry counts for each bucket.
void
RandomBucketListGenerator::buildPlans()
{
    uint32_t const current = Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    uint32_t const numLevels = LiveBucketList::kNumLevels;

    auto fillPlans = [&](std::vector<LevelPlan>& plans,
                         std::vector<std::pair<size_t, size_t>> const& counts,
                         uint32_t minVersion) {
        plans.resize(numLevels);
        for (uint32_t level = 0; level < numLevels; ++level)
        {
            uint32_t version =
                interpolateVersion(level, numLevels, minVersion, current);
            plans[level] = {version, counts[level].first, counts[level].second};
        }

        for (uint32_t level = numLevels - 1; level > 0; --level)
        {
            releaseAssert(plans[level].protocolVersion <=
                          plans[level - 1].protocolVersion);
            releaseAssert(plans[level].protocolVersion >= minVersion);
        }
    };

    fillPlans(mLivePlans, LIVE_ENTRY_COUNTS, LIVE_MIN_PROTOCOL_VERSION);
    fillPlans(mHotArchivePlans, HOT_ARCHIVE_ENTRY_COUNTS,
              HOT_ARCHIVE_MIN_PROTOCOL_VERSION);
}

template <typename BucketT>
std::shared_ptr<BucketT>
RandomBucketListGenerator::createBucket(
    uint32_t protocolVersion,
    std::vector<typename BucketT::EntryT> const& entries, bool keepTombstones)
{
    static_assert(std::is_same_v<BucketT, LiveBucket> ||
                      std::is_same_v<BucketT, HotArchiveBucket>,
                  "BucketT must be LiveBucket or HotArchiveBucket");

    auto& bm = mApp.getBucketManager();

    BucketMetadata meta;
    meta.ledgerVersion = protocolVersion;
    if (protocolVersionStartsFrom(
            protocolVersion,
            LiveBucket::FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION))
    {
        meta.ext.v(1);
        if constexpr (std::is_same_v<BucketT, LiveBucket>)
        {
            meta.ext.bucketListType() = BucketListType::LIVE;
        }
        else
        {
            meta.ext.bucketListType() = BucketListType::HOT_ARCHIVE;
        }
    }

    MergeCounters mc;
    BucketOutputIterator<BucketT> out(bm.getTmpDir(), keepTombstones, meta, mc,
                                      mApp.getClock().getIOContext(),
                                      /*doFsync=*/false);

    for (auto const& e : entries)
    {
        out.put(e);
    }

    return out.getBucket(bm);
}

template std::shared_ptr<LiveBucket>
RandomBucketListGenerator::createBucket<LiveBucket>(
    uint32_t, std::vector<BucketEntry> const&, bool);
template std::shared_ptr<HotArchiveBucket>
RandomBucketListGenerator::createBucket<HotArchiveBucket>(
    uint32_t, std::vector<HotArchiveBucketEntry> const&, bool);

uint32_t
RandomBucketListGenerator::generateRandomTTL() const
{
    if (rand_flip())
    {
        // Expired: liveUntilLedgerSeq < FIXED_LCL
        return rand_uniform<uint32_t>(FIXED_LCL - 2000, FIXED_LCL - 1);
    }
    else
    {
        // Live: liveUntilLedgerSeq >= FIXED_LCL
        return rand_uniform<uint32_t>(FIXED_LCL, FIXED_LCL + 2000);
    }
}

void
RandomBucketListGenerator::scheduleLiveBucketListEvent(
    PendingEvent event, BucketLocation const& minLocation)
{
    scheduleLiveBucketListEventAtWeightedLocation(std::move(event), minLocation,
                                                  mLivePlans, mPendingEvents);
    // If no valid location, event is dropped (all buckets at capacity)
}

bool
RandomBucketListGenerator::scheduleHotArchiveEvent(
    HotArchivePendingEvent event, BucketLocation const& minLocation)
{
    return scheduleLiveBucketListEventAtWeightedLocation(
        std::move(event), minLocation, mHotArchivePlans,
        mHotArchivePendingEvents);
}

// Whenever we write a non-dead entry, this function is called to schedule the
// next update for that key. In the case of a classic entry, this is either:
// 1. Do nothing, last entry will not be shadowed
// 2. Update the entry
// 3. Delete the entry
// In the case of a Soroban entry, this is either:
// 1. Do nothing, last entry will not be shadowed
// 2. Update the entry
// 3. Extend the TTL, but don't update the entry
// 4. Delete the entry
void
RandomBucketListGenerator::scheduleNextUpdateEvent(
    LedgerEntry const& entry, BucketLocation const& location,
    std::optional<uint32_t> currentTTL)
{
    auto key = LedgerEntryKey(entry);
    bool isSoroban = isSorobanEntry(key);

    // Soroban entries must have a TTL
    releaseAssert(!isSoroban || currentTTL.has_value());

    PendingEvent event;
    event.lastEntryValue = entry;
    event.lastTTLValue = currentTTL;

    if (isSoroban)
    {
        switch (rand_uniform<int>(1, 4))
        {
        case 1:
            // Do nothing, last entry will not be shadowed
            break;
        case 2:
            event.type = EventType::UPDATE;
            scheduleLiveBucketListEvent(std::move(event), location);
            break;
        case 3:
            event.type = EventType::TTL_EXTEND;
            scheduleLiveBucketListEvent(std::move(event), location);
            break;
        case 4:
            event.type = EventType::DELETE;
            scheduleLiveBucketListEvent(std::move(event), location);
            break;
        }
    }
    else
    {
        switch (rand_uniform<int>(1, 3))
        {
        case 1:
            // Do nothing, last entry will not be shadowed
            break;
        case 2:
            event.type = EventType::UPDATE;
            scheduleLiveBucketListEvent(std::move(event), location);
            break;
        case 3:
            event.type = EventType::DELETE;
            scheduleLiveBucketListEvent(std::move(event), location);
            break;
        }
    }
}

// ============================================================================
// Bucket Entry Building
// ============================================================================

template <typename BucketT>
BucketLedgerRange
RandomBucketListGenerator::computeLedgerRange(
    BucketLocation const& location) const
{
    using BucketListT =
        std::conditional_t<std::is_same_v<BucketT, LiveBucket>, LiveBucketList,
                           HotArchiveBucketList>;

    uint32_t level = location.level;
    uint32_t oldestInCurr = BucketListT::oldestLedgerInCurr(FIXED_LCL, level);
    uint32_t oldestInSnap = BucketListT::oldestLedgerInSnap(FIXED_LCL, level);

    uint32_t newestInCurr;
    if (level == 0)
    {
        newestInCurr = FIXED_LCL;
    }
    else
    {
        uint32_t oldestInPrevSnap =
            BucketListT::oldestLedgerInSnap(FIXED_LCL, level - 1);
        newestInCurr = oldestInPrevSnap - 1;
    }

    return location.isCurr ? BucketLedgerRange{oldestInCurr, newestInCurr}
                           : BucketLedgerRange{oldestInSnap, oldestInCurr - 1};
}

template BucketLedgerRange
RandomBucketListGenerator::computeLedgerRange<LiveBucket>(
    BucketLocation const&) const;
template BucketLedgerRange
RandomBucketListGenerator::computeLedgerRange<HotArchiveBucket>(
    BucketLocation const&) const;

template <>
std::vector<BucketEntry>
RandomBucketListGenerator::buildBucketEntries<LiveBucket>(
    BucketLocation const& location, LevelPlan const& plan)
{
    size_t targetEntryCount =
        location.isCurr ? plan.currEntryCount : plan.snapEntryCount;

    if (targetEntryCount == 0)
    {
        return {};
    }

    auto range = computeLedgerRange<LiveBucket>(location);
    auto randomLedgerSeq = [&range]() {
        return rand_uniform<uint32_t>(range.lo, range.hi);
    };

    std::vector<LedgerEntry> initEntries;
    std::vector<LedgerEntry> liveEntries;
    std::vector<LedgerKey> deadEntries;

    // Step 1: Execute all pending events for this bucket location. This
    // includes generating the necessary BucketEntry, as well as scheduling any
    // follow up events.
    auto& events = mPendingEvents.at(location);
    for (auto& event : events)
    {
        uint32_t ledgerSeq = randomLedgerSeq();
        auto key = LedgerEntryKey(event.lastEntryValue);

        switch (event.type)
        {
        case EventType::UPDATE:
        {
            // Update data/code entry only (TTL unchanged)
            LedgerTestUtils::randomlyModifyEntry(event.lastEntryValue);
            event.lastEntryValue.lastModifiedLedgerSeq = ledgerSeq;
            liveEntries.push_back(event.lastEntryValue);

            scheduleNextUpdateEvent(event.lastEntryValue, location,
                                    event.lastTTLValue);
            break;
        }

        case EventType::TTL_EXTEND:
        {
            // Extend TTL only (code/data unchanged)
            releaseAssert(isSorobanEntry(key));
            releaseAssert(event.lastTTLValue.has_value());
            *event.lastTTLValue += rand_uniform<uint32_t>(1, 1000);
            auto ttlEntry =
                getTTLEntryForTTLKey(getTTLKey(key), *event.lastTTLValue);
            ttlEntry.lastModifiedLedgerSeq = ledgerSeq;
            liveEntries.push_back(ttlEntry);

            scheduleNextUpdateEvent(event.lastEntryValue, location,
                                    event.lastTTLValue);
            break;
        }

        case EventType::DELETE:
        {
            // Emit dead entries
            deadEntries.push_back(key);
            if (isSorobanEntry(key))
            {
                deadEntries.push_back(getTTLKey(key));
            }

            // Recreate the entry 50% of the time
            if (rand_flip())
            {
                event.type = EventType::RECREATE;
                scheduleLiveBucketListEvent(std::move(event), location);
            }
            break;
        }

        case EventType::RECREATE:
        {
            // Recreate both parent and TTL together.
            if (rand_flip())
            {
                // 50% of the time, recreate a different version of the
                // entry. Otherwise, recreate the same version.
                LedgerTestUtils::randomlyModifyEntry(event.lastEntryValue);
            }
            event.lastEntryValue.lastModifiedLedgerSeq = ledgerSeq;
            initEntries.push_back(event.lastEntryValue);

            // Recreate TTL if Soroban
            std::optional<uint32_t> ttl;
            if (isSorobanEntry(key))
            {
                ttl = generateRandomTTL();
                auto ttlEntry = getTTLEntryForTTLKey(getTTLKey(key), *ttl);
                ttlEntry.lastModifiedLedgerSeq = ledgerSeq;
                initEntries.push_back(ttlEntry);
            }

            scheduleNextUpdateEvent(event.lastEntryValue, location, ttl);
            break;
        }
        }
    }
    events.clear();

    // Step 2: Calculate how many new entries we can create
    size_t currentCount =
        initEntries.size() + liveEntries.size() + deadEntries.size();
    size_t newEntryBudget =
        (targetEntryCount > currentCount) ? targetEntryCount - currentCount : 0;

    // Ensure every non-empty bucket has at least some new entries
    if (newEntryBudget < MINIMUM_NEW_ENTRIES_PER_BUCKET)
    {
        newEntryBudget = MINIMUM_NEW_ENTRIES_PER_BUCKET;
    }

    // Step 3: Create new entries
    size_t classicCount = 0;
    size_t sorobanCount = 0;
    if (protocolVersionStartsFrom(plan.protocolVersion,
                                  SOROBAN_PROTOCOL_VERSION))
    {
        // Split the budget between Soroban and classic entries.
        // Each Soroban entry creates 2 bucket entries (code/data + TTL)
        sorobanCount = newEntryBudget / 4;
        classicCount = newEntryBudget - (sorobanCount * 2);
    }
    else
    {
        classicCount = newEntryBudget;
    }

    // Create classic entries
    auto classicEntries =
        LedgerTestUtils::generateValidUniqueLedgerEntriesWithExclusions(
            {CONFIG_SETTING, CONTRACT_DATA, CONTRACT_CODE, TTL}, classicCount,
            mGlobalSeenKeys);

    for (auto& entry : classicEntries)
    {
        uint32_t ledgerSeq = randomLedgerSeq();
        entry.lastModifiedLedgerSeq = ledgerSeq;
        initEntries.push_back(entry);

        scheduleNextUpdateEvent(entry, location);
    }

    // Create Soroban entries
    if (sorobanCount > 0)
    {
        auto sorobanEntries =
            LedgerTestUtils::generateValidUniqueLedgerEntriesWithTypes(
                {CONTRACT_DATA, CONTRACT_CODE}, sorobanCount, mGlobalSeenKeys);

        for (auto& entry : sorobanEntries)
        {
            uint32_t ledgerSeq = randomLedgerSeq();
            entry.lastModifiedLedgerSeq = ledgerSeq;
            initEntries.push_back(entry);

            uint32_t ttl = generateRandomTTL();

            // Create TTL entry
            auto ttlEntry = getTTLEntryForTTLKey(getTTLKey(entry), ttl);
            ttlEntry.lastModifiedLedgerSeq = ledgerSeq;
            initEntries.push_back(ttlEntry);

            scheduleNextUpdateEvent(entry, location, ttl);
        }
    }

    return LiveBucket::convertToBucketEntry(
        /*useInit=*/true, initEntries, liveEntries, deadEntries);
}

template <>
std::vector<HotArchiveBucketEntry>
RandomBucketListGenerator::buildBucketEntries<HotArchiveBucket>(
    BucketLocation const& location, LevelPlan const& plan)
{
    size_t targetEntryCount =
        location.isCurr ? plan.currEntryCount : plan.snapEntryCount;

    if (targetEntryCount == 0)
    {
        return {};
    }

    std::vector<LedgerEntry> archivedEntries;
    std::vector<LedgerKey> restoredKeys;

    // Can schedule to buckets above this location (including same-level curr
    // when processing snap)
    bool canScheduleMore = (location.level > 0) || !location.isCurr;

    // Helper to schedule a RESTORE event. Returns true if scheduled.
    auto scheduleRestore = [&](LedgerKey const& key, LedgerEntry const& entry,
                               HotArchiveLiveState liveState) -> bool {
        HotArchivePendingEvent restoreEvent;
        restoreEvent.type = HotArchiveEventType::RESTORE;
        restoreEvent.key = key;
        restoreEvent.entry = entry;
        restoreEvent.liveState = liveState;
        return scheduleHotArchiveEvent(std::move(restoreEvent), location);
    };

    // Helper to maybe schedule a RESTORE (otherwise entry stays ARCHIVE_ONLY).
    // Only called for NOT_IN_LIVE and DEAD_IN_LIVE entries.
    auto maybeScheduleRestore = [&](LedgerKey const& key,
                                    LedgerEntry const& entry,
                                    HotArchiveLiveState liveState) {
        if (canScheduleMore && rand_flip())
        {
            scheduleRestore(key, entry, liveState);
        }
    };

    // Step 1: Process pending events
    auto& events = mHotArchivePendingEvents.at(location);
    for (auto& event : events)
    {
        switch (event.type)
        {
        case HotArchiveEventType::INITIAL_ARCHIVE:
        {
            // LIVE_IN_LIVE entries have RESTORE pre-scheduled; just add to
            // bucket. Other entries may become ARCHIVE_ONLY or get RESTORE
            // scheduled.
            archivedEntries.push_back(event.entry);
            if (event.liveState != HotArchiveLiveState::LIVE_IN_LIVE)
            {
                maybeScheduleRestore(event.key, event.entry, event.liveState);
            }
            break;
        }

        case HotArchiveEventType::REARCHIVE:
        {
            archivedEntries.push_back(event.entry);
            break;
        }

        case HotArchiveEventType::RESTORE:
        {
            restoredKeys.push_back(event.key);
            // LIVE_IN_LIVE entries must stay restored. Others may get
            // REARCHIVE scheduled.
            if (event.liveState != HotArchiveLiveState::LIVE_IN_LIVE &&
                canScheduleMore && rand_flip())
            {
                event.type = HotArchiveEventType::REARCHIVE;
                scheduleHotArchiveEvent(std::move(event), location);
            }
            break;
        }
        }
    }
    events.clear();

    // Step 2: Calculate budget for new entries
    size_t currentCount = archivedEntries.size() + restoredKeys.size();
    size_t newEntryBudget =
        (targetEntryCount > currentCount) ? targetEntryCount - currentCount : 0;

    // Step 3: Generate new archive entries to fill budget
    for (size_t i = 0; i < newEntryBudget; ++i)
    {
        LedgerEntry entry;
        LedgerKey key;
        HotArchiveLiveState liveState;

        // Randomly choose: pull from pool (dead or live) OR generate new entry
        bool hasDeadEntries = !mDeadArchivableEntries.empty();
        bool hasLiveEntries = !mLiveArchivableEntries.empty();
        releaseAssert(hasDeadEntries || hasLiveEntries);

        // Randomly decide: use dead pool, live pool, or generate new
        int choice = rand_uniform<int>(0, 2);
        bool useDeadPool = (choice == 0) && hasDeadEntries;
        bool useLivePool = (choice == 1) && hasLiveEntries && canScheduleMore;

        if (useDeadPool)
        {
            // Pull from dead pool - these are DEAD in live BL
            entry = mDeadArchivableEntries.back();
            mDeadArchivableEntries.pop_back();
            key = LedgerEntryKey(entry);
            liveState = HotArchiveLiveState::DEAD_IN_LIVE;
        }
        else if (useLivePool)
        {
            // Pull from live pool - these are LIVE in live BL, must be restored
            entry = mLiveArchivableEntries.back();
            mLiveArchivableEntries.pop_back();
            key = LedgerEntryKey(entry);
            liveState = HotArchiveLiveState::LIVE_IN_LIVE;

            // Schedule RESTORE so hot archive shows entry was restored
            if (scheduleRestore(key, entry, liveState))
            {
                archivedEntries.push_back(entry);
            }
            continue;
        }
        else
        {
            // Generate new hot-archive-only entry
            auto entries =
                LedgerTestUtils::generateValidUniqueLedgerEntriesWithTypes(
                    {CONTRACT_DATA, CONTRACT_CODE}, 1, mGlobalSeenKeys);

            if (entries.empty())
            {
                break; // Can't generate more
            }

            entry = entries[0];
            if (entry.data.type() == CONTRACT_DATA)
            {
                entry.data.contractData().durability = PERSISTENT;
            }
            key = LedgerEntryKey(entry);
            liveState = HotArchiveLiveState::NOT_IN_LIVE;
        }

        archivedEntries.push_back(entry);
        maybeScheduleRestore(key, entry, liveState);
    }

    if (archivedEntries.empty() && restoredKeys.empty())
    {
        return {};
    }

    return HotArchiveBucket::convertToBucketEntry(archivedEntries,
                                                  restoredKeys);
}

template <typename BucketT>
void
RandomBucketListGenerator::generateBucketList(
    std::vector<std::shared_ptr<BucketT>>& currBuckets,
    std::vector<std::shared_ptr<BucketT>>& snapBuckets,
    std::vector<LevelPlan> const& plans, std::string const& bucketListName)
{
    uint32_t const numLevels = BucketListBase<BucketT>::kNumLevels;

    // Process from bottom (oldest) to top (newest)
    for (int32_t level = numLevels - 1; level >= 0; --level)
    {
        auto const& plan = plans[level];
        auto makeBucket = [&](BucketLocation const& location,
                              std::string const& name) {
            auto entries = buildBucketEntries<BucketT>(location, plan);

            if (entries.empty())
            {
                CLOG_INFO(Bucket, "{} level {}: Creating empty {} bucket",
                          bucketListName, level, name);
            }
            else
            {
                CLOG_INFO(Bucket,
                          "{} level {}: Creating {} bucket (protocol {}, {} "
                          "entries)...",
                          bucketListName, level, name, plan.protocolVersion,
                          entries.size());
            }

            return createBucket<BucketT>(plan.protocolVersion, entries,
                                         /*keepTombstones=*/true);
        };

        BucketLocation snapLoc{static_cast<uint32_t>(level), false};
        snapBuckets[level] = makeBucket(snapLoc, "snap");

        BucketLocation currLoc{static_cast<uint32_t>(level), true};
        currBuckets[level] = makeBucket(currLoc, "curr");
    }
}

template void RandomBucketListGenerator::generateBucketList<LiveBucket>(
    std::vector<std::shared_ptr<LiveBucket>>&,
    std::vector<std::shared_ptr<LiveBucket>>&, std::vector<LevelPlan> const&,
    std::string const&);
template void RandomBucketListGenerator::generateBucketList<HotArchiveBucket>(
    std::vector<std::shared_ptr<HotArchiveBucket>>&,
    std::vector<std::shared_ptr<HotArchiveBucket>>&,
    std::vector<LevelPlan> const&, std::string const&);

// ============================================================================
// Validation
// ============================================================================

LiveBucketStats
RandomBucketListGenerator::countLiveEntries() const
{
    LiveBucketStats stats;

    // Track lifecycle per key as we iterate newest -> oldest
    UnorderedMap<LedgerKey, LiveLifecycle> keyLifecycles;

    auto processBucket = [&](std::shared_ptr<LiveBucket> const& bucket) {
        if (!bucket || bucket->isEmpty())
        {
            return;
        }

        for (BucketInputIterator<LiveBucket> iter(bucket); iter; ++iter)
        {
            BucketEntry const& be = *iter;
            auto bet = be.type();

            // Count entry types
            if (bet == INITENTRY)
            {
                stats.totalInitCount++;
            }
            else if (bet == LIVEENTRY)
            {
                stats.totalLiveCount++;
            }
            else
            {
                stats.totalDeadCount++;
            }

            auto entryType =
                bucketEntryToLedgerEntryAndDurabilityType<LiveBucket>(be);

            // Skip TTL entries for lifecycle tracking, since these are implicit
            // to the associated Soroban entry.
            if (entryType == LedgerEntryTypeAndDurability::TTL)
            {
                continue;
            }

            LedgerKey key;
            if (bet == INITENTRY || bet == LIVEENTRY)
            {
                key = LedgerEntryKey(be.liveEntry());
            }
            else
            {
                key = be.deadEntry();
            }

            auto it = keyLifecycles.find(key);
            if (it == keyLifecycles.end())
            {
                // First entry seen for this key, set initial state
                LiveLifecycle lifecycle;
                if (bet == DEADENTRY)
                {
                    lifecycle = LiveLifecycle::DELETE;
                }
                else if (bet == LIVEENTRY)
                {
                    lifecycle = LiveLifecycle::UPDATE;
                }
                else
                {
                    lifecycle = LiveLifecycle::CREATE_ONLY;
                }
                keyLifecycles.emplace(key, lifecycle);
            }
            else
            {
                // We've already seen this key before, but may have to update
                // the lifecycle based on previous values.
                auto& lifecycle = it->second;

                switch (lifecycle)
                {
                case LiveLifecycle::DELETE:
                case LiveLifecycle::RECREATE:
                    // No update required, prior versions do not impact these
                    // states.
                    break;
                case LiveLifecycle::CREATE_ONLY:
                case LiveLifecycle::UPDATE:
                    // If we see an outdated DEADENTRY for a live key, it must
                    // have been recreated.
                    if (bet == DEADENTRY)
                    {
                        lifecycle = LiveLifecycle::RECREATE;
                    }
                    break;
                }
            }
        }
    };

    // Iterate from newest to oldest
    for (uint32_t level = 0; level < LiveBucketList::kNumLevels; ++level)
    {
        processBucket(mLiveCurrBuckets[level]);
        processBucket(mLiveSnapBuckets[level]);
    }

    // Aggregate lifecycle counts
    for (auto const& [key, lifecycle] : keyLifecycles)
    {
        auto entryType = ledgerKeyToTypeAndDurability(key);
        stats.lifecycleCounts[entryType][lifecycle]++;
    }

    return stats;
}

HotArchiveBucketStats
RandomBucketListGenerator::countHotArchiveEntries() const
{
    HotArchiveBucketStats stats;

    // State tracking for lifecycle detection while iterating newest→oldest
    struct HotArchiveKeyState
    {
        bool newestIsArchived; // First entry seen (newest) was ARCHIVED
        bool sawLive;          // Saw at least one LIVE entry
    };

    // Track per-key state as we iterate newest→oldest
    UnorderedMap<LedgerKey, HotArchiveKeyState> keyStates;

    // Helper to process a single bucket and accumulate counts
    auto processBucket = [&](std::shared_ptr<HotArchiveBucket> const& bucket) {
        if (!bucket || bucket->isEmpty())
        {
            return;
        }

        for (BucketInputIterator<HotArchiveBucket> iter(bucket); iter; ++iter)
        {
            auto const& e = *iter;
            LedgerKey key;
            bool isArchived = false;

            if (e.type() == HOT_ARCHIVE_ARCHIVED)
            {
                stats.totalArchivedCount++;
                key = LedgerEntryKey(e.archivedEntry());
                isArchived = true;
            }
            else if (e.type() == HOT_ARCHIVE_LIVE)
            {
                stats.totalLiveCount++;
                key = e.key();
                isArchived = false;
            }
            else
            {
                continue; // METAENTRY or DELETED
            }

            // Update lifecycle state for this key
            auto it = keyStates.find(key);
            if (it == keyStates.end())
            {
                // First entry seen for this key (newest)
                keyStates.emplace(key,
                                  HotArchiveKeyState{isArchived, !isArchived});
            }
            else
            {
                // Subsequent entry (older)
                if (!isArchived)
                {
                    it->second.sawLive = true;
                }
            }
        }
    };

    // Iterate from newest to oldest: level 0 curr -> snap -> level 1 curr ->
    // snap -> ...
    for (uint32_t level = 0; level < HotArchiveBucketList::kNumLevels; ++level)
    {
        processBucket(mHotArchiveCurrBuckets[level]);
        processBucket(mHotArchiveSnapBuckets[level]);
    }

    // Compute lifecycle counts from key states
    for (auto const& [key, state] : keyStates)
    {
        if (!state.newestIsArchived)
        {
            // Newest is LIVE -> ARCHIVE_RESTORE
            stats.archiveRestoreCount++;
        }
        else if (state.sawLive)
        {
            // Newest is ARCHIVED and saw LIVE -> ARCHIVE_RESTORE_ARCHIVE
            stats.archiveRestoreArchiveCount++;
        }
        else
        {
            // Newest is ARCHIVED and no LIVE seen -> ARCHIVE_ONLY
            stats.archiveOnlyCount++;
        }
    }

    return stats;
}

// Collects persistent entries from the live BucketList for hot archive
// generation.
void
RandomBucketListGenerator::collectArchivableEntries()
{
    // We need to track the latest version of a key right before it was deleted.
    // To do this, if we see a DEADENTRY that it the newest version of the key,
    // we mark it in seenDeadKeys as false. When we later see the LIVEENTRY, we
    // add the entry data to mDeadArchivableEntries and mark the key as true.
    UnorderedMap<LedgerKey, bool> seenDeadKeys;
    UnorderedSet<LedgerKey> seenLiveKeys;

    auto processBucket = [&](std::shared_ptr<LiveBucket> const& bucket) {
        if (!bucket || bucket->isEmpty())
        {
            return;
        }

        for (BucketInputIterator<LiveBucket> iter(bucket); iter; ++iter)
        {
            BucketEntry const& be = *iter;
            auto bet = be.type();
            bool isLive = (bet == INITENTRY || bet == LIVEENTRY);
            LedgerKey key =
                isLive ? LedgerEntryKey(be.liveEntry()) : be.deadEntry();

            if (!isPersistentEntry(key))
            {
                continue;
            }

            if (isLive)
            {
                // If we've seen a DEADENTRY for this key, but have not yet seen
                // its LIVEENTRY
                auto deadIt = seenDeadKeys.find(key);
                if (deadIt != seenDeadKeys.end() && !deadIt->second)
                {
                    // Add the entry data to the dead archivable entries and
                    // mark that we have seen the LIVEENTRY for this key.
                    mDeadArchivableEntries.push_back(be.liveEntry());
                    deadIt->second = true;
                }
                // If we haven't seen this key before, it is live.
                else if (seenLiveKeys.find(key) == seenLiveKeys.end() &&
                         deadIt == seenDeadKeys.end())
                {
                    mLiveArchivableEntries.push_back(be.liveEntry());
                    seenLiveKeys.insert(key);
                }
            }
            else
            {
                // Dead entry, track if not already seen
                if (seenLiveKeys.find(key) == seenLiveKeys.end() &&
                    seenDeadKeys.find(key) == seenDeadKeys.end())
                {
                    seenDeadKeys.emplace(key, false);
                }
            }
        }
    };

    // Iterate from newest to oldest
    for (uint32_t level = 0; level < LiveBucketList::kNumLevels; ++level)
    {
        processBucket(mLiveCurrBuckets[level]);
        processBucket(mLiveSnapBuckets[level]);
    }

    CLOG_INFO(
        Bucket,
        "Collected {} dead and {} live persistent entries for hot archive",
        mDeadArchivableEntries.size(), mLiveArchivableEntries.size());
}

void
RandomBucketListGenerator::reportLiveStats(LiveBucketStats const& stats)
{
    CLOG_INFO(Bucket, "BucketEntry totals: INIT={} LIVE={} DEAD={}",
              stats.totalInitCount, stats.totalLiveCount, stats.totalDeadCount);

    CLOG_INFO(Bucket, "Live lifecycle counts by entry type:");
    for (auto const& [entryType, counts] : stats.lifecycleCounts)
    {
        size_t createOnly = counts.count(LiveLifecycle::CREATE_ONLY)
                                ? counts.at(LiveLifecycle::CREATE_ONLY)
                                : 0;
        size_t update = counts.count(LiveLifecycle::UPDATE)
                            ? counts.at(LiveLifecycle::UPDATE)
                            : 0;
        size_t deleted = counts.count(LiveLifecycle::DELETE)
                             ? counts.at(LiveLifecycle::DELETE)
                             : 0;
        size_t recreate = counts.count(LiveLifecycle::RECREATE)
                              ? counts.at(LiveLifecycle::RECREATE)
                              : 0;

        CLOG_INFO(Bucket,
                  "  {}: CREATE_ONLY={} UPDATE={} DELETE={} RECREATE={}",
                  toString(entryType), createOnly, update, deleted, recreate);
    }

    size_t totalKeys = 0, totalCreateOnly = 0, totalUpdate = 0, totalDelete = 0,
           totalRecreate = 0;
    for (auto const& [entryType, counts] : stats.lifecycleCounts)
    {
        if (counts.count(LiveLifecycle::CREATE_ONLY))
        {
            totalCreateOnly += counts.at(LiveLifecycle::CREATE_ONLY);
        }
        if (counts.count(LiveLifecycle::UPDATE))
        {
            totalUpdate += counts.at(LiveLifecycle::UPDATE);
        }
        if (counts.count(LiveLifecycle::DELETE))
        {
            totalDelete += counts.at(LiveLifecycle::DELETE);
        }
        if (counts.count(LiveLifecycle::RECREATE))
        {
            totalRecreate += counts.at(LiveLifecycle::RECREATE);
        }
    }

    totalKeys = totalCreateOnly + totalUpdate + totalDelete + totalRecreate;
    CLOG_INFO(Bucket,
              "Live lifecycle totals: {} keys (CREATE_ONLY={} UPDATE={} "
              "DELETE={} RECREATE={})",
              totalKeys, totalCreateOnly, totalUpdate, totalDelete,
              totalRecreate);
}

void
RandomBucketListGenerator::reportHotArchiveStats(
    HotArchiveBucketStats const& stats)
{
    CLOG_INFO(Bucket, "HotArchiveBucketEntry totals: ARCHIVED={} LIVE={}",
              stats.totalArchivedCount, stats.totalLiveCount);

    CLOG_INFO(Bucket,
              "Hot archive lifecycle counts: ARCHIVE_ONLY={}, "
              "ARCHIVE_RESTORE={}, ARCHIVE_RESTORE_ARCHIVE={}",
              stats.archiveOnlyCount, stats.archiveRestoreCount,
              stats.archiveRestoreArchiveCount);
}

void
RandomBucketListGenerator::validateLiveStructure()
{
    // All pending events should have been consumed during generation
    for (auto const& [loc, events] : mPendingEvents)
    {
        releaseAssert(events.empty());
    }

    validateEntryCounts(mLiveCurrBuckets, mLiveSnapBuckets, mLivePlans);
    validateProtocols(mLiveCurrBuckets, mLiveSnapBuckets,
                      LIVE_MIN_PROTOCOL_VERSION);

    // Buckets with protocol version < 20 must have no Soroban entries
    for (uint32_t level = 0; level < LiveBucketList::kNumLevels; ++level)
    {
        auto const& curr = mLiveCurrBuckets[level];
        auto const& snap = mLiveSnapBuckets[level];

        if (!curr->isEmpty() && curr->getBucketVersion() < 20)
        {
            if (bucketContainsSorobanEntries(curr))
            {
                throw std::runtime_error(fmt::format(
                    "Level {} curr (protocol {}) contains Soroban entries",
                    level, curr->getBucketVersion()));
            }
        }
        if (!snap->isEmpty() && snap->getBucketVersion() < 20)
        {
            if (bucketContainsSorobanEntries(snap))
            {
                throw std::runtime_error(fmt::format(
                    "Level {} snap (protocol {}) contains Soroban entries",
                    level, snap->getBucketVersion()));
            }
        }
    }

    auto liveStats = countLiveEntries();
    reportLiveStats(liveStats);
    validateLifecycleCounts(liveStats);
}

void
RandomBucketListGenerator::validateHotArchiveStructure()
{
    // All pending events should have been consumed during generation
    for (auto const& [loc, events] : mHotArchivePendingEvents)
    {
        releaseAssert(events.empty());
    }

    validateEntryCounts(mHotArchiveCurrBuckets, mHotArchiveSnapBuckets,
                        mHotArchivePlans);
    validateProtocols(mHotArchiveCurrBuckets, mHotArchiveSnapBuckets,
                      HOT_ARCHIVE_MIN_PROTOCOL_VERSION);

    auto hotArchiveStats = countHotArchiveEntries();
    reportHotArchiveStats(hotArchiveStats);
}

void
RandomBucketListGenerator::validateCrossReferenceConsistency() const
{
    // Scan Live BucketList to build sets of live/deleted keys
    UnorderedSet<LedgerKey> liveNonDeletedKeys;
    UnorderedSet<LedgerKey> liveDeletedKeys;
    UnorderedSet<LedgerKey> allLiveKeys;

    // Scan from newest to oldest to find final state of each key
    for (uint32_t level = 0; level < mLiveCurrBuckets.size(); ++level)
    {
        auto scanLiveBucket = [&](std::shared_ptr<LiveBucket> const& bucket) {
            if (!bucket)
            {
                return;
            }
            for (BucketInputIterator<LiveBucket> iter(bucket); iter; ++iter)
            {
                BucketEntry const& be = *iter;
                LedgerKey key;
                bool isDeleted = false;

                if (be.type() == INITENTRY || be.type() == LIVEENTRY)
                {
                    key = LedgerEntryKey(be.liveEntry());
                }
                else if (be.type() == DEADENTRY)
                {
                    key = be.deadEntry();
                    isDeleted = true;
                }
                else
                {
                    continue; // METAENTRY
                }

                // Skip if already seen (newer takes precedence)
                if (allLiveKeys.find(key) != allLiveKeys.end())
                {
                    continue;
                }

                allLiveKeys.insert(key);
                if (isDeleted)
                {
                    liveDeletedKeys.insert(key);
                }
                else
                {
                    liveNonDeletedKeys.insert(key);
                }
            }
        };

        scanLiveBucket(mLiveCurrBuckets[level]);
        scanLiveBucket(mLiveSnapBuckets[level]);
    }

    // Scan Hot Archive BucketList to determine lifecycle for each key
    struct HotArchiveKeyState
    {
        bool newestIsArchived;
        bool sawLive;
    };
    UnorderedMap<LedgerKey, HotArchiveKeyState> hotArchiveKeyStates;

    for (uint32_t level = 0; level < mHotArchiveCurrBuckets.size(); ++level)
    {
        auto scanHotArchiveBucket =
            [&](std::shared_ptr<HotArchiveBucket> const& bucket) {
                if (!bucket || bucket->isEmpty())
                {
                    return;
                }
                for (BucketInputIterator<HotArchiveBucket> iter(bucket); iter;
                     ++iter)
                {
                    auto const& e = *iter;
                    LedgerKey key;
                    bool isArchived = false;

                    if (e.type() == HOT_ARCHIVE_ARCHIVED)
                    {
                        key = LedgerEntryKey(e.archivedEntry());
                        isArchived = true;
                    }
                    else if (e.type() == HOT_ARCHIVE_LIVE)
                    {
                        key = e.key();
                        isArchived = false;
                    }
                    else
                    {
                        continue; // METAENTRY or DELETED
                    }

                    auto it = hotArchiveKeyStates.find(key);
                    if (it == hotArchiveKeyStates.end())
                    {
                        hotArchiveKeyStates.emplace(
                            key, HotArchiveKeyState{isArchived, !isArchived});
                    }
                    else
                    {
                        if (!isArchived)
                        {
                            it->second.sawLive = true;
                        }
                    }
                }
            };

        scanHotArchiveBucket(mHotArchiveCurrBuckets[level]);
        scanHotArchiveBucket(mHotArchiveSnapBuckets[level]);
    }

    // Validate cross-references and count lifecycles
    size_t archiveOnlyCount = 0;
    size_t archiveRestoreCount = 0;
    size_t archiveRestoreArchiveCount = 0;
    size_t hotArchiveOnlyCount = 0;
    size_t restoredAndLiveCount = 0;

    for (auto const& [key, state] : hotArchiveKeyStates)
    {
        bool inLive = allLiveKeys.find(key) != allLiveKeys.end();
        bool isLiveNonDeleted =
            liveNonDeletedKeys.find(key) != liveNonDeletedKeys.end();

        // Determine lifecycle
        HotArchiveLifecycle lifecycle;
        if (!state.newestIsArchived)
        {
            lifecycle = HotArchiveLifecycle::ARCHIVE_RESTORE;
        }
        else if (state.sawLive)
        {
            lifecycle = HotArchiveLifecycle::ARCHIVE_RESTORE_ARCHIVE;
        }
        else
        {
            lifecycle = HotArchiveLifecycle::ARCHIVE_ONLY;
        }

        switch (lifecycle)
        {
        case HotArchiveLifecycle::ARCHIVE_ONLY:
            archiveOnlyCount++;
            if (isLiveNonDeleted)
            {
                throw std::runtime_error(
                    "HA-R11 violated: ARCHIVE_ONLY entry found as non-deleted "
                    "LIVE in live BL");
            }
            break;

        case HotArchiveLifecycle::ARCHIVE_RESTORE:
            archiveRestoreCount++;
            // Count entries that are restored AND live in live BL
            if (isLiveNonDeleted)
            {
                restoredAndLiveCount++;
            }
            break;

        case HotArchiveLifecycle::ARCHIVE_RESTORE_ARCHIVE:
            archiveRestoreArchiveCount++;
            if (isLiveNonDeleted)
            {
                throw std::runtime_error(
                    "HA-R11 violated: ARCHIVE_RESTORE_ARCHIVE entry found as "
                    "non-deleted LIVE in live BL");
            }
            break;
        }

        if (!inLive)
        {
            hotArchiveOnlyCount++;
        }
    }

    if (archiveOnlyCount < MIN_HOT_ARCHIVE_PER_LIFECYCLE)
    {
        throw std::runtime_error(fmt::format("ARCHIVE_ONLY count {} < {}",
                                             archiveOnlyCount,
                                             MIN_HOT_ARCHIVE_PER_LIFECYCLE));
    }
    if (archiveRestoreCount < MIN_HOT_ARCHIVE_PER_LIFECYCLE)
    {
        throw std::runtime_error(fmt::format("ARCHIVE_RESTORE count {} < {}",
                                             archiveRestoreCount,
                                             MIN_HOT_ARCHIVE_PER_LIFECYCLE));
    }
    if (archiveRestoreArchiveCount < MIN_HOT_ARCHIVE_PER_LIFECYCLE)
    {
        throw std::runtime_error(fmt::format(
            "ARCHIVE_RESTORE_ARCHIVE count {} < {}", archiveRestoreArchiveCount,
            MIN_HOT_ARCHIVE_PER_LIFECYCLE));
    }
    if (hotArchiveOnlyCount < MIN_HOT_ARCHIVE_ONLY)
    {
        throw std::runtime_error(fmt::format("Hot-archive-only count {} < {}",
                                             hotArchiveOnlyCount,
                                             MIN_HOT_ARCHIVE_ONLY));
    }
    if (restoredAndLiveCount < MIN_RESTORED_AND_LIVE)
    {
        throw std::runtime_error(fmt::format("Restored-and-live count {} < {}",
                                             restoredAndLiveCount,
                                             MIN_RESTORED_AND_LIVE));
    }

    CLOG_INFO(Bucket,
              "Cross-reference validation passed: ARCHIVE_ONLY={}, "
              "ARCHIVE_RESTORE={}, ARCHIVE_RESTORE_ARCHIVE={}, "
              "hot-archive-only={}, restored-and-live={}",
              archiveOnlyCount, archiveRestoreCount, archiveRestoreArchiveCount,
              hotArchiveOnlyCount, restoredAndLiveCount);
}

// ============================================================================
// Fixture I/O
// ============================================================================

void
RandomBucketListGenerator::saveFixture(std::filesystem::path const& testDataDir)
{
    std::filesystem::create_directories(testDataDir);
    std::filesystem::create_directories(testDataDir / "buckets");

    HistoryArchiveState has;
    has.version =
        HistoryArchiveState::HISTORY_ARCHIVE_STATE_VERSION_WITH_HOT_ARCHIVE;
    has.currentLedger = FIXED_LCL;
    has.networkPassphrase = mApp.getConfig().NETWORK_PASSPHRASE;

    // Populate live bucket list
    for (uint32_t level = 0; level < LiveBucketList::kNumLevels; ++level)
    {
        has.currentBuckets[level].curr =
            binToHex(mLiveCurrBuckets[level]->getHash());
        has.currentBuckets[level].snap =
            binToHex(mLiveSnapBuckets[level]->getHash());
    }

    // Populate hot archive bucket list
    has.hotArchiveBuckets.resize(HotArchiveBucketList::kNumLevels);
    for (uint32_t level = 0; level < HotArchiveBucketList::kNumLevels; ++level)
    {
        has.hotArchiveBuckets[level].curr =
            binToHex(mHotArchiveCurrBuckets[level]->getHash());
        has.hotArchiveBuckets[level].snap =
            binToHex(mHotArchiveSnapBuckets[level]->getHash());
    }

    auto hasPath = testDataDir / "eviction-test-has.json";
    has.save(hasPath.string());
    CLOG_INFO(Bucket, "Saved HAS (version 2) to {}", hasPath.string());

    auto copyBucketFileIfNeeded = [&](auto const& bucket, char const* label) {
        if (bucket->isEmpty())
        {
            return;
        }
        auto srcPath = bucket->getFilename();
        auto dstPath =
            testDataDir / "buckets" / (binToHex(bucket->getHash()) + ".xdr");
        if (!std::filesystem::exists(dstPath))
        {
            std::filesystem::copy_file(srcPath, dstPath);
            CLOG_DEBUG(Bucket, "Copied {} bucket {} to {}", label,
                       srcPath.string(), dstPath.string());
        }
    };

    // Copy live bucket files
    for (uint32_t level = 0; level < LiveBucketList::kNumLevels; ++level)
    {
        copyBucketFileIfNeeded(mLiveCurrBuckets[level], "live");
        copyBucketFileIfNeeded(mLiveSnapBuckets[level], "live");
    }

    // Copy hot archive bucket files
    for (uint32_t level = 0; level < HotArchiveBucketList::kNumLevels; ++level)
    {
        copyBucketFileIfNeeded(mHotArchiveCurrBuckets[level], "hot archive");
        copyBucketFileIfNeeded(mHotArchiveSnapBuckets[level], "hot archive");
    }

    // Call assumeState to load buckets and build indexes
    auto& bm = mApp.getBucketManager();
    bm.assumeState(mApp, has, Config::CURRENT_LEDGER_PROTOCOL_VERSION,
                   /*restartMerges=*/false);
    CLOG_INFO(Bucket,
              "Called assumeState to build indexes for both bucket lists");

    // Copy index files
    auto bucketDir = std::filesystem::path(bm.getBucketDir());
    size_t indexesCopied = 0;
    for (auto const& hashStr : has.allBuckets())
    {
        if (hashStr == binToHex(uint256{}))
        {
            continue;
        }
        auto srcIndexPath = bucketDir / ("bucket-" + hashStr + ".index");
        auto dstIndexPath = testDataDir / "buckets" / (hashStr + ".index");
        if (std::filesystem::exists(srcIndexPath))
        {
            if (!std::filesystem::exists(dstIndexPath))
            {
                std::filesystem::copy_file(srcIndexPath, dstIndexPath);
                ++indexesCopied;
                CLOG_DEBUG(Bucket, "Copied index {} to {}",
                           srcIndexPath.string(), dstIndexPath.string());
            }
        }
        else
        {
            CLOG_DEBUG(Bucket, "Index file does not exist: {}",
                       srcIndexPath.string());
        }
    }
    CLOG_INFO(Bucket, "Copied {} index files to testdata", indexesCopied);
}

void
RandomBucketListGenerator::loadFixture(std::filesystem::path const& testDataDir)
{
    auto& bm = mApp.getBucketManager();
    auto hasPath = testDataDir / "eviction-test-has.json";

    if (!std::filesystem::exists(hasPath))
    {
        throw std::runtime_error("HAS file not found: " + hasPath.string());
    }

    CLOG_INFO(Bucket, "Loading BucketList from {}", hasPath.string());

    HistoryArchiveState has;
    has.load(hasPath.string());

    bool hasHotArchive = has.hasHotArchiveBuckets();
    CLOG_INFO(Bucket, "HAS version: {}, has hot archive: {}", has.version,
              hasHotArchive);

    auto srcBucketDir = testDataDir / "buckets";
    auto dstBucketDir = std::filesystem::path(bm.getBucketDir());
    auto& clock = mApp.getClock();
    for (auto const& hashStr : has.allBuckets())
    {
        if (hashStr == binToHex(uint256{}))
        {
            continue;
        }

        auto srcPath = srcBucketDir / (hashStr + ".xdr");
        auto dstPath = dstBucketDir / ("bucket-" + hashStr + ".xdr");
        if (std::filesystem::exists(srcPath) &&
            !std::filesystem::exists(dstPath))
        {
            std::filesystem::copy_file(srcPath, dstPath);
        }

        auto srcIndexPath = srcBucketDir / (hashStr + ".index");
        auto dstIndexPath = dstBucketDir / ("bucket-" + hashStr + ".index");
        if (std::filesystem::exists(srcIndexPath) &&
            !std::filesystem::exists(dstIndexPath))
        {
            std::filesystem::copy_file(srcIndexPath, dstIndexPath);
        }

        auto hash = hexToBin256(hashStr);

        auto liveBucket = bm.getBucketByHash<LiveBucket>(hash);
        ensureBucketIndexed<LiveBucket>(bm, liveBucket, dstIndexPath, dstPath,
                                        hash, clock);

        if (hasHotArchive)
        {
            auto hotBucket = bm.getBucketByHash<HotArchiveBucket>(hash);
            ensureBucketIndexed<HotArchiveBucket>(bm, hotBucket, dstIndexPath,
                                                  dstPath, hash, clock);
        }
    }

    bm.assumeState(mApp, has, Config::CURRENT_LEDGER_PROTOCOL_VERSION,
                   /*restartMerges=*/false);

    // Rebuild plans for validation
    buildPlans();

    CLOG_INFO(Bucket, "BucketList loaded successfully (hot archive: {})",
              hasHotArchive);
}

// ============================================================================
// Accessors
// ============================================================================

std::vector<std::shared_ptr<LiveBucket>> const&
RandomBucketListGenerator::getLiveCurrBuckets() const
{
    return mLiveCurrBuckets;
}

std::vector<std::shared_ptr<LiveBucket>> const&
RandomBucketListGenerator::getLiveSnapBuckets() const
{
    return mLiveSnapBuckets;
}

std::vector<std::shared_ptr<HotArchiveBucket>> const&
RandomBucketListGenerator::getHotArchiveCurrBuckets() const
{
    return mHotArchiveCurrBuckets;
}

std::vector<std::shared_ptr<HotArchiveBucket>> const&
RandomBucketListGenerator::getHotArchiveSnapBuckets() const
{
    return mHotArchiveSnapBuckets;
}

std::vector<LevelPlan> const&
RandomBucketListGenerator::getLivePlans() const
{
    return mLivePlans;
}

std::vector<LevelPlan> const&
RandomBucketListGenerator::getHotArchivePlans() const
{
    return mHotArchivePlans;
}

// ============================================================================
// Utility Functions
// ============================================================================

bool
bucketContainsSorobanEntries(std::shared_ptr<LiveBucket> const& bucket)
{
    if (bucket->isEmpty())
    {
        return false;
    }

    for (LiveBucketInputIterator iter(bucket); iter; ++iter)
    {
        auto const& e = *iter;
        if (e.type() == METAENTRY)
        {
            continue;
        }

        LedgerEntryType let;
        if (e.type() == INITENTRY || e.type() == LIVEENTRY)
        {
            let = e.liveEntry().data.type();
        }
        else if (e.type() == DEADENTRY)
        {
            let = e.deadEntry().type();
        }
        else
        {
            continue;
        }

        if (let == CONTRACT_DATA || let == CONTRACT_CODE || let == TTL)
        {
            return true;
        }
    }
    return false;
}

} // namespace stellar
