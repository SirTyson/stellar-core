#pragma once

// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/BucketUtils.h"
#include "bucket/HotArchiveBucket.h"
#include "bucket/LiveBucket.h"
#include "util/UnorderedSet.h"
#include "xdr/Stellar-ledger-entries.h"
#include <filesystem>
#include <map>
#include <memory>
#include <vector>

namespace stellar
{
class Application;

// Generates a synthetic Live BucketList and Hot Archive BucketList for testing
// eviction and other BucketList features. Buckets at each level are constructed
// directly and added to the BucketList, bypassing the slow ledger-close
// spill/merge path. However, it still takes a long time to generate the
// BucketList, so we generate it once and save it to a testdata directory.
//
// Generated Live BucketList properties
// ------------------------------------
//   - Some buckets are empty.
//   - Protocol versions increase monotonically from 19 to current protocol
//     version.
//   - Some buckets just contain classic entries, some contain a mix of classic
//     and Soroban entries.
//   - Entries exist in various lifecycle states, with keys shadowed across
//     multiple levels:
//       * CREATE_ONLY: entry created, never modified or deleted
//       * UPDATE: entry created, then updated one or more times
//       * DELETE: entry created, then deleted
//       * RECREATE: entry created, deleted, then recreated
//   - All soroban entries have a corresponding TTL entry, with a mix of expired
//     and live TTLs based on a constant fixed ledgerSeq.
//   - The BucketLists are "structurally correct" with respect to in-memory
//     state and eviction invariants, but do not respect any other invariants,
//     such as conservation of lumens.
//
// Generated Hot Archive BucketList properties
// -------------------------------------------
//   - Protocol versions increase monotonically from 23 to current protocol
//     version.
//   - Some buckets are empty.
//   - Entries exist in various lifecycle states:
//       * ARCHIVE_ONLY: entry archived, never restored (has DEADENTRY in live)
//       * ARCHIVE_RESTORE: entry archived, then restored (now live in live)
//       * ARCHIVE_RESTORE_ARCHIVE: entry archived, restored, then archived
//         again
//   - The Hot Archive BucketList is consistent with the Live BucketList. While
//     some keys purposefully overlap, they are always in the correct state
//     (e.g. a LIVE key in the Live BucketList is RESTORED in the Hot Archive
//     BucketList).
//

// ============================================================================
// Enums and Constants
// ============================================================================

enum class HotArchiveLifecycle
{
    ARCHIVE_ONLY,
    ARCHIVE_RESTORE,
    ARCHIVE_RESTORE_ARCHIVE
};

enum class HotArchiveLiveState
{
    NOT_IN_LIVE,
    LIVE_IN_LIVE,
    DEAD_IN_LIVE
};

// Lifecycle categories for live BucketList entries
enum class LiveLifecycle
{
    CREATE_ONLY, // Entry only exists as a single INIT entry
    UPDATE,      // Entry was created then updated via LIVEENTRY
    DELETE,      // Entry was deleted via DEADENTRY (and not recreated)
    RECREATE     // Entry was created, deleted, then created again
};

constexpr size_t MIN_ENTRIES_PER_CATEGORY = 100;
// LCL set to 13,107,199 (= 50 * 4^9 - 1). Next ledger spills level 8 but not
// level 9 (since 50 is not a multiple of 4). All levels 0-10 are populated.
constexpr uint32_t FIXED_LCL = 13'107'199;

constexpr size_t MIN_HOT_ARCHIVE_PER_LIFECYCLE = 50;
constexpr size_t MIN_HOT_ARCHIVE_ONLY = 30;
constexpr size_t MIN_RESTORED_AND_LIVE = 30;
constexpr size_t MINIMUM_NEW_ENTRIES_PER_BUCKET = 10;

// Minimum protocol versions for each BucketList type
constexpr uint32_t LIVE_MIN_PROTOCOL_VERSION = 19;
constexpr uint32_t HOT_ARCHIVE_MIN_PROTOCOL_VERSION = 23;

// Entry counts per bucket (curr, snap) for each level.
// Bottom levels (higher indices) have more entries since they represent older,
// accumulated data. Buckets with entry count 0 are empty to test empty bucket
// handling. Index 0 = level 0 (top), index 10 = level 10 (bottom).
//
// Live BucketList: empty buckets at level 5 curr, level 6 snap, level 10 snap
// (level 10 snap is never populated in real operation)
// Levels 0-8 have higher counts to ensure sufficient Soroban entries (protocol >= 20)
// Target: at least 100 RECREATE per Soroban type
inline std::vector<std::pair<size_t, size_t>> const LIVE_ENTRY_COUNTS = {
    {800, 640},   {1200, 960},  {1600, 1280}, {2400, 1920}, {3200, 2560}, {0, 4000},
    {4800, 0},    {5600, 4480}, {6400, 5120}, {1000, 800},  {1500, 0}};

// Hot Archive BucketList: empty buckets at level 3 curr, level 8 snap, level 10 snap
// (level 10 snap is never populated in real operation)
// Capacities are sized to accommodate initial archives, restores, and re-archives.
// Total capacity needs room for all three event types as they cascade through levels.
inline std::vector<std::pair<size_t, size_t>> const HOT_ARCHIVE_ENTRY_COUNTS = {
    {400, 200}, {500, 250}, {600, 300}, {0, 350},   {800, 400},  {900, 450},
    {1000, 500}, {1100, 550}, {1200, 0},  {1300, 650}, {1400, 0}};

// ============================================================================
// Configuration Structs
// ============================================================================

struct LevelPlan
{
    uint32_t protocolVersion;
    size_t currEntryCount;
    size_t snapEntryCount;
};

// ============================================================================
// Entry Counting Result Structs
// ============================================================================

// Results from counting Live BucketList entries
struct LiveBucketStats
{
    // Total entry counts across all buckets
    size_t totalInitCount = 0;
    size_t totalLiveCount = 0;
    size_t totalDeadCount = 0;

    // Lifecycle counts by entry type
    std::map<LedgerEntryTypeAndDurability, std::map<LiveLifecycle, size_t>>
        lifecycleCounts;
};

// Results from counting Hot Archive BucketList entries
struct HotArchiveBucketStats
{
    // Total entry counts across all buckets
    size_t totalArchivedCount = 0;
    size_t totalLiveCount = 0;

    // Lifecycle counts
    size_t archiveOnlyCount = 0;
    size_t archiveRestoreCount = 0;
    size_t archiveRestoreArchiveCount = 0;
};

// ============================================================================
// Intermediate Structs (defined early for use in EntryTracker)
// ============================================================================

struct BucketLedgerRange
{
    uint32_t lo; // oldest ledger (inclusive)
    uint32_t hi; // newest ledger (inclusive)
};

// ============================================================================
// Tracking Structs
// ============================================================================

// Identifies a specific bucket in the BucketList
struct BucketLocation
{
    uint32_t level;
    bool isCurr; // true = curr bucket, false = snap bucket

    bool operator==(BucketLocation const& other) const
    {
        return level == other.level && isCurr == other.isCurr;
    }

    bool operator<(BucketLocation const& other) const
    {
        if (level != other.level)
            return level < other.level;
        return isCurr < other.isCurr;
    }
};

// Event types for pending events (Live BucketList)
enum class EventType
{
    UPDATE,       // Update parent entry (TTL unchanged)
    TTL_EXTEND,   // Extend TTL only (parent unchanged)
    DELETE,       // Delete both parent and TTL
    RECREATE      // Recreate both parent and TTL
};

// Event types for hot archive pending events
enum class HotArchiveEventType
{
    INITIAL_ARCHIVE, // Initial archive from eviction
    RESTORE,         // Restore after archive
    REARCHIVE        // Re-archive after restore
};

// A pending event scheduled to execute at a specific bucket location.
// Contains all data needed to execute the event.
struct PendingEvent
{
    EventType type;

    // Last non-dead value of the LedgerEntry/TTL. Used when recreating or
    // modifying entries.
    LedgerEntry lastEntryValue;
    std::optional<uint32_t> lastTTLValue; // Only populated for Soroban entries
};

// A pending event scheduled for the hot archive BucketList
struct HotArchivePendingEvent
{
    HotArchiveEventType type;
    LedgerKey key;
    LedgerEntry entry; // The archived entry data
    HotArchiveLiveState liveState;
};

// ============================================================================
// RandomBucketListGenerator
// ============================================================================

class RandomBucketListGenerator
{
  public:
    explicit RandomBucketListGenerator(Application& app);

    // Main generation entry point - generates both Live and HotArchive
    void generate();

    // Validation
    void validateLiveStructure();
    void validateHotArchiveStructure();
    void validateCrossReferenceConsistency() const;

    // Fixture I/O
    void saveFixture(std::filesystem::path const& testDataDir);
    void loadFixture(std::filesystem::path const& testDataDir);

    // Accessors for results
    std::vector<std::shared_ptr<LiveBucket>> const& getLiveCurrBuckets() const;
    std::vector<std::shared_ptr<LiveBucket>> const& getLiveSnapBuckets() const;

    std::vector<std::shared_ptr<HotArchiveBucket>> const&
    getHotArchiveCurrBuckets() const;
    std::vector<std::shared_ptr<HotArchiveBucket>> const&
    getHotArchiveSnapBuckets() const;

    // Plan accessors (for validation after load)
    std::vector<LevelPlan> const& getLivePlans() const;
    std::vector<LevelPlan> const& getHotArchivePlans() const;

    // Entry counting - returns stats without side effects
    LiveBucketStats countLiveEntries() const;
    HotArchiveBucketStats countHotArchiveEntries() const;

    // Collect persistent entries from live BL that can be archived
    void collectArchivableEntries();

    // Reporting - logs stats to console
    static void reportLiveStats(LiveBucketStats const& stats);
    static void reportHotArchiveStats(HotArchiveBucketStats const& stats);

  private:
    Application& mApp;

    // Level plans
    std::vector<LevelPlan> mLivePlans;
    std::vector<LevelPlan> mHotArchivePlans;

    // Live BucketList state
    std::vector<std::shared_ptr<LiveBucket>> mLiveCurrBuckets;
    std::vector<std::shared_ptr<LiveBucket>> mLiveSnapBuckets;

    // Event backlog: map from bucket location to pending events
    std::map<BucketLocation, std::vector<PendingEvent>> mPendingEvents;

    // Keys we've already generated (to avoid duplicates)
    UnorderedSet<LedgerKey> mGlobalSeenKeys;

    // Hot Archive BucketList state
    std::vector<std::shared_ptr<HotArchiveBucket>> mHotArchiveCurrBuckets;
    std::vector<std::shared_ptr<HotArchiveBucket>> mHotArchiveSnapBuckets;

    // Hot archive event backlog: map from bucket location to pending events
    std::map<BucketLocation, std::vector<HotArchivePendingEvent>>
        mHotArchivePendingEvents;

    // Final state of "archivable" entries (persistent data and code) collected
    // from live BL for hot archive generation. mDeadArchivableEntries stores
    // the most recent LedgerEntry for a given deleted key.
    // mLiveArchivableEntries stores the most recent LedgerEntry for a live key.
    std::vector<LedgerEntry> mDeadArchivableEntries;
    std::vector<LedgerEntry> mLiveArchivableEntries;

    // Plan building
    void buildPlans();

    // Templated BucketList generation - works for both Live and HotArchive
    template <typename BucketT>
    void generateBucketList(std::vector<std::shared_ptr<BucketT>>& currBuckets,
                            std::vector<std::shared_ptr<BucketT>>& snapBuckets,
                            std::vector<LevelPlan> const& plans,
                            std::string const& bucketListName);

    // Templated entry building - returns ready-to-use bucket entries
    template <typename BucketT>
    std::vector<typename BucketT::EntryT>
    buildBucketEntries(BucketLocation const& location, LevelPlan const& plan);

    // Ledger range computation
    template <typename BucketT>
    BucketLedgerRange computeLedgerRange(BucketLocation const& location) const;

    // Bucket creation helper - takes pre-converted entries
    template <typename BucketT>
    std::shared_ptr<BucketT>
    createBucket(uint32_t protocolVersion,
                 std::vector<typename BucketT::EntryT> const& entries,
                 bool keepTombstones);

    // TTL generation helper
    uint32_t generateRandomTTL() const;

    // Schedule a pending event at a weighted random location (Live BucketList)
    void scheduleLiveBucketListEvent(PendingEvent event,
                                     BucketLocation const& minLocation);

    // Rolls dice for next lifecycle event after UPDATE, TTL_EXTEND, or RECREATE.
    // Either records the entry as finalized or schedules a follow-up event.
    // currentTTL is only populated for Soroban entries.
    void
    scheduleNextUpdateEvent(LedgerEntry const& entry,
                            BucketLocation const& location,
                            std::optional<uint32_t> currentTTL = std::nullopt);

    // Schedule a hot archive pending event at a weighted random location.
    // Returns true if scheduled, false if dropped (no capacity).
    bool scheduleHotArchiveEvent(HotArchivePendingEvent event,
                                 BucketLocation const& minLocation);
};

// ============================================================================
// Utility Functions
// ============================================================================

bool bucketContainsSorobanEntries(std::shared_ptr<LiveBucket> const& bucket);

} // namespace stellar
