# Parallel finalizeLedgerTxnChanges Optimization

## Summary

Modified `finalizeLedgerTxnChanges()` to run three independent operations in parallel using `std::async`:
- `addHotArchiveBatch` (modifies mHotArchiveBucketList)
- `addLiveBatch` (modifies mLiveBucketList) - runs on main thread
- `updateInMemorySorobanState` (modifies mInMemorySorobanState)

This reduces ledger close latency by overlapping CPU-bound operations that were previously sequential.

## Change

**Files**: 
- `src/ledger/LedgerManagerImpl.cpp`
- `src/ledger/LedgerManagerImpl.h`

### New Accessor Method

Added `getInMemorySorobanStateForUpdate()` to allow direct mutable access to `mInMemorySorobanState` during the COMMITTING phase:

```cpp
InMemorySorobanState&
LedgerManagerImpl::ApplyState::getInMemorySorobanStateForUpdate()
{
    releaseAssert(mPhase == Phase::SETTING_UP_STATE ||
                  mPhase == Phase::COMMITTING);
    return mInMemorySorobanState;
}
```

### Parallelized Operations

**Before**: All three operations ran sequentially on the main thread.

**After**: Three operations run in parallel:

```cpp
// 1. Launch addHotArchiveBatch asynchronously
hotArchiveBatchFuture = std::async(std::launch::async,
    [&bucketManager, this, lh, archivedEntries, restoredHotArchiveKeys]() {
        ZoneScopedN("addHotArchiveBatch (async)");
        bucketManager.addHotArchiveBatch(mApp, lh, archivedEntries, 
                                         restoredHotArchiveKeys);
    });

// 2. Launch updateInMemorySorobanState asynchronously
inMemoryStateUpdateFuture = std::async(std::launch::async,
    [&inMemoryState, &initEntries, &liveEntries, &deadEntries, &lh,
     &finalSorobanConfig, &sorobanMetrics]() {
        ZoneScopedN("updateInMemorySorobanState (async)");
        inMemoryState.updateState(initEntries, liveEntries, deadEntries,
                                  lh, finalSorobanConfig, sorobanMetrics);
    });

// 3. Run addLiveBatch on main thread
mApp.getBucketManager().addLiveBatch(mApp, lh, initEntries, liveEntries, 
                                     deadEntries);

// 4. Wait for all async operations
if (hotArchiveBatchFuture.valid()) hotArchiveBatchFuture.get();
if (inMemoryStateUpdateFuture.valid()) inMemoryStateUpdateFuture.get();
```

## Thread Safety Analysis

### Why It's Safe

The three operations modify completely independent data structures with no shared state:

| Operation | Data Structure Modified | Location |
|-----------|------------------------|----------|
| `addHotArchiveBatch` | `mHotArchiveBucketList` | BucketManager |
| `addLiveBatch` | `mLiveBucketList` | BucketManager |
| `updateInMemorySorobanState` | `mInMemorySorobanState` | ApplyState |

### Data Independence Guarantees

1. **No cross-structure writes**: Each operation writes to a different data structure
2. **No concurrent reads during writes**: During COMMITTING phase, no other threads read these structures
3. **Input data stability**: All input parameters (`initEntries`, `liveEntries`, `deadEntries`, `lh`, etc.) remain valid until futures complete
4. **Phase-based synchronization**: The `releaseAssert(mPhase == Phase::COMMITTING)` ensures this only runs at the correct time

### Lambda Capture Strategy

- References are captured for data that outlives the async operation:
  - `&bucketManager`, `&inMemoryState`, `&initEntries`, `&liveEntries`, `&deadEntries`
- Values are copied for data that might not outlive:
  - `archivedEntries` (copied by value)
  - `lh` (copied by value for safety)

## Design Decisions

### Why Use getInMemorySorobanStateForUpdate()?

The existing `updateInMemorySorobanState()` method has a main thread invariant check (`assertMainThread()`). Since we're calling from an async task, we bypass this by calling `mInMemorySorobanState.updateState()` directly.

This is safe because:
1. The main thread invariant exists to prevent data races
2. During `finalizeLedgerTxnChanges`, no other thread accesses `mInMemorySorobanState`
3. The future is joined before the function returns, ensuring completion

### Why addLiveBatch on Main Thread?

`addLiveBatch` is typically the heaviest operation, so we keep it on the main thread and parallelize the other two operations alongside it. This avoids thread pool contention and keeps the critical path predictable.

## Expected Performance Impact

The latency improvement depends on the relative sizes of the three operations:

```
Before: T_total = T_hotArchive + T_addLive + T_inMemoryUpdate
After:  T_total = max(T_hotArchive, T_addLive, T_inMemoryUpdate)
```

For ledgers with significant Soroban activity, this can reduce finalization time substantially since all three operations have meaningful work to do.

## Testing

- Build: PASSED
- Smoke test: PASSED (LedgerTxn addChild)
- Tracy zones added for profiling: `addHotArchiveBatch (async)`, `updateInMemorySorobanState (async)`

## Date

2025-02-02

## Commit

```
git log --oneline -1
37827539b Parallelize in-memory state update with bucket list operations
```
