# Optimization 002: Without-Loading Commit

## Summary
Reduced `commitChangesToLedgerTxn` time by 12% and `getNewestVersion` calls by 56% by using `createWithoutLoading()`/`updateWithoutLoading()` instead of the expensive `load()` + update pattern.

## Results

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **TPS** | 7,680 | 10,240 | **+33.3%** |
| **commitChangesToLedgerTxn** | 542ms | 478ms | **-12%** |
| **getNewestVersion** | 306ms | 136ms | **-56%** |
| **applySorobanStageClustersInParallel** | 985ms | 780ms | **-21%** |

Note: This includes cumulative improvements from optimization 001 (main-thread-helps + cluster sorting).

## Problem Analysis

In `commitChangesToLedgerTxn()`, the original code used `load()` + update/create pattern for every dirty entry:

```cpp
// Original (slow)
auto ltxe = ltxInner.load(key);
if (ltxe) {
    ltxe.current() = *updatedLe;
} else {
    ltxInner.create(*updatedLe);
}
```

The `load()` call triggers `getNewestVersion()` which is expensive (306ms total self-time for 700k+ calls). Most of this was unnecessary because we already know whether entries existed before parallel apply started.

## Solution

Track which keys existed in the LedgerTxn before parallel apply:

1. Added `std::unordered_set<LedgerKey> mOriginalLedgerTxnKeys` to `GlobalParallelApplyLedgerState`
2. Populate it when loading classic entries from LedgerTxn during initialization
3. In `commitChangesToLedgerTxn()`, check if key was original:
   - For Soroban in-memory types: check `mInMemorySorobanState.get(key)`
   - For other types: check `mLiveSnapshot->load(key)` 
4. Use `updateWithoutLoading()` for existing entries, `createWithoutLoading()` for new ones
5. For deletions: Still use `load()` + `erase()` pattern (using `eraseWithoutLoading()` sets EXTRA_DELETES consistency which breaks downstream `getChanges()`/`getDelta()` calls)

## Key Code Changes

### ParallelApplyUtils.h
```cpp
class GlobalParallelApplyLedgerState {
    // ...
    std::unordered_set<LedgerKey> mOriginalLedgerTxnKeys;
};
```

### ParallelApplyUtils.cpp

During initialization (line ~357):
```cpp
auto lk = LedgerEntryKey(le);
mOriginalLedgerTxnKeys.emplace(lk);  // Track original keys
mGlobalEntryMap.try_emplace(...);
```

In `commitChangesToLedgerTxn()`:
```cpp
// Check if entry existed before parallel apply
bool originallyExisted = mOriginalLedgerTxnKeys.find(key) != mOriginalLedgerTxnKeys.end();
if (!originallyExisted) {
    if (InMemorySorobanState::isInMemoryType(key))
        originallyExisted = mInMemorySorobanState.get(key) != nullptr;
    else
        originallyExisted = mLiveSnapshot->load(key) != nullptr;
}

if (updatedLe) {
    if (originallyExisted)
        ltxInner.updateWithoutLoading(*updatedLe);
    else
        ltxInner.createWithoutLoading(*updatedLe);
} else {
    // For deletions, still use load() + erase() to avoid EXTRA_DELETES
    if (originallyExisted) {
        auto ltxe = ltxInner.load(key);
        if (ltxe)
            ltxInner.erase(key);
    }
}
```

## Tracy Trace Files

- Previous: `~/logs/ai/max-sac-tps/2026-01-30_15-46-05_main-thread-helps-sorted.tracy`
- After: `~/logs/ai/max-sac-tps/2026-01-30_16-11-53_without-loading-commit-v2.tracy`

## Files Modified

- `src/transactions/ParallelApplyUtils.h` - Added `mOriginalLedgerTxnKeys` member
- `src/transactions/ParallelApplyUtils.cpp` - Modified initialization and `commitChangesToLedgerTxn()`

## Important Constraints

- Cannot use `eraseWithoutLoading()` - it sets EXTRA_DELETES consistency level which breaks `getChanges()`/`getDelta()` calls used by downstream code
- Must still check `mInMemorySorobanState` and `mLiveSnapshot` for entries that weren't in the original LedgerTxn
