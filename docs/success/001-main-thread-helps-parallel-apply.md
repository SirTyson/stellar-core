# Main Thread Helps Optimization

## Summary

Modified `applySorobanStageClustersInParallel()` to have the main thread process cluster 0 directly instead of launching all clusters as async tasks and waiting. This eliminates main thread idle time during parallel cluster execution.

## Change

**File**: `src/ledger/LedgerManagerImpl.cpp` (lines 2307-2371)

**Before**: Main thread launched N async tasks (one per cluster) and then waited for all to complete.

**After**: Main thread launches N-1 async tasks (clusters 1..N-1) and processes cluster 0 itself while others run in parallel.

```cpp
// Launch async tasks for clusters 1..N-1 (if any)
// Cluster 0 will be processed on the main thread to avoid idle waiting
for (size_t i = 1; i < numClusters; ++i)
{
    // ... launch async task for cluster i
}

// Process cluster 0 on the main thread while other clusters run in parallel
{
    auto const& cluster = stage.getCluster(0);
    auto result = applyThread(app, std::move(threadStatePtr), cluster, ...);
    threadStates.emplace_back(std::move(result));
}

// Collect results from async tasks (clusters 1..N-1)
for (auto& threadFuture : threadFutures)
{
    threadStates.emplace_back(threadFuture.get());
}
```

## Results

### TPS Improvement

| Metric | Baseline | Optimized | Change |
|--------|----------|-----------|--------|
| Max sustainable TPS | 7,680 | 8,960 | **+16.7%** |

### Tracy Microbenchmark Improvement

`applySorobanStageClustersInParallel` per-call timing:

| Metric | Baseline | Optimized | Change |
|--------|----------|-----------|--------|
| Mean time | 777ms | 569ms | **-27%** |
| Min time | 741ms | 495ms | **-33%** |
| Max time | 840ms | 641ms | **-24%** |

## Why It Works

The original implementation had the main thread:
1. Launch N async tasks
2. Wait for all N tasks to complete (doing nothing)

With 4 clusters, the main thread was idle for ~740ms per stage (the time for all clusters to complete).

The optimized implementation has the main thread:
1. Launch N-1 async tasks (clusters 1..N-1)
2. Process cluster 0 directly (productive work)
3. Wait for remaining N-1 tasks (some may already be done)

This converts ~25% of the main thread's waiting time into productive work, since cluster 0 typically takes similar time to other clusters.

## Test Configuration

- Clusters: 4
- Batch size: 1 transfer/tx
- Target close time: 1000ms
- Search range: 6000-12000 TPS

## Date

2026-01-30
