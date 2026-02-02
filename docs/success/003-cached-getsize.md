# Cached getSize Optimization

## Summary

Cached the result of `xdr::xdr_size(mEnvelope)` in `TransactionFrame::getSize()` to avoid repeated XDR serialization size calculations. While this reduced the self-time of `getSize` by 68%, it did not result in a measurable TPS improvement because `getSize` was not on the critical apply path.

## Change

**Files**: 
- `src/transactions/TransactionFrame.cpp` (lines 2455-2463)
- `src/transactions/TransactionFrame.h` (line 74)

**Before**: `getSize()` called `xdr::xdr_size(mEnvelope)` every time.

**After**: Result is cached in `mCachedSize` member variable on first call.

```cpp
// TransactionFrame.h
mutable uint32_t mCachedSize{0}; // cached result of xdr_size(mEnvelope)

// TransactionFrame.cpp
uint32_t
TransactionFrame::getSize() const
{
    ZoneScoped;
    if (mCachedSize == 0)
    {
        mCachedSize = static_cast<uint32_t>(xdr::xdr_size(mEnvelope));
    }
    return mCachedSize;
}
```

## Results

### TPS Improvement

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Max sustainable TPS | 10,240 | 10,240 | **0%** |

### Tracy Microbenchmark Improvement

`getSize` self-time (total across 6 ledgers):

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Self-time | 819ms | 259ms | **-68%** |
| Calls | 3.3M | 3.3M | No change |

## Why No TPS Improvement

Although `getSize` self-time was reduced significantly, the function is called primarily during:
1. Transaction building (tryAdd phase) - before apply
2. TX set validation (checkValidInternal) - before apply
3. Surge pricing calculations - before apply

These phases are **not included in the benchmark timer** when `APPLY_LOAD_TIME_WRITES=true`. The benchmark only measures the `{"ledger", "ledger", "close"}` timer which covers `applyLedger` from start of fee processing through bucket list updates.

The optimization is still valuable for:
- Overall ledger close performance in production
- Reduced CPU usage during transaction building
- Lower latency for transaction submission

## Implementation Notes

- Used `mutable` qualifier since `getSize()` is a `const` method
- Zero-initialization is safe since XDR size is always > 0 for valid envelopes
- No thread-safety concerns since each TransactionFrame is accessed by one thread during apply

## Test Configuration

- Clusters: 4
- Batch size: 1 transfer/tx
- Target close time: 1000ms
- Search range: 8000-16000 TPS
- APPLY_LOAD_TIME_WRITES: true

## Date

2026-01-30
