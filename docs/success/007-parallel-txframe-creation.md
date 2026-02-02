# Successful Optimization: Parallel TxFrame Creation

**Date**: 2026-02-02
**Commits**:
- `5c388492b` - Revert batch signature verification and signature cache warming
- `9199af40c` - Parallelize TxFrame creation during transaction set deserialization
- `f5e1006e9` - Cache XDR size in InMemorySorobanState entries

## Summary

Replaced batch signature verification and signature cache warming with parallel TxFrame creation during transaction set deserialization. This provides more comprehensive parallelization by covering all TxFrame construction work, not just signature verification.

## Previous Approach (Reverted)

The previous optimizations (docs 004 and 006) attempted to improve TPS by:
1. **Batch signature verification** (`batchVerifySig`): Verified signatures in batches using Rust ed25519-dalek
2. **Signature cache warming** (`warmSignatureCacheParallel`): Pre-verified source account signatures before parallel apply

### Limitations of Previous Approach
- Only covered single-signer transactions with matching hints
- Required complex filtering logic
- Signature verification was already cached, limiting the benefit
- Did not parallelize the actual TxFrame construction work

## New Approach

Parallelize the TxFrame creation during transaction set deserialization in `TxSetFrame.cpp`:

### Key Changes

1. **`createTxFramesParallel()`**: New function that creates TxFrames from XDR envelopes in parallel
   - Divides work evenly among available threads
   - Uses `std::async` with work-stealing
   - Precomputes hashes to avoid race conditions

2. **`addWireTxsToList()`**: Modified to accept `maxThreads` parameter and use parallel creation

3. **`makeFromWireParallel()`**: Restructured to:
   - Flatten all transaction envelopes with position tracking
   - Create all TxFrames in parallel
   - Reconstruct the nested stage/cluster structure
   - Verify sorting (fast since hashes are precomputed)

### Code Structure

```cpp
// Parallel TxFrame creation
auto createTx = [&](size_t index) {
    auto tx = TransactionFrameBase::makeTransactionFromWire(networkID, xdrTxs[index]);
    if (!tx->XDRProvidesValidFee()) {
        validationFailed.store(true, std::memory_order_relaxed);
        return;
    }
    // Precompute hashes to avoid race conditions in sorting
    (void)tx->getContentsHash();
    (void)tx->getFullHash();
    results[index] = std::move(tx);
};
```

## Additional Optimization: Cached XDR Size

Added `sizeBytes` field to `ContractDataMapEntryT` in `InMemorySorobanState` to cache the XDR serialized size. This avoids repeated `xdr_size()` calls during entry updates.

## Why This is Better

1. **More comprehensive**: Parallelizes all TxFrame construction, not just signature verification
2. **Simpler**: No complex hint-matching or filtering logic
3. **Earlier in pipeline**: Work happens during deserialization, before apply phase
4. **Covers all transactions**: Not limited to single-signer transactions

## Files Modified

- `src/herder/TxSetFrame.cpp` - Added parallel TxFrame creation
- `src/herder/TxSetFrame.h` - Updated function signatures
- `src/crypto/SecretKey.cpp` - Removed `batchVerifySig`
- `src/crypto/SecretKey.h` - Removed `batchVerifySig` declaration
- `src/transactions/ParallelApplyUtils.cpp` - Removed `warmSignatureCacheParallel`
- `src/ledger/InMemorySorobanState.cpp` - Added cached XDR size
- `src/ledger/InMemorySorobanState.h` - Added `sizeBytes` field
- `src/ledger/LedgerTxn.cpp` - Added Tracy zone

## Supersedes

This optimization supersedes:
- **004-batch-signature-verification.md** - Batch signature verification
- **006-signature-cache-warming.md** - Signature cache warming

Those approaches are no longer used as parallel TxFrame creation provides better overall throughput.
