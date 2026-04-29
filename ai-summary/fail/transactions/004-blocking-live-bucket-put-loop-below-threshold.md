# H004: Pipeline Blocking Live-Bucket Put Loop During Finalization

**Date**: 2026-04-29
**Subsystem**: transactions, bucket
**Severity**: Low
**Impact**: blocking BucketList write serialization during soroswap ledger finalization
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After Soroban transactions are applied, Core should synchronously persist the deterministic live BucketList changes needed for the ledger header hash, update in-memory Soroban state, and wait only for blocking bucket work that is required for the just-closed ledger. Background bucket merges remain out of scope, but the live first-level batch write must still produce the same bucket bytes, hash, index, and in-memory entries.

## Mechanism

`finalizeLedgerTxnChanges` calls `ltx.getAllEntries`, starts an async in-memory state update, and then blocks in `BucketManager::addLiveBatch`, where `BucketLevel<LiveBucket>::prepareFirstLevel` eventually calls `LiveBucket::mergeInMemory`. That path merges entries in memory and then serializes/hashes the merged entries through `BucketOutputIterator::put` before the apply path can finish. The apparent optimization would pipeline or parallelize the serialization/hashing put loop with more of the in-memory merge work, but current trace overlap shows the blocking portion is too small to clear the objective's Medium threshold.

## Trigger

Run the current soroswap Tracy benchmark and inspect `finalizeLedgerTxnChanges`, `addLiveBatch`, `mergeInMemory put loop`, `BucketOutputIterator::put`, and `writeOne` zones that overlap `applyLedger`. The issue would trigger on Soroban-heavy ledgers with high write volume, where many modified contract data, contract code, and TTL entries are flushed into the live BucketList at ledger finalization.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3215-3367` — `finalizeLedgerTxnChanges` performs eviction resolution, loads final Soroban config, extracts all entries, starts in-memory state update, and blocks on `addLiveBatch`.
- `src/bucket/BucketManager.cpp:1026-1046` — `BucketManager::addLiveBatch` synchronously calls the live BucketList batch insertion path.
- `src/bucket/BucketListBase.cpp:225-237` — first-level live buckets use `freshInMemoryOnly` followed by `LiveBucket::mergeInMemory`.
- `src/bucket/LiveBucket.cpp:648-690` — `mergeInMemory` creates merged entries, starts index construction asynchronously, then runs the blocking put loop before waiting for the index.
- `src/bucket/BucketOutputIterator.cpp:78-165` — `BucketOutputIterator::put` validates ordering, buffers entries, and writes prior entries through XDR serialization/hashing.

## Evidence

The path is inside the measured apply window and is not a background merge: `finalizeLedgerTxnChanges` overlaps `applyLedger` by 286.721 ms across 69 ledgers in the current soroswap diagnostic trace. `BucketOutputIterator::put` has 168.629 ms apply-window overlap across 346,383 calls, `writeOne` at `util/XDRStream.h:485` has 203.762 ms total self-time across 560,061 calls, and `addLiveBatch` totals 294.648 ms across 70 calls. The code confirms `mergeInMemory` already parallelizes index construction but keeps the serialization/hashing put loop on the blocking apply thread.

## Anti-Evidence

The overlap is spread across 69 ledgers, so the average blocking finalization cost is only about 4 ms per ledger in the diagnostic trace, below the 3% Medium threshold for the current roughly 300 ms non-Tracy soroswap median. The code also already avoids writing the temporary first-level snap bucket (`freshInMemoryOnly`) and starts index construction in parallel with the put loop, leaving less low-risk work to remove. Further parallelizing bucket byte emission risks changing hash/write ordering unless carefully designed, and the projected win is below objective severity.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — blocking live-bucket put-loop pipelining was not listed in the transactions failure summary

### Why It Failed

The code path is real and apply-blocking, but the current soroswap trace shows only about 286.721 ms of `finalizeLedgerTxnChanges` overlap across 69 ledgers and about 168.629 ms of `BucketOutputIterator::put` overlap. Even an optimistic implementation that removed a large fraction of this work would average below the objective's 3% Medium floor, and the remaining work is correctness-sensitive bucket serialization and hash production.

### Lesson Learned

Blocking bucket finalization should be checked per ledger before promotion. Aggregate trace totals can look large, but when spread across many apply windows the live-bucket first-level write path is currently a Low-tier optimization, unlike background bucket merge work which is explicitly out of scope.
