# H006: Cache pre-encoded XDR buffer alongside InMemorySorobanState entries to skip `addReads` re-serialization

**Date**: 2026-05-03
**Subsystem**: transactions / ledger / bucket
**Severity**: Low
**Impact**: Remove the `toCxxBuf(*entryOpt)` XDR re-serialization (and the implicit `xdr::xdr_size` pre-walk) inside `InvokeHostFunctionOpFrame::HostFunctionMetricsHandler::addReads` for every Soroban footprint key.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`addReads` (`src/transactions/InvokeHostFunctionOpFrame.cpp:386-535`) is invoked twice per
Soroban tx (once for the read-only footprint, once for the read-write footprint) to populate
`mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs` — the buffers that get passed across the C++/Rust
bridge into `invoke_host_function`. For every footprint entry it currently:

1. Calls `getLedgerEntryOpt(lk)` to fetch a deserialized `LedgerEntry` from
   `InMemorySorobanState` (CONTRACT_DATA, CONTRACT_CODE) or from `mLCLSnapshot.loadLiveEntry`
   (classic ACCOUNT/TRUSTLINE).
2. Calls `toCxxBuf(*entryOpt)` (`InvokeHostFunctionOpFrame.cpp:484`) which calls
   `xdr::xdr_size(le)` followed by a full XDR `marshal` into a freshly allocated
   `std::vector<uint8_t>`.
3. Same for the TTL entry (`toCxxBuf(*ttlEntry)` line 493).

Expected behavior: since `InMemorySorobanState` is loaded from the BucketList (which already
holds the entries in their canonical XDR form), and CONTRACT_DATA / CONTRACT_CODE / TTL entries
inside `InMemorySorobanState` are immutable for the lifetime of a single `applyLedger` call,
the XDR encoding of every `InMemorySorobanState` entry should be computed at most once per
ledger close — not once per footprint read across thousands of parallel-apply transactions. The
bridge call should reuse a cached buffer (or pointer to canonical bucket bytes) when the entry
is unchanged.

## Mechanism

The actual implementation re-serializes the LedgerEntry from its deserialized form on every
single `addReads` invocation. For soroswap, with ~95 invoke-host txs/ledger × ~10 footprint
entries each × 2 buffers (entry + TTL) = ~1900 XDR serialization passes per ledger. Each
serialization walks the entry tree, computes the size, allocates a vector, then writes bytes.

The deviation from expected behaviour is the redundant per-tx serialization of identical
immutable entries. A cache keyed by `InMemoryIndex` slot pointer (or by the
`ParallelApplyLedgerKey` hash already cached by success #4) could amortize the work to once
per (ledger, entry) instead of once per (ledger, entry, footprint-read).

## Trigger

Run the soroswap apply-load benchmark with Tracy; observe the `addReads` zone (Tracy: 197 ms
self / 13648 calls = 14.4 µs/call). Each call serializes ~10-12 KB of LedgerEntry data; the
bulk of that work is XDR walking + vector allocation visible only as `addReads` self-time
because the inner `xdr_size`/`marshal` calls are not Tracy-zoned.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` entry-handling loop.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:484-497` — `toCxxBuf(*entryOpt)` and
  `toCxxBuf(*ttlEntry)` per-entry serialization sites.
- `src/bucket/InMemorySorobanState.h/.cpp` — would need an `xdrBuf` cache slot per entry, or a
  side cache keyed by entry pointer.
- `src/transactions/ParallelApplyUtils.cpp:1084-1118` — `getLiveEntryOpt` returns the
  `LedgerEntry`; would need a parallel API returning a `(LedgerEntry, CxxBuf)` pair.

## Evidence

- Tracy `addReads` self-time = 196.7 ms / 13648 calls = ~14.4 µs/call across the 71-ledger
  trace. With NUM_CLUSTERS=8 worker parallelism, wall savings if 100% removable ≈
  196.7 ms / 8 / 71 ≈ 0.35 ms / ledger.
- Soroswap baseline = 272.9 ms / ledger; 0.35 ms = 0.13 % — well below Low.
- Even an end-to-end "cache + bypass `toCxxBuf`" win cannot reach Medium (8.2 ms / ledger);
  it cannot reach Low either.

## Anti-Evidence

1. **Cache invalidation cost**: every entry mutated by a parallel-apply tx must re-encode for
   downstream commits. The cost of cache maintenance (on writes) likely exceeds the savings on
   reads, especially for the RW footprint.
2. **Memory cost**: holding a serialized buffer alongside the deserialized `LedgerEntry`
   doubles the resident-set size of `InMemorySorobanState`, which is already meaningful at
   apply-load scale.
3. **Bucket-side serialized form is not 1:1 with the live entry**: bucket entries live inside
   `BucketEntry` envelopes and are not byte-equal to the `LedgerEntry` body the bridge expects.
   The cache cannot trivially share the bucket bytes; it would have to materialize a fresh
   per-entry buffer on first read.
4. **Below objective threshold even at idealized 100% savings.**

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail #003 (which targeted the *probe count*, not the
serialization step).

### Why It Failed

Quantification kills it. The `addReads` zone totals 197 ms self across the entire 71-ledger
trace. After dividing by NUM_CLUSTERS=8 (parallel-phase zone) we get ~24.6 ms / 71 ≈ 0.35 ms
saved per ledger at the 100 %-removal idealized limit. That is 0.13 % of the 272.9 ms soroswap
baseline — below benchmark noise (1 %), and well below the Low (1-3 %) and Medium (3-10 %)
thresholds enforced by this objective. Even adding the ~30 ms / ledger cache-side bookkeeping
overhead bookkeeping makes the net change net-negative in the worst case.

### Lesson Learned

Re-serialization in `addReads` is real but tiny: the `addReads` self-time bound caps any
optimization in this exact zone at sub-Low. Future angles attacking the C++/Rust bridge cost
must look at *aggregate* bridge-side work (`ledger_info`, footprint encoding, auth payloads,
contract-event decode on the return path) rather than the input-side `LedgerEntry` buffer
specifically.
