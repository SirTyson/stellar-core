# H004: Avoid full LedgerEntry copy in getLiveEntryOpt for entries served from immutable in-memory caches

**Date**: 2026-04-30
**Subsystem**: ledger / transactions
**Severity**: Medium
**Impact**: apply-time CPU and allocation reduction in `applySorobanStageClustersInParallel`

**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `ThreadParallelApplyLedgerState::getLiveEntryOpt` resolves a key by
hitting `InMemorySorobanState::get` (or `mLCLSnapshot.loadLiveEntry`), the
underlying entry is an immutable `shared_ptr<LedgerEntry const>` shared
across all tx threads in a ledger. The lookup is intended to be a
near-O(1) cache hit. The handle returned to callers should reflect that:
no deep copy of the (potentially multi-KB) XDR object should happen for a
read-only access.

## Mechanism

`ThreadParallelApplyLedgerState::getLiveEntryOpt`
(`src/transactions/ParallelApplyUtils.cpp:1085-1121`) returns
`scopeAdoptEntryOpt(res ? std::make_optional(*res) : std::nullopt)`. The
`*res` dereference triggers a full `LedgerEntry` copy constructor —
recursively cloning XDR unions including the `CONTRACT_CODE.code` byte
vector — into a freshly heap-allocated `std::optional<LedgerEntry>` owned
by a `ScopedLedgerEntry`. This copy is performed **once per
(tx, footprint key)** because every tx in a cluster issues `addReads` /
`getLedgerEntryOpt` calls for its full read set. For the soroswap
workload the same router `CONTRACT_CODE` (and a handful of pool
`CONTRACT_DATA` entries) gets deep-copied by every one of the ~145 tx in
each ledger, on top of being re-encoded (see H003). The actual data is
already immutable in `InMemorySorobanState`; the copy exists only because
the helper API returns by value rather than threading a
`shared_ptr<LedgerEntry const>` through. Replacing the value-copy path
with a shared-ownership handle eliminates ~145× per-ledger redundant
allocations and memcpys of the largest read-only entries inside the
dominant `applySorobanStageClustersInParallel` zone.

## Trigger

Run the soroswap apply-load benchmark and instrument allocations /
self-time in `getLiveEntryOpt`, `addReads`, and `toCxxBuf`. The expected
delta is two-fold: (a) eliminate the per-tx `LedgerEntry` copy (allocator
+ memcpy), (b) make H003's encoded-bytes cache trivially keyed on
`shared_ptr` identity. Re-run the benchmark to confirm a measurable
apply-time reduction across multiple runs (this objective requires the
delta to survive noise).

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1085-1121` —
  `ThreadParallelApplyLedgerState::getLiveEntryOpt`. The line
  `scopeAdoptEntryOpt(res ? std::make_optional(*res) : std::nullopt)` is
  where the deep copy happens. Replacing the return type with one that
  carries a `shared_ptr<LedgerEntry const>` (and falls back to value
  ownership for non-cache hits) avoids the copy.
- `src/transactions/ParallelApplyUtils.cpp:1295-1320` —
  `TxParallelApplyLedgerState::getLiveEntryOpt`, the per-tx layer that
  also currently calls `scopeAdoptEntryOptFrom(thread.getLiveEntryOpt, ...)`
  and would need the same shared-handle plumbing.
- `src/transactions/ParallelApplyUtils.h:340-390` — the
  `(*Thread|*Tx)ParApplyLedgerEntryOpt` scope-handle types and the
  `LedgerAccessHelper::getLedgerEntryOpt` virtual contract; design
  challenge is keeping scope/lifetime checks intact while admitting
  shared ownership.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:421-498` —
  `addReads`, the consumer that forces an `*entryOpt` dereference and
  passes the value to `toCxxBuf`. With shared ownership we can pass the
  underlying object reference through without the copy.
- `src/ledger/InMemorySorobanState.cpp:207` — origin of the
  `shared_ptr<LedgerEntry const>` we want to thread through unchanged.

## Evidence

- The soroswap router contract code entry is large (multi-KB) and copied
  by every tx in every ledger. With ~145 tx/ledger × ~5 RO footprint
  entries averaging non-trivial XDR contents, the copy volume is ~MB/s
  per cluster thread of pure memcpy + heap traffic during the dominant
  `applySorobanStageClustersInParallel` zone (4.13 s self-time, 40% of
  `applyLedger` in the headline trace).
- The cache already exposes `shared_ptr<LedgerEntry const>`, signalling
  intent for shared ownership; the consumer-side copy is purely an
  artifact of the access-helper API surface.
- Stage-internal scope checking (`LedgerEntryScope<S>`) is concerned with
  *who can read/modify* the entry — orthogonal to whether the storage is
  owned-by-value or shared-by-pointer. The scoping invariants can be
  preserved by attaching the scope tag to a small handle that wraps the
  shared pointer instead of an `std::optional<LedgerEntry>`.
- This compounds with H003: once `getLiveEntryOpt` returns a shared
  handle, the encoded-bytes cache becomes trivially keyable by pointer
  identity, eliminating a separate hash lookup. Either hypothesis stands
  alone; together they remove both the encode and the copy from the
  per-tx footprint loop.
- Cluster threads contend for allocator scalability under load; cutting
  per-tx allocation count is known to lift parallel apply throughput on
  multi-core hosts (success/000-summary records two prior allocator-style
  wins of ~2–3% each).

## Anti-Evidence

- The handle types
  (`TxParApplyLedgerEntryOpt`, `ThreadParApplyLedgerEntryOpt`) and
  `LedgerEntryScope<S>` machinery are intentionally restrictive to
  enforce the cross-thread / cross-stage scoping invariants. Threading a
  `shared_ptr<LedgerEntry const>` through must not weaken those
  invariants — the design probably needs a wrapper that preserves the
  scope tag but stores the shared pointer.
- For RW entries, the global/thread maps store an
  `std::optional<LedgerEntry>` because the entry will be mutated. Only
  the *cache-served read-only fallback* path benefits from
  shared-ownership; the rest of the access path must continue to copy
  on first write. The change is therefore a fast-path addition, not a
  blanket refactor.
- A previous self-rejection
  (`fail/ledger/006-reuse-host-encoded-bytes-in-addlivebatch.md`)
  hit `lastModifiedLedgerSeq` stamping. That hazard is on the *write*
  side; the read-side copy elimination is unaffected.
- A simpler intermediate refactor — keeping the value copy but
  short-circuiting `addReads` to use the cached `shared_ptr` directly
  — gives most of the benefit with smaller blast radius and might be
  the right first step.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in ledger fail/success records
**Failed At**: reviewer

### Trace Summary

The specific `InMemorySorobanState::get` fallback copy exists, but it is not the per-transaction soroswap read-only path described by the hypothesis. `GlobalParallelApplyLedgerState::readOnlyPreParallelApply` preloads unique Soroban read-only keys and TTLs into `mGlobalEntryMap`, and each `ThreadParallelApplyLedgerState` copies matching global entries into `mThreadEntryMap` before worker execution; normal `addReads` lookups then hit the thread map rather than repeatedly dereferencing the immutable cache pointer. A real value-copy pattern remains in the scoped-entry API, but fixing it requires redesigning the global/thread/tx scoped wrappers and `LedgerAccessHelper` return contract, while the remaining `toCxxBuf` owned-buffer serialization/copy still runs for every read.

### Code Paths Examined

- `src/transactions/ParallelApplyUtils.cpp:646-718` — Soroban read-only footprint entries and TTLs are preloaded once per unique key into `mGlobalEntryMap`; the `std::make_optional(*res)` copy happens here, not once per transaction.
- `src/ledger/LedgerManagerImpl.cpp:2531-2575` — `applySorobanStageClustersInParallel` constructs each thread state under a deactivated global scope before launching the worker future, so global-to-thread entry copying is per cluster and on the setup path, not per transaction.
- `src/transactions/ParallelApplyUtils.cpp:925-1000` — thread state construction copies any needed global entries into `mThreadEntryMap` with `scopeAdoptEntryOptFrom`; this is the map normally consulted by transaction reads.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — thread-level `getLiveEntryOpt` first checks `mThreadEntryMap`; only keys absent from the preloaded global/thread maps fall through to `InMemorySorobanState::get` or `mLCLSnapshot.loadLiveEntry`.
- `src/transactions/ParallelApplyUtils.cpp:1294-1313` and `src/transactions/ParallelApplyUtils.cpp:337-342` — tx-level reads adopt the thread result into tx scope and then return `std::optional<LedgerEntry>` by value, so the remaining hot copy is caused by the scoped wrapper/value-return API rather than by repeated cache fallback.
- `src/ledger/LedgerEntryScope.h:278-320` and `src/ledger/LedgerEntryScope.cpp:189-207,486-501` — `ScopedLedgerEntryOpt` owns `std::optional<LedgerEntry>` and its copy constructor / const-scope adoption copy the optional payload.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:474-497` and `src/transactions/TransactionUtils.h:370-376` — `addReads` still serializes each returned entry into a fresh owned `CxxBuf` with `xdr::xdr_to_opaque`, so eliminating the `LedgerEntry` value copy alone does not eliminate the per-transaction XDR materialization path rejected in H003.
- `src/simulation/ApplyLoad.cpp:3441-3456` — each soroswap swap declares five read-only keys, including router code and pair code; these are exactly the keys preloaded into the global/thread maps.

### Why It Failed

The central mechanism is wrong for the target workload: the line `scopeAdoptEntryOpt(res ? std::make_optional(*res) : std::nullopt)` in `ThreadParallelApplyLedgerState::getLiveEntryOpt` is a fallback for keys not already in the thread map, while soroswap's large read-only Soroban entries are normally preloaded before worker execution. The actual per-read copies are an API-shape issue: `ScopedLedgerEntryOpt` stores entries by value, thread-map hits are returned through scoped optional values, and `LedgerAccessHelper::getLedgerEntryOpt` returns another `std::optional<LedgerEntry>` by value.

That API issue is real but does not meet this objective's Medium severity threshold as stated. For soroswap, the removable part is roughly two `LedgerEntry` value copies around the read helper for a small fixed read-only set per transaction; the much larger unavoidable work after this point still includes allocating an owned `CxxBuf`, XDR-encoding the entry, and Rust decoding the bytes for every invocation. Without direct measurement showing that the scoped-entry value copies alone consume at least 3% of top-line apply time, this is below the optimize-soroswap review floor and should not proceed to PoC.

### Lesson Learned

For parallel Soroban apply, distinguish immutable cache ownership from the actual read path used by workers. `InMemorySorobanState` is the source of preloaded entries, but the hot transaction loop usually reads copied values from scoped global/thread/tx maps; optimizations must measure the specific scoped-wrapper/value-return copies separately from the larger `addReads` XDR serialization and bridge-copy costs.
