# H001: Share read-only footprint LedgerEntry/TTL CxxBufs (and their Rust-side decoded forms) across all txs in a soroswap cluster

**Date**: 2026-04-27
**Subsystem**: transactions
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing redundant per-tx XDR serialization and Rust-side decoding of identical read-only Soroban entries within a cluster.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a soroswap cluster, every tx in the cluster shares the same read-only
footprint (the same pair contract data, contract code, and instance keys —
the apply-load generator constructs exactly one pair per cluster and
round-robins swaps across txs in that cluster). Because read-only entries
cannot change inside the cluster (parallel apply enforces RO-vs-RW
disjointness via the conflict check before clusterization), the
on-disk-equivalent bytes of those RO entries — and their decoded Rust-side
`Rc<LedgerEntry>` / `Rc<TtlEntry>` representations — are byte-identical for
every tx in the cluster. The expected behavior is that Core constructs each
RO entry's `CxxBuf` (XDR encode), passes it across the bridge, and decodes
it on the Rust side **at most once per cluster**, then reuses the cached
result for the rest of the cluster's txs while still charging the per-tx
metering for "I/O and cloning of an Rc" deterministically. Observable host
behavior — metering, errors, footprint validation, returned values — must
be unchanged, since the Rust host only sees the same `Rc<LedgerEntry>`
contents it would have constructed itself.

## Mechanism

Today, `InvokeHostFunctionOpFrame::HostFunctionMetricsHelper::addReads`
iterates every footprint key for every tx and unconditionally calls
`toCxxBuf(*entryOpt)` and `toCxxBuf(*ttlEntry)` (which internally do
`xdr_to_opaque`, a full XDR marshalling pass + a `std::vector<uint8_t>`
allocation) for read-only keys. The resulting `CxxBuf`s are then handed to
`rust_bridge::invoke_host_function`, where
`build_storage_map_from_xdr_ledger_entries` decodes the bytes back into
`Rc<LedgerEntry>` / `Rc<TtlEntry>` for every tx, and inserts them into a
fresh `MeteredOrdMap`. For a soroswap cluster of ~500 txs sharing the same
5 RO keys, this is ~2500 redundant XDR encode + 2500 redundant XDR decode
+ 2500 redundant `Rc::metered_new` round-trips per cluster, all on the
parallel-apply critical path. The fix is to encode and decode each RO
entry once per cluster (in `applyThread` setup, before iterating txs) and
share the resulting `CxxBuf` (or, even better, a Rust-side cached
`Rc<LedgerEntry>` / `Rc<TtlEntry>` keyed by cluster-id) across all txs in
that cluster. RW entries are unaffected since they may diverge between
txs.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the soroswap config and 8
clusters × 4000 tx ledgers (the headline benchmark). Observe with Tracy
that `applyThread` runs `addReads` and the Rust-side
`build_storage_map_from_xdr_ledger_entries` once per tx, and that the
Tracy zones for `read xdr with budget` (~36 ms aggregate) and the
`addReads` loop body show ~10× the necessary call count for read-only
keys. After applying the fix, the same call counts for RO-key encode/
decode should drop to ~1× per cluster (~8 per ledger × 5 keys = 40 calls
instead of 20 000).

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-498` —
  `addReads` calls `toCxxBuf` on every RO LedgerEntry + TTLEntry per tx.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` does a full
  `xdr_to_opaque` and allocates a fresh `std::vector<uint8_t>` for each
  entry, every tx.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:540-584` —
  `invokeHostFunction` hands the per-tx `mLedgerEntryCxxBufs` /
  `mTtlEntryCxxBufs` to the Rust bridge.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` —
  `build_storage_map_from_xdr_ledger_entries` decodes those bytes back
  per tx (and is also the target of the in-pipeline reviewed/001
  bulk-build optimization, which complements but does not subsume this
  hypothesis).
- `src/ledger/LedgerManagerImpl.cpp:2483-2574` — `applyThread` is the
  worker-thread loop that owns each cluster; this is where shared RO
  entry caching for the cluster naturally lives.
- `src/transactions/ParallelApplyUtils.cpp:431-598` — preParallelApply
  already separates RO vs RW handling per cluster, providing a precedent
  for cluster-scoped shared RO state.

## Evidence

- The soroswap apply-load generator at `src/simulation/ApplyLoad.cpp:
  3382-3505` (per the `benchmarking` memory) creates **one pair per
  cluster** and round-robins swaps; the RO footprint (pair contract
  data + WASM code + instance) is therefore literally identical across
  ~500 txs/cluster.
- Tracy `applySorobanStages` total = 1793 ms / 65 ledgers = ~27.6 ms per
  ledger wall; `InvokeHostFunctionOpFrame doParallelApply` total worker
  time is ~4787 ms in the headline trace. Removing thousands of
  redundant per-tx XDR encode/decode + `Rc::metered_new` round-trips
  should plausibly recover several percent of `applySorobanStages`.
- Every RO entry the cluster touches lives in
  `mInMemorySorobanState` (per the bucket-indexing memory: in-memory
  for buckets <20 MB), so the encode source is already a stable
  pointer; caching the encoded `CxxBuf` does not change lifetime
  semantics.
- The conflict check that builds clusters (in
  `ParallelApplyUtils.cpp`) guarantees no other cluster is mutating a
  given RO key during the stage, so the cached entry stays valid for
  the cluster's lifetime.
- Existing precedent: `previouslyRestoredFromHotArchive(lk)` at
  `InvokeHostFunctionOpFrame.cpp:450` already reuses prior
  cross-tx state for restored entries; the proposed cache extends the
  same pattern to the (much hotter) all-RO path.

## Anti-Evidence

- Metering must remain per-tx: each tx still has to pay the
  `MeteredOrdMap::insert`/`Rc::metered_new` budget charges for its
  footprint. The fix must arrange to charge the budget on every tx
  (e.g., re-cloning a cached `Rc<LedgerEntry>` and re-inserting into a
  per-tx `MeteredOrdMap`) without redoing the XDR
  encode/decode. If metering of "decode XDR" is observable in
  `Storage`, the change must call into the same charge functions to
  keep gas identical — otherwise determinism breaks across protocol
  versions.
- The `ParallelApplyUtils` per-tx footprint validation paths
  (especially `addArchivedEntryAndOptionalAutorestore`) have edge
  cases — archived entries, hot-archive restores, autorestore — that
  do mutate cross-tx state. The cache must only short-circuit the
  pure-RO-and-live path; archived/restored RO keys must fall back to
  the slow path.
- The reviewed/001 hypothesis (`bulk-build-soroban-storage-maps`)
  attacks the Rust-side `MeteredOrdMap::insert` cost directly and may
  capture some of the same wins. The two are complementary (one
  removes per-insert allocation, the other removes per-tx encode/
  decode entirely for RO keys), but if reviewed/001 lands first and
  shrinks `applySorobanStages` substantially, this hypothesis must be
  re-measured before commit.
- `toCxxBuf`-level CPU cost per entry is small (microseconds), so the
  win comes mainly from amortizing the Rust-side decode + `Rc`
  allocation + `MeteredOrdMap` insert. PoC must demonstrate ≥3% top-
  line apply-time reduction across repeated runs to clear Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success transaction or cross-subsystem record found
**Failed At**: reviewer

### Trace Summary

The repeated encode/decode path exists: every successful parallel Soroban invocation constructs a fresh apply helper, `addFootprint()` calls `addReads()` for the transaction's read-only and read-write footprints, and every existing entry is serialized into fresh `CxxBuf`s before the Rust bridge decodes them into a fresh storage map. This is in the `closeLedger` parallel apply hot path through `applyThread()`. However, the proposed cluster-wide cache is not correct as stated because a final apply cluster is a sequential bin that may contain RO/RW conflicts or artificially packed independent logical clusters; the conflict builder merges RO/RW overlaps into the same cluster rather than proving read-only immutability inside the cluster. Even ignoring that correctness issue, the hypothesis's own cited Tracy cost for Rust XDR reads is about 36 ms aggregate versus 1793 ms aggregate `applySorobanStages`, so the projected top-line improvement is below this objective's Medium threshold.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread()` iterates every `TxBundle` in a cluster and calls `TransactionFrameBase::parallelApply()` once per tx on the apply critical path.
- `src/transactions/TransactionFrame.cpp:2386-2454` — `TransactionFrame::parallelApply()` dispatches the single Soroban operation to `OperationFrame::parallelApply()` and records successful changes.
- `src/transactions/OperationFrame.cpp:175-188` — `OperationFrame::parallelApply()` calls `doParallelApply()` for Soroban operations.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `InvokeHostFunctionOpFrame::doParallelApply()` constructs a fresh `InvokeHostFunctionParallelApplyHelper` for every tx and calls `helper.apply()`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-498` — `addReads()` iterates each footprint key and serializes every present ledger entry with `toCxxBuf(*entryOpt)` and every TTL with `toCxxBuf(*ttlEntry)`, including read-only keys.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf()` allocates a new `std::vector<uint8_t>` from `xdr::xdr_to_opaque(t)` for each object.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction()` passes the per-tx `mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs` into `rust_bridge::invoke_host_function()`.
- `src/rust/src/bridge.rs:193-208` and `src/rust/src/soroban_invoke.rs:7-38` — the Rust bridge takes per-tx vectors of encoded ledger and TTL entries and forwards them to the selected protocol module.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-449,959-1052` — `invoke_host_function()` calls `build_storage_map_from_xdr_ledger_entries()`, which decodes each entry with `metered_from_xdr_with_budget`, wraps it in `Rc::metered_new`, derives a key, optionally decodes TTL, and inserts into fresh metered maps.
- `src/transactions/ParallelApplyUtils.cpp:32-39,84-90` — the parallel apply comments define conflicts and state that clusters run sequentially; they do not guarantee RO-vs-RW disjointness inside a cluster.
- `src/herder/ParallelTxSetBuilder.cpp:57-60,627-693` — the builder treats shared keys as conflicts only when at least one side is read-write and records RO/RW conflicts; such transactions are placed together, not separated from the cluster.
- `src/herder/ParallelTxSetBuilder.cpp:400-426,534-544` — final XDR clusters are bins that may also pack independent logical clusters, so an `applyThread` cluster is not a proof that every read-only key is common or immutable for the whole cluster.
- `src/simulation/ApplyLoad.cpp:2672-2678,3382-3505` — the soroswap generator does create one pair per configured dependent cluster and round-robins swaps, with common read-only router/SAC/code keys and pair-specific read-write keys.

### Why It Failed

This is a real micro-inefficiency, but it does not clear the optimize-soroswap review threshold. The hypothesis's cited `read xdr with budget` cost is roughly 36 ms over a trace whose `applySorobanStages` wall total is 1793 ms, which is about 2% before accounting for incomplete eliminability, per-tx metering preservation, map insertion work that remains, and any added cache lookup/ownership overhead. The proposed mechanism is also too broad: a cached RO entry may be stale if any transaction in the same sequential cluster writes that key, because RO/RW overlap is exactly what causes clustering.

### Lesson Learned

In parallel apply, an `ApplyStage` cluster is a scheduling unit, not an immutability boundary. A safe shared-entry cache would need to restrict itself to live Soroban keys absent from the union of all read-write footprints in the cluster, avoid archived/restored paths, and preserve per-tx XDR decode budget charges; even then, the projected soroswap apply-time win appears below the Medium objective floor.
