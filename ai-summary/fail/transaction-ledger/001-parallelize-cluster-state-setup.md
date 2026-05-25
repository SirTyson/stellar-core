# H001: Parallelize per-cluster ThreadParallelApplyLedgerState construction

**Date**: 2025-05-25
**Subsystem**: transaction-ledger (parallel apply orchestration)
**Severity**: Medium
**Impact**: Apply-time reduction on Soroban-heavy workloads (soroswap)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `applySorobanStageClustersInParallel` dispatches `NUM_CLUSTERS` worker
threads (8 in the bench config), the per-thread setup work (collecting each
cluster's footprint entries from the global state, reserving the thread map,
computing TTL keys via SHA-256) should run **in parallel** alongside the rest
of each worker thread's apply work. The main thread should do constant-time
dispatch work per cluster (move the cluster reference into the lambda) and
then immediately block on the futures. The wall-clock critical path of the
stage should be `max(per-cluster setup_i + per-cluster apply_i)` over the 8
workers, divided across worker threads.

## Mechanism

`applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2545-2554`) iterates the stage's clusters
serially on the main thread and, for each one, **first constructs** a
`ThreadParallelApplyLedgerState` (which immediately calls
`collectClusterFootprintEntriesFromGlobal` —
`ParallelApplyUtils.cpp:925-986`) and **then** spawns the worker via
`std::async`. The constructor walks every TX in the cluster, every footprint
key, and for each Soroban key computes `getTTLKey(key)` — which performs an
XDR-serialize + SHA-256 (`LedgerTypeUtils.cpp:30-38`) and a global-map
lookup. This setup is purely serial on the main thread: the second cluster's
setup cannot begin until the first cluster's setup completes and the
`std::async` call returns, and the eighth cluster's worker doesn't even
start its apply until all seven prior setups have finished.

For the soroswap stage (122 Soroban TXs / 8 clusters ≈ 15 TXs/cluster, each
with ~6–10 footprint keys, each requiring a TTL-key SHA-256 + map lookup),
the per-cluster setup is estimated at ~0.6–1.0 ms. Serialized across 8
clusters this is **4–8 ms per ledger of pure main-thread serial work**, on
top of which workers' apply work also starts late. Moving the construction
**inside** the worker lambda (and relaxing the
`releaseAssert(threadIsMain() || app.threadIsType(APPLY))` at
`ParallelApplyUtils.cpp:929-930` to also accept `std::async` worker threads,
or registering those threads appropriately) collapses 8× sequential setups
to a single max() worker setup time and overlaps the remaining setup with
apply.

This is a critical-path saving (not aggregate worker self-time), so it
counts directly against the bench `total-apply` metric.

## Trigger

Run the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py`)
on the current `soroswap-perf` branch. The serial setup loop runs on the
main thread before each parallel-Soroban stage. Per-ledger, soroswap has
one Soroban stage with `NUM_CLUSTERS = 8`; the savings repeat every ledger.

To validate impact precisely, instrument `applySorobanStageClustersInParallel`
with two timers: (a) total time from entry to first
`threadFutures[i].get()` returning, (b) main-thread time spent in the
construction loop (lines 2545-2554). Baseline (b) should be ~5 ms per
ledger on soroswap.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2531-2575` —
  `applySorobanStageClustersInParallel`. Move the
  `std::make_unique<ThreadParallelApplyLedgerState>(...)` call inside the
  lambda body passed to `std::async`. Keep the `DeactivateScopeGuard` on
  the main thread.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` —
  `ThreadParallelApplyLedgerState` constructor. No code change needed if
  invocation moves into the worker lambda; verify that read-only access to
  `global.getGlobalEntryMap()`, `global.getRestoredEntries()`, and the
  `LedgerEntryScope`/`scopeAdoptEntryOptFrom` machinery is safe under
  concurrent read from multiple worker threads (the global state is
  frozen for the duration of the stage, so reads should be safe but
  scope-bookkeeping side effects must be audited).
- `src/transactions/ParallelApplyUtils.cpp:925-930` — relax the
  thread-type assertion or register `std::async` workers as `APPLY` type
  via `app.markThreadAsApply(...)` (verify whether such a registration
  helper exists; if not, the assertion needs widening).
- `src/transactions/ParallelApplyUtils.cpp:431-525` —
  `preParallelApplyAndCollectModifiedClassicEntries` already runs setup
  work in parallel via a worker pool (`readOnlyPreParallelApply` at
  line 526); reuse the same pattern here.

## Evidence

1. The construction loop is provably serial: line 2548 (the unique_ptr
   ctor running `collectClusterFootprintEntriesFromGlobal`) is a
   synchronous expression that completes before line 2550's `std::async`
   call dispatches the worker. Loop iteration i+1 cannot begin until the
   previous iteration's entire body has completed.

2. The constructor's dominant cost is real:
   `collectClusterFootprintEntriesFromGlobal` iterates every TX × every
   footprint key × (key itself + getTTLKey). `getTTLKey`
   (`LedgerTypeUtils.cpp:30-38`) performs `xdr::xdr_to_opaque` followed by
   `sha256` — neither is cheap (each ~1–3 µs). Even though
   `004-parallel-apply-ledgerkey-hash-recompute` in success/ caches keys
   inside `ParallelApplyLedgerKey`, the TTL-derived key in
   `collectClusterFootprintEntriesFromGlobal` line 980-981 is computed
   fresh per call.

3. The existing parallel-pool pattern at
   `preParallelApplyAndCollectModifiedClassicEntries` /
   `readOnlyPreParallelApply` (`ParallelApplyUtils.cpp:526`) demonstrates
   that this codebase already runs setup-style work concurrently across
   worker threads, so the infrastructure (thread registration, scope
   handling) exists.

4. The applySorobanStageClustersInParallel zone in the latest soroswap
   trace
   (`/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`)
   has non-trivial main-thread self-time before the
   `future.get()` loop; that self-time IS the serial setup loop. Per the
   meta-patterns, only critical-path savings count — and this work is
   strictly on the critical path.

## Anti-Evidence

1. `LedgerEntryScope` and `scopeAdoptEntryOptFrom` may carry hidden
   mutable bookkeeping in `global`'s scope. If `scopeAdoptEntryOptFrom`
   atomically mutates a counter or list inside `global`, concurrent
   construction from 8 threads is unsafe and would require either
   mutex-guarding the global side or refactoring the scope adoption to a
   thread-local stage. This is the primary risk and must be audited
   before the change can land.

2. The thread-type assertion at `ParallelApplyUtils.cpp:929-930` is
   defensive; widening it may inadvertently allow other unsafe call sites.
   The fix should mark `std::async` workers as `APPLY` type explicitly
   (mirroring how `readOnlyPreParallelApply` already handles its workers)
   rather than removing the assertion outright.

3. Estimated savings are ~4–8 ms / ledger on a ~62.5 ms `applyLedger`
   window per ledger (Tracy normalization) or ~207 ms `total-apply`
   (bench normalization). That puts impact in the 2–4% range —
   **borderline Medium**. If measurement shows <3% it must be moved to
   fail/. Run the bench at least 3× before/after to confirm the delta
   exceeds noise.

4. Fail entry `H023` notes
   `commitChangesFromThreads ordering constraint blocks parallel folding`,
   which is the inverse problem (parallelizing the post-stage merge).
   That doesn't apply here — this is parallelizing the **pre-stage
   setup**, which has no ordering dependency between clusters because the
   global state is frozen during the stage.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `051-parallelize-per-cluster-thread-state-setup-into-worker`
**Failed At**: reviewer

### Trace Summary

The current code still constructs each `ThreadParallelApplyLedgerState` synchronously in `LedgerManagerImpl::applySorobanStageClustersInParallel` before launching the corresponding `std::async` worker. That constructor calls `collectClusterFootprintEntriesFromGlobal`, which reserves the per-thread map, walks every transaction footprint in the cluster, computes `getTTLKey` for Soroban keys, and probes the immutable global entry map before `applyThread` begins executing transaction work. This is the same mechanism already recorded in the transaction-ledger failure summary as `051-parallelize-per-cluster-thread-state-setup-into-worker`, where direct sizing found the serial pre-launch staircase below the objective threshold.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2531-2575` — `applySorobanStageClustersInParallel` performs serial per-cluster `ThreadParallelApplyLedgerState` construction before each `std::async` launch, then waits for all futures.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` consumes the already-built thread state, applies the cluster transactions sequentially, and returns the state for later merging.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState` construction copies prior restored entries and runs `collectClusterFootprintEntriesFromGlobal`; the collector reserves by footprint size, probes `global.getGlobalEntryMap()`, and computes TTL keys with `getTTLKey` for each Soroban footprint key.
- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey const&)` builds a TTL key by XDR-serializing the ledger key and hashing it with SHA-256.
- `src/ledger/LedgerEntryScope.cpp:489-520` — `scopeAdoptEntryOptFromImpl` copies or moves the optional entry after checking that the source scope is inactive; it does not mutate the global map, but the global scope is protected by `DeactivateScopeGuard` during the stage.
- `src/main/ApplicationImpl.cpp:1301-1305` and `src/main/ApplicationImpl.h:240-243` — `threadIsType` requires the current thread to be present in the constructor-populated `mThreadTypes` map, so anonymous `std::async` workers are not currently registerable through an existing helper.

### Why It Failed

This hypothesis is a duplicate of the already-investigated `051-parallelize-per-cluster-thread-state-setup-into-worker` failure summary entry. The claimed serial setup path exists, but the prior investigation directly sized the same constructor work — unordered-map reserve, footprint/global-map probes, TTL-key construction, and scoped-entry copying — as well under 1 ms per cluster and sub-millisecond recoverable critical-path time per ledger after moving it into workers. Under the optimize-soroswap objective, Low and sub-Low findings are rejected, and the previous entry specifically records that this mechanism cannot reach the 3% Medium floor.

The trace also confirms one correction to the current hypothesis: there is no `app.markThreadAsApply(...)` helper to reuse. `ApplicationImpl::mThreadTypes` is intentionally populated only during construction, and `threadIsType` asserts that the calling thread is already registered. A PoC would therefore have to either broaden the assertion in `collectClusterFootprintEntriesFromGlobal` or introduce a larger thread-registration redesign, increasing implementation risk without changing the sub-threshold performance ceiling already recorded for this exact mechanism.

### Lesson Learned

For per-cluster setup hypotheses, do not infer Medium impact from the total `applySorobanStageClustersInParallel` zone because it includes worker execution and `future.get()` wait time. Size the constructor body itself; for soroswap, the serial `ThreadParallelApplyLedgerState` setup loop is bounded by a few thousand footprint/TTL probes and is already captured as a sub-threshold duplicate in the failure summary.
