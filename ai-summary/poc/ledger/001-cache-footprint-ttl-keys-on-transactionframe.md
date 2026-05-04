# H001: Cache footprint TTL keys on `TransactionFrame` to eliminate aggregate per-call-site SHA256 work

**Date**: 2026-05-04
**Subsystem**: ledger / Soroban parallel apply setup + InvokeHostFunction apply path
**Severity**: Medium
**Impact**: 3–5% apply-time reduction by eliminating redundant `getTTLKey()` (XDR-encode + SHA256) calls across 11 distinct call sites in the in-scope apply path, including the previously-unaddressed serial cluster-setup walk that blocks parallel apply launch.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A Soroban transaction's footprint TTL keys are a pure function of its
footprint, which is fixed once the envelope is parsed. The TTL key for any
footprint entry should be computed at most **once per transaction per
ledger**, then reused by every consumer that needs it during apply. The
expected design is: each `TransactionFrame` (or `TxBundle`) carries a
small parallel array of pre-computed TTL `LedgerKey`s, indexed positionally
against `sorobanResources().footprint.{readOnly,readWrite}`, populated
lazily on first access (or eagerly during `applyParallelPhase` bundle
construction at `LedgerManagerImpl.cpp:2982-3020`). All in-apply consumers
should read from that cache rather than recompute via
`getTTLKey()`.

## Mechanism

`getTTLKey(LedgerKey)` (`src/ledger/LedgerTypeUtils.cpp:31-38`) performs
`xdr_to_opaque(e)` followed by `SHA256(...)`. Each call costs ~1.4 µs
(matches the trace's mean per-`sha256` call). The current code recomputes
this value at **eleven** distinct in-apply call sites for the *same*
footprint keys, every ledger, every transaction:

1. `ParallelApplyUtils.cpp:127` — `collectAllReadWriteTTLKeys`
2. `ParallelApplyUtils.cpp:249` — `collectAllReadOnlyTTLKeys`
3. `ParallelApplyUtils.cpp:691` — `fetchSorobanReadOnlyEntries from footprints`
   (apply thread, pre-parallel)
4. `ParallelApplyUtils.cpp:781` — restore-marker loop in
   `commitChangesToLedgerTxn` (hot archive)
5. `ParallelApplyUtils.cpp:794` — same loop, live BucketList branch
6. `ParallelApplyUtils.cpp:980` — `collectClusterFootprintEntriesFromGlobal`
   (apply-thread, **serial blocker before each `std::async` cluster launch**;
   re-runs per cluster so the same key is hashed N-clusters times)
7. `ParallelApplyUtils.cpp:1017` — `flushRoTTLBumpsInTxWriteFootprint`
   (worker-thread per RW Soroban key per tx)
8. `InvokeHostFunctionOpFrame.cpp:406` — `addReads` for every RO/RW Soroban
   key per Soroban tx (worker thread)
9. `InvokeHostFunctionOpFrame.cpp:685` — inner per-output loop in
   `recordStorageChanges` (O(out × rwKeys) re-hashes)
10. `InvokeHostFunctionOpFrame.cpp:761` — TTL bump path
11. `InvokeHostFunctionOpFrame.cpp:1159` — restore handler

Prior single-site rejections (`fail/011-cache-ttl-key-hash-on-globalparapply-ro-entries.md`
and `fail/012-hoist-getttlkey-from-recordstoragechanges-inner-loop.md`)
correctly observed that *each individual site* is sub-Medium. This
hypothesis is structurally different: a single positional cache on
`TransactionFrame` collapses **all eleven sites at once**, including the
cluster-setup site (#6), which is uniquely on the **serial apply-thread
critical path** before parallel cluster workers launch — eliminating it
not only saves CPU but reduces the time before futures dispatch, which
shortens the parallel apply wall-clock window (`applySorobanStageClustersInParallel`
self-time ≈ 33.5% of trace is dominated by the wait for the slowest
worker, which is gated on dispatch latency).

The diagnostic trace shows aggregate `sha256` (`crypto/SHA.cpp:33`) self
time of 647 ms (6.29% of trace), of which a meaningful fraction is the
TTL-key SHA256 work fired across these eleven sites; eliminating that
fraction plus removing the serial XDR-encode work in the cluster-setup
critical path is targeted at the 3–5% apply-time tier.

## Trigger

Reproduce with the standard soroswap apply-load run:

```sh
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
```

The benchmark generates 2000 swap-style Soroban transactions per ledger,
each with multiple Soroban footprint entries (token contract instance,
WASM, pair-state). Every footprint key is hashed for its TTL key 8+ times
per ledger across the eleven call sites listed above; the cache eliminates
all but the first computation per (tx, footprint-position) pair.

Verify the per-site count by adding a counting `ZoneScopedN` around each
`getTTLKey(...)` call and re-running with `--tracy`; the unwrap-mode
export will show repeated calls for the same key signature within a
single `applyLedger` window.

## Target Code

- `src/transactions/TransactionFrame.h` / `TransactionFrame.cpp` —
  add `mutable std::optional<std::vector<LedgerKey>> mFootprintReadOnlyTTLKeys;`
  and `...mFootprintReadWriteTTLKeys;`, populated lazily by a new
  `getFootprintTTLKeys(bool readWrite, size_t index) const` helper.
- `src/transactions/TransactionFrameBase.h:341-342` — extend the abstract
  interface with a `getFootprintTTLKey(bool readWrite, size_t index)` accessor
  so non-Soroban `TransactionFrame` implementations can `releaseAssertOrThrow`.
- `src/transactions/ParallelApplyUtils.cpp:127, 249, 691, 781, 794, 980, 1017`
  — replace direct `getTTLKey(...)` calls with `tx.getFootprintTTLKey(...)`
  where the originating tx is in scope (most sites are inside per-tx loops;
  the restore-marker loop at 781/794 will need a fallback because the keys
  there are restored entries not directly tied to a tx — see Anti-Evidence).
- `src/transactions/InvokeHostFunctionOpFrame.cpp:406, 685, 761, 1159` —
  replace with the cache via `mOpFrame.mParentTx.getFootprintTTLKey(...)`.
- `src/ledger/LedgerManagerImpl.cpp:2982-3020` — optionally pre-warm the
  cache during `TxBundle` construction so all later access is a vector
  read with no synchronization.

## Evidence

- Trace data: `sha256` self time = 647,849,613 ns (6.29% of trace, 451,808
  calls). The mean SHA256 cost (1.4 µs) matches the hot per-call cost of
  `getTTLKey`.
- Trace data: `applySorobanStageClustersInParallel` self time = 3,455 ms
  (33.5% of trace) is dominated by future-wait; the construction of
  `ThreadParallelApplyLedgerState` (which calls `collectClusterFootprintEntriesFromGlobal`
  → `getTTLKey` per Soroban footprint key per tx in cluster) runs serially
  on the apply thread before each `std::async` launch
  (`LedgerManagerImpl.cpp:2548-2553`), so reducing its cost shortens the
  parallel apply window directly.
- Trace data: `addReads` self = 196 ms (1.91%), `recordStorageChanges` self
  = 55 ms (0.54%); these are upper bounds on the per-tx Soroban-key
  hashing each consumer pays. Cluster-setup pays the same `getTTLKey` cost
  per cluster (8+ times per ledger for the same key), making the cluster
  site likely the largest single TTL-hash consumer that has not been
  individually addressed.
- Code structure: `TransactionFrame::sorobanResources()` returns a `const&`
  to the pre-decoded resources, so the footprint vector is stable for the
  lifetime of the frame; caching is safe with no invalidation needed.
- Memory: stored memory `parallel apply: applySorobanStageClustersInParallel
  constructs each ThreadParallelApplyLedgerState before std::async launch,
  so per-cluster state setup stays on the stage critical path` confirms the
  cluster-setup site is on the critical path.

## Anti-Evidence

- Two prior single-site attempts (`fail/011`, `fail/012`) were rejected as
  sub-Medium. The aggregate-cache angle differs by collapsing 11 sites
  *plus* the on-critical-path cluster-setup site that neither prior
  hypothesis covered. If the aggregate still falls below 3% in the
  realized PoC, the optimization should be downgraded.
- The restore-marker loop at `ParallelApplyUtils.cpp:781,794` operates on
  `mGlobalRestoredEntries` which is keyed by the restored `LedgerKey`, not
  by tx; this site cannot trivially use a tx-positional cache. The fix is
  either (a) keep the existing `getTTLKey(kvp.first)` for restore loops
  (it is rare in soroswap, so leaving it is fine) or (b) use a
  small per-key memo populated during the worker phase.
- `getTTLKey` results are also stored in `mGlobalEntryMap` keys
  (`ParallelApplyUtils.cpp:691`); the cache must produce *bitwise-identical*
  `LedgerKey` values so map lookups continue to match. This is guaranteed
  because the cache result is a copy of the same XDR bytes hashed to form
  the TTL key; no rounding/canonicalization concerns.
- A previous structural-parallelism attempt to move cluster setup into
  worker threads regressed (`fail/cluster-state-setup-failure` /
  `001-parallelize-cluster-state-setup`). This hypothesis does **not**
  parallelize cluster setup; it only reduces serial work, so the cache
  effects that defeated that earlier attempt do not apply here.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The parallel Soroban close path builds `TxBundle`s, constructs a `GlobalParallelApplyLedgerState`, then for each stage constructs every `ThreadParallelApplyLedgerState` on the apply thread before launching that cluster's worker future. The claimed `getTTLKey` calls exist on that path: some run during global pre-apply setup, some run in the serial thread-state footprint copy before `std::async`, and others run per transaction inside `InvokeHostFunctionOpFrame` worker execution and successful-result commit. The soroswap generator uses a fixed 5 read-only / 5 read-write footprint per swap, with 8 Soroban code/data keys requiring TTL keys, so the same per-transaction footprint positions are hashed repeatedly by multiple consumers. The proposed cache is semantically safe if it is indexed by footprint position and either pre-warmed before worker launch or otherwise initialized without cross-thread lazy mutation.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2966-3030` — `applyParallelPhase` creates `TxBundle`s from the tx set's parallel stages before invoking `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2710` — `applySorobanStages` constructs the global parallel state, applies each stage, then commits global changes back to the outer `LedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2554` — `applySorobanStageClustersInParallel` constructs each `ThreadParallelApplyLedgerState` serially on the apply thread before launching the corresponding `std::async` worker.
- `src/transactions/ParallelApplyUtils.cpp:386-466` — `GlobalParallelApplyLedgerState` performs pre-parallel apply and then collects modified entries; read-only Soroban preloading later hashes TTL keys for footprint entries not already in the global map.
- `src/transactions/ParallelApplyUtils.cpp:104-132`, `src/transactions/ParallelApplyUtils.cpp:238-251`, `src/transactions/ParallelApplyUtils.cpp:646-718`, `src/transactions/ParallelApplyUtils.cpp:774-799`, `src/transactions/ParallelApplyUtils.cpp:925-1001`, `src/transactions/ParallelApplyUtils.cpp:1003-1039`, and `src/transactions/ParallelApplyUtils.cpp:1240-1251` — direct `getTTLKey` users in stage RW-set construction, RO TTL set construction, global RO preloading, restored-entry marker lookup, serial cluster footprint import, RW TTL bump flushing, and successful tx commit.
- `src/transactions/TransactionFrame.cpp:2385-2455` — worker execution calls the operation's `parallelApply` and records successful operation changes.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — invoke-host-function parallel apply delegates to `InvokeHostFunctionParallelApplyHelper::apply`, which runs `addFootprint`, host invocation, and `recordStorageChanges`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535`, `src/transactions/InvokeHostFunctionOpFrame.cpp:640-767`, and `src/transactions/InvokeHostFunctionOpFrame.cpp:1115-1188` — worker-side `getTTLKey` calls occur while loading TTL entries for RO/RW footprint keys, matching TTL output entries back to RW footprint positions, deleting associated TTL entries for removed Soroban entries, and restoring archived entries.
- `src/simulation/ApplyLoad.cpp:3382-3505` and `scripts/run_apply_load_matrix.py:417-425` — the in-scope soroswap benchmark generates 2000 swap txs with 8 configured dependent clusters and a footprint with 5 read-only entries plus 5 read-write entries, 8 of which are Soroban code/data entries that require TTL-key derivation.
- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey const&)` XDR-encodes the code/data key and hashes the bytes to construct the TTL `LedgerKey`.

### Findings

The inefficiency is real: the code currently recomputes a deterministic TTL key from stable `sorobanResources().footprint` entries at multiple call sites for the same transaction. The hottest fixed repetition is not a single local loop but the aggregate of serial cluster setup (`collectClusterFootprintEntriesFromGlobal`), worker footprint ingress (`addReads`), RW TTL bump flushing, RO TTL set construction, stage RW-set construction, and output-to-footprint matching in `recordStorageChanges`.

The path is in scope for the objective. `collectClusterFootprintEntriesFromGlobal` runs before each worker future is launched, so eliminating its per-footprint XDR+SHA256 work shortens the apply-thread dispatch path rather than only reducing background worker CPU. The worker-side sites are also descendants of `TransactionFrame::parallelApply` / `InvokeHostFunctionOpFrame::doParallelApply`, exercised by every successful soroswap swap transaction.

The proposed fix is correctness-preserving as long as the cache is keyed by the read-only/read-write footprint vector and index, not by ad-hoc ledger-key lookup. A cached value is the same `LedgerKey` that `getTTLKey` returns today; it is only reused after the transaction envelope has been decoded. The main implementation caveat is thread safety: avoid unsynchronized first-use mutation from worker threads by precomputing or pre-warming the vectors while building `TxBundle`s or before launching cluster workers.

The projected impact is plausibly Medium. The prior failures correctly rejected isolated `addReads` or `recordStorageChanges` changes, but this proposal combines those savings with serial cluster-state setup and stage/commit helpers. Given the trace's 6.29% aggregate `sha256` self time and the verified repeated TTL-key call sites across the soroswap footprint, eliminating most per-transaction TTL-key derivations has a credible 3-5% apply-time target; the PoC must confirm this with the standard multi-run matrix.

### PoC Guidance

- **Target code**: `src/transactions/TransactionFrameBase.h`, `src/transactions/TransactionFrame.h`, `src/transactions/TransactionFrame.cpp`, `src/transactions/FeeBumpTransactionFrame.*`, `src/transactions/ParallelApplyUtils.cpp`, and `src/transactions/InvokeHostFunctionOpFrame.cpp`.
- **Change description**: Add a positional TTL-key accessor for Soroban footprint entries, backed by cached RO/RW vectors on `TransactionFrame` and delegating through fee-bump wrappers where needed. Replace range loops at the call sites with indexed loops where the originating transaction is in scope. Leave the restored-entry marker loops in `commitChangesToLedgerTxn` on the direct `getTTLKey(kvp.first)` path unless a small restored-key memo is introduced; those keys are not naturally transaction-positioned and are rare for soroswap.
- **Correctness check**: Existing invoke-host-function and parallel-apply tests should cover read-only/read-write footprint loading, TTL bumping, restore/autorestore, and fee-bump Soroban behavior. If the cache is mutable, update `clearCached()` for test-mutated envelopes; preferably pre-warm during `TxBundle` construction or before cluster launch to avoid any data race from lazy initialization in worker threads.
- **Benchmark focus**: Measure top-line soroswap apply time with `scripts/run_apply_load_matrix.py` across repeated non-Tracy runs. Diagnostic Tracy should show fewer `sha256` calls, especially under serial cluster setup and invoke-host-function footprint/recording zones; promotion requires the soroswap median improvement to clear the objective's 3% Medium threshold.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-04
**PoC by**: gpt-5.5, high

### Changes Made

- `src/transactions/TransactionFrameBase.h:367-369` adds the virtual TTL-key precompute/accessor interface.
- `src/transactions/TransactionFrame.h:74-75,403-405` and `src/transactions/TransactionFrame.cpp:180-181,693-742` add cached RO/RW footprint TTL-key vectors, reset them for test-mutated envelopes, and populate/access them positionally.
- `src/transactions/FeeBumpTransactionFrame.h:193-195`, `src/transactions/FeeBumpTransactionFrame.cpp:67-76`, `src/transactions/test/TransactionTestFrame.h:197-199`, and `src/transactions/test/TransactionTestFrame.cpp:467-475` delegate the new interface through wrappers.
- `src/transactions/ParallelApplyStage.h:84-85` prewarms each bundle transaction cache during bundle construction before parallel workers can read it.
- `src/transactions/ParallelApplyUtils.cpp:119-131,242-255,698-713,982-996,1024-1034` replaces position-aware parallel-apply TTL-key derivations with cached `getFootprintTTLKey` lookups while leaving restored-entry marker loops on direct `getTTLKey` as guided.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:403-407,684-687,760-766,1162-1164` uses the transaction cache for addReads, TTL-output matching, TTL deletion, and autorestore/restore TTL updates.

### Demonstration

The change computes each Soroban footprint TTL key once per transaction when the `TxBundle` is constructed, then all later apply consumers read the cached positional `LedgerKey`. This removes repeated XDR encoding and SHA256 work from stage RW/RO set construction, global RO preloading, serial cluster footprint import before `std::async` launch, RW TTL bump flushing, and invoke-host-function footprint/result handling.

### Test Results

`./autogen.sh` and `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` completed successfully, followed by `make -j $(nproc)` successfully building `src/stellar-core`. The full regression suite `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS="--ll fatal -r simple --abort --disable-dots" make -j $(nproc) check` exited 0; a local generated `src/Makefile` git-state dependency workaround was needed in this worktree because submodule gitdirs live under the outer repository worktree metadata rather than `.git/modules`.
