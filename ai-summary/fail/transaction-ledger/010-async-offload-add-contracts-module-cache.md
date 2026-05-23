# H010: Async-Offload `addAnyContractsToModuleCache` Alongside Live Bucket Batch Write

**Date**: 2026-05-23
**Subsystem**: transaction-ledger (apply-thread serial post-apply phase)
**Severity**: Low
**Impact**: Apply-thread serial work reduction in `finalizeLedgerTxnChanges`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::finalizeLedgerTxnChanges`
(`src/ledger/LedgerManagerImpl.cpp:3217`) should run on the apply thread
only work that must be sequenced before the next ledger's setup. After
`ltx.getAllEntries(initEntries, liveEntries, deadEntries)` extracts the
final entry vectors, three independent writers operate on disjoint state:
`addHotArchiveBatch` (writes `mHotArchiveBucketList`), `updateState`
(writes `mInMemorySorobanState`), and `addAnyContractsToModuleCache`
(writes the shared module cache). Two of these are already launched as
async futures and joined before `finalizeLedgerTxnChanges` returns; the
third (`addAnyContractsToModuleCache`, called twice — once on `initEntries`
and once on `liveEntries` at lines 3354–3355) runs synchronously on the
apply thread, interleaved with the synchronous `addLiveBatch` write.

If `addAnyContractsToModuleCache` were also launched as an async future
joined together with the existing two, the apply thread would only have
to wait on the slowest of the three independent writers plus `addLiveBatch`,
shortening the synchronous post-apply serial section.

## Mechanism

`addAnyContractsToModuleCache` iterates each entry vector looking for
`CONTRACT_CODE` entries and inserts any new Wasm bytecode into the
shared `SorobanModuleCache`. The shared cache is itself synchronized
(it is already being written by the async `compile wasm contracts` /
`SharedModuleCacheCompiler` paths during steady-state), so moving the
call to a worker future is safe under the existing concurrency model.
Today the call runs serially on the apply thread between
`getAllEntries` and `addLiveBatch`, adding its self-time to the
critical path. Wrapping it in `std::async(std::launch::async, …)` and
joining alongside the existing hot-archive and in-memory-state futures
removes that serial contribution.

## Trigger

Run `apply-load --mode soroswap-tps`; observe
`finalizeLedgerTxnChanges`'s synchronous serial section in the diagnostic
Tracy trace; specifically inspect
`addAnyContractsToModuleCache` (`src/ledger/LedgerManagerImpl.cpp:3471`)
total self-time per ledger.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3354-3357` — synchronous calls to
  `addAnyContractsToModuleCache` for `initEntries` and `liveEntries`,
  followed by synchronous `addLiveBatch`.
- `src/ledger/LedgerManagerImpl.cpp:3468-` —
  `LedgerManagerImpl::ApplyState::addAnyContractsToModuleCache`
  implementation.
- `src/ledger/SharedModuleCacheCompiler.cpp` — existing background
  compilation path the cache is already prepared for concurrent writes.

## Evidence

- Diagnostic Tracy soroswap trace shows
  `addAnyContractsToModuleCache` total self-time of 1.317 ms across
  144 calls (2 per ledger × 72 ledgers), mean 9.1 us/call. Per-ledger
  serial cost ≈ 18.3 us.
- The same code path already runs `addHotArchiveBatch` and
  `updateInMemorySorobanState` as `std::async` futures and joins them
  with `future::get()` at the end of `finalizeLedgerTxnChanges`,
  demonstrating the pattern is established.

## Anti-Evidence

- Per-ledger serial savings are 18.3 us / 218 ms baseline ≈ 0.008% —
  three orders of magnitude below the objective's Low (1%) and
  Medium (3%) floors.
- For soroswap the workload deploys contracts once at setup and then
  invokes them; there are essentially zero `CONTRACT_CODE` entries
  in steady-state `initEntries`/`liveEntries`, so most of the 18.3 us
  is the vector walks themselves rather than cache insertion work.
- Adding `std::async`/`future::get` instrumentation adds task-launch
  overhead (typically 5–15 us per launch on Linux) which can exceed
  the saved sequential work for an empty-input workload.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — `addAnyContractsToModuleCache` async-offload not
previously investigated. Related but distinct from
`001-async-addlivebatch.md`/`003-defer-addlivebatch-encoding-to-background.md`
(which targeted `addLiveBatch` itself, not the module-cache hooks
around it), and from `007-shared-ptr-getallentries-fanout.md` (which
targeted entry copies into the fan-out path, not the per-callee
synchronization model). The "fan-out parallelism" angle for
`finalizeLedgerTxnChanges` was discussed in
`003-defer-hot-archive-future-across-finalize.md` (1.4 ms / ledger
lead, below threshold), but that record was specifically about
deferring the hot-archive future past `finalizeLedgerTxnChanges`'s
boundary, not about offloading the module-cache hooks.

### Why It Failed

The candidate is orders of magnitude below the objective's Medium
severity threshold and also below the Low noise floor.
`addAnyContractsToModuleCache` self-time is 18.3 us / ledger
(0.008% of the 218 ms soroswap baseline). On a workload where
`initEntries`/`liveEntries` rarely contain `CONTRACT_CODE`, the
function body is primarily two vector walks with a type discrimination
check; nothing meaningful is moved off the critical path by deferring
to a worker thread. The `std::async` launch + join overhead would
typically equal or exceed the saved sequential work. The same lesson
recorded in meta-pattern #18 of the failure summary ("All Prefetch
Phases Collectively Bounded Under ~3 ms/Ledger") applies symmetrically
to `finalizeLedgerTxnChanges` sub-callees that are already sub-ms:
async offload of microsecond-scale serial calls is not a viable
soroswap optimization.

### Lesson Learned

When a function is already invoked twice in sequence (initEntries
+ liveEntries) immediately before a heavier synchronous writer
(`addLiveBatch`), it can superficially look like a candidate for the
existing async fan-out next to it. Always size the function's
per-ledger self-time before proposing offload: if it is in the
single-digit microsecond range, `std::async` launch overhead alone
(5–15 us) will negate the saving, and the proposal cannot reach any
of the objective's severity thresholds. Add async offload only when
the deferred callee's per-ledger self-time meaningfully exceeds the
task-launch + future-join overhead.
