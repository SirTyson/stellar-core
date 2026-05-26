# H001: Single-Stage Soroswap Direct Thread-State LedgerTxn Commit

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing the global-map merge/writeback tail for one-stage Soroban ledgers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Soroban ledger whose parallel phase has exactly one apply stage, worker-thread results should still be committed in deterministic stage/cluster order and produce the identical `LedgerTxn` state, restored-entry records, transaction results, metadata, and bucket output. Because there are no prior stages in this case, the apply path should not need to first merge all dirty thread entries into `mGlobalEntryMap` and then scan that same global map again to write dirty entries into the parent `LedgerTxn`.

## Mechanism

The current apply path always uses the general multi-stage flow: `GlobalParallelApplyLedgerState::commitChangesFromThreads` copies each dirty thread entry into `mGlobalEntryMap`, and `GlobalParallelApplyLedgerState::commitChangesToLedgerTxn` later scans the global map and writes dirty entries into an inner `LedgerTxn`. For the headline soroswap workload, the configured setup is 8 pairs for 8 clusters and the phase timing shows one-stage-shaped behavior, so the extra global merge layer is plausibly pure overhead. A single-stage fast path can write each `ThreadParallelApplyLedgerState`'s dirty entries directly to the inner `LedgerTxn` in canonical cluster order, while applying the existing RO TTL max merge before each write, avoiding the previous final-stage-direct-commit blocker where earlier stages had to be written before final-stage overrides.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark from `ai-summary/CURRENT_STATE.md`. The diagnostic log reports the relevant serial tail:

- `commit_from_thrds` median 7.64 ms per ledger
- `commit_to_ltx` median 4.29 ms per ledger
- current soroswap median close time about 207.6 ms

Then implement a gated prototype that only activates when `applyStages.size() == 1`, no hot-archive/live restores require cross-stage reconciliation, and all dirty entries can be emitted in deterministic cluster order. Compare three non-Tracy soroswap runs against the current baseline.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2672-2710` — `applySorobanStages` always commits stage results through `globalParState.commitChangesToLedgerTxn(ltx)`.
- `src/transactions/ParallelApplyUtils.cpp:893-922` — `commitChangesFromThreads` serially merges every thread state into `mGlobalEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `commitChangesToLedgerTxn` scans `mGlobalEntryMap` and writes dirty entries through an inner `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:821-890` — `maybeMergeRoTTLBumps` and `commitChangeFromThread` contain the TTL-max and `mIsNew` rules that the direct path must preserve.

## Evidence

This is a refinement of the previously rejected final-stage direct-commit surface, not the same hypothesis: the retained blocker in `001-final-stage-dirty-direct-ledgertxn-commit` was multi-stage correctness (`DELETED+LIVE` / `DELETED+INIT` merge semantics and prior-stage dirty entries that must be written before final-stage overrides). The proposed trigger explicitly avoids that blocker by activating only for one-stage soroswap ledgers, where there are no prior-stage dirty entries. The phase timing puts `commit_from_thrds + commit_to_ltx` at about 11.9 ms/ledger, comfortably above the 3% Medium floor if a substantial fraction of the double pass is removed.

## Anti-Evidence

`mGlobalEntryMap` is also the place where read-only TTL bumps from different clusters are max-merged and where restored-entry bookkeeping is accumulated. A correct prototype must prove that direct writes preserve the same TTL max result and the same restored-entry invariant inputs. If soroswap occasionally has multiple stages, or if the single-stage direct path still needs to materialize most of `mGlobalEntryMap` to resolve TTL/restored-entry ordering, the remaining saving may fall below Medium.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in the one-stage-only form

### Trace Summary

The close-ledger path is `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> one or more `applySorobanStage` calls, followed by a final `commitChangesToLedgerTxn`. The apply-load model benchmark explicitly asserts that the measured model ledger has exactly one Soroban stage and the configured maximum cluster count, so the prior multi-stage direct-commit blocker is absent for this workload. In the current implementation, even that one-stage case still first moves dirty entries from every `ThreadParallelApplyLedgerState` into `mGlobalEntryMap`, then scans the global map to write dirty entries into an inner `LedgerTxn`. The diagnostic phase log for the current baseline confirms this serial tail is hot enough to matter: median 7.64 ms in `commit_from_thrds` plus 4.29 ms in `commit_to_ltx` against a 207.6 ms soroswap median.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` builds parallel phases, `applyParallelPhase` converts tx-set stages to `ApplyStage`s, and calls `applySorobanStages` inside the measured close path.
- `src/simulation/ApplyLoad.cpp:2280-2334` — the model benchmark resolves bucket futures before timing and asserts `stagesMetric.count() == 1` with max clusters after the soroswap close.
- `src/ledger/LedgerManagerImpl.cpp:2530-2670` — each stage constructs thread states, applies clusters in async workers, checks invariants, merges thread state into global state, and destroys thread states.
- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` creates one `GlobalParallelApplyLedgerState`, applies all stages sequentially, then always calls `globalParState.commitChangesToLedgerTxn(ltx)`.
- `src/transactions/ParallelApplyUtils.cpp:386-428,600-718` — global setup preloads modified classic keys and Soroban read-only entries into `mGlobalEntryMap`, mostly as clean entries.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `commitChangesToLedgerTxn` scans `mGlobalEntryMap`, skips clean entries, writes dirty live/init entries with `updateWithoutLoading` or `createWithoutLoading`, handles deletes, marks restores, then commits the inner `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:821-922` — `commitChangesFromThreads` builds the stage read-write key set, walks each thread map, rescopes dirty entries into global state, max-merges read-only TTL bumps, preserves first-touch `mIsNew`, and accumulates restored entries.
- `src/transactions/ParallelApplyUtils.cpp:924-1252` — thread state preloads global entries, buffers read-only TTL bumps, collapses each cluster's sequential transactions into final dirty thread entries, and records per-thread restores.
- `src/ledger/LedgerTxn.cpp:760-865,2460-2533` — `createWithoutLoading`/`updateWithoutLoading` merge entries into an inner `LedgerTxn`; repeated live updates are valid, while the prior final-stage blocker came from deleted-entry state-machine cases that arise when earlier-stage state must be overwritten.

### Findings

The inefficiency exists on the described hot path. For one-stage soroswap ledgers, dirty thread entries are currently materialized in two serial containers before reaching the parent ledger transaction: thread map -> global map -> inner `LedgerTxn`. Because same-stage clusters are non-conflicting except for commutative read-only TTL bumps, non-TTL dirty keys can be emitted once from thread state in deterministic cluster order without needing global last-write-wins reconciliation.

The proposed fix is correctness-plausible if it is narrowly gated and preserves the two special global-merge semantics. First, read-only TTL entries duplicated across clusters must be max-merged, not last-writer-wins; a direct path should either precompute the max for duplicate RO TTL dirty entries or maintain a small TTL-max map while emitting writes. Second, restored-entry records must still be marked in the inner `LedgerTxn` exactly once with corresponding TTL entries; for the soroswap benchmark this is likely empty, but the fast path should either support the existing disjoint restored-entry invariant or gate off when restores are present.

The Medium projection is credible for review. The current measured serial tail is about 11.9 ms/ledger. The direct path cannot remove the actual `LedgerTxn` writes, but it can remove most of the 7.64 ms thread-to-global merge pass while still reusing the existing `LedgerTxn` write semantics. Recovering roughly 6.3 ms on a 207.6 ms baseline clears the 3% objective floor; the measured `commit_from_thrds` phase alone is large enough that a substantial reduction is worth a PoC.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.cpp::applySorobanStages` and `src/transactions/ParallelApplyUtils.{h,cpp}` around `GlobalParallelApplyLedgerState::commitChangesFromThreads`, `commitChangeFromThread`, `maybeMergeRoTTLBumps`, and `commitChangesToLedgerTxn`.
- **Change description**: Add a one-stage-only direct commit path after `applySorobanStage` returns thread states. When `stages.size() == 1`, write dirty entries from each `ThreadParallelApplyLedgerState` directly into one inner `LedgerTxn` in cluster order, preserving `mIsNew` for create/update selection and using the existing load+erase behavior for deletes. Preserve RO TTL max semantics with a small duplicate-TTL merge mechanism, and either correctly mark per-thread restored entries or disable the fast path when any restore map is non-empty.
- **Correctness check**: Existing parallel Soroban apply tests and full `make check` should cover ledger effects, meta, restored-entry invariants, and deterministic apply. Add narrow unit coverage only if the new direct path has branches not exercised by existing one-stage apply tests, especially duplicate RO TTL max-merge and create/delete/recreate state transitions.
- **Benchmark focus**: Use the current `ai-summary/CURRENT_STATE.md` non-Tracy soroswap baseline and run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times. The expected metric is lower top-line soroswap median apply time, with diagnostic phase timing showing `commit_from_thrds` mostly eliminated or replaced by a smaller direct-commit phase while `commit_to_ltx` does not regress enough to erase the gain.
