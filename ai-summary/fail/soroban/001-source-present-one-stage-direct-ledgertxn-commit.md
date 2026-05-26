# H001: Source-Present One-Stage Direct LedgerTxn Commit

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing the one-stage thread-state -> global-map -> LedgerTxn copy chain
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Soroban ledger with exactly one parallel apply stage, worker results should be committed to `LedgerTxn` in deterministic cluster order without first materializing every dirty worker entry in `GlobalParallelApplyLedgerState::mGlobalEntryMap`. The ledger entries, restored-entry bookkeeping, RO TTL max-merge result, transaction results, metadata, and bucket input order should match the existing path exactly.

## Mechanism

`LedgerManagerImpl::applySorobanStages` currently applies every stage through `applySorobanStage`, which always calls `commitChangesFromThreads`, and then always drains `mGlobalEntryMap` through `commitChangesToLedgerTxn`. In the soroswap apply-load shape the model ledger is one stage with bounded cluster parallelism, so there is no later stage that needs the global map as an inter-stage visibility layer. A source-present fast path can run the existing worker futures, then write dirty thread entries directly into one inner `LedgerTxn` in cluster order while using a small deterministic RO-TTL max map and the existing restored-entry marking logic.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark. The trigger is any ledger whose Soroban phase contains exactly one `ApplyStage`; in that case, after `applySorobanStageClustersInParallel` joins all workers, direct commit should bypass `GlobalParallelApplyLedgerState::commitChangesFromThreads` and the final dirty scan of `commitChangesToLedgerTxn`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` already returns thread states in deterministic cluster-vector order after all bounded worker futures complete.
- `src/ledger/LedgerManagerImpl.cpp:2672-2710` — `applySorobanStages` always takes the multi-stage global-map path and then calls `commitChangesToLedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `commitChangesToLedgerTxn` scans `mGlobalEntryMap` and writes dirty entries to an inner `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:821-922` — `maybeMergeRoTTLBumps`, `commitChangeFromThread`, and `commitChangesFromThreads` encode the RO TTL and `mIsNew` semantics the direct path must preserve.

## Evidence

The current Tracy trace confirms this is inside `applyLedger`: `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` has 2.660882058s self-time across 43 apply-contained stage calls, and unwrap containment shows `commitChangesFromThreads` and `commitChangesToLedgerTxn` events occur wholly inside `applyLedger`. Source inspection shows the same one-stage case still pays two serial container transitions after worker execution: thread maps are rescoped into `mGlobalEntryMap`, then dirty global entries are moved into a child `LedgerTxn`.

This hypothesis is specifically source-present: the PoC must add and benchmark the direct commit API in the checked-out source, not just describe it. The determinism argument is that same-stage clusters are read-write disjoint by construction, the main thread emits writes in canonical cluster order, and RO TTL bumps are commutative `max` reductions handled before final writes.

## Anti-Evidence

The global map also carries required semantics: RO TTL max-merge, first-touch `mIsNew`, restored-entry invariant inputs, and delete handling through `load()+erase()`. If the direct path has to reconstruct most of `mGlobalEntryMap` to preserve these semantics, or if the benchmark ledger is not consistently one-stage, the recoverable work may fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/001-single-stage-direct-thread-ledgertxn-commit.md`
**Failed At**: reviewer

### Trace Summary

The traced close-ledger path still matches the hypothesis mechanism: `applySorobanStages` creates a `GlobalParallelApplyLedgerState`, `applySorobanStage` launches one thread state per cluster with `applySorobanStageClustersInParallel`, then serially calls `commitChangesFromThreads`; after all stages, `commitChangesToLedgerTxn` drains dirty global entries into an inner `LedgerTxn`. The soroswap model benchmark also still asserts the relevant one-stage/max-cluster shape after timing the close. However this exact single-stage direct thread-state-to-`LedgerTxn` optimization was already reviewed in `001-single-stage-direct-thread-ledgertxn-commit.md`, including the same target functions, same RO TTL max-merge and restored-entry constraints, same deterministic cluster-order argument, and same Medium projection from eliminating the thread-map -> global-map -> `LedgerTxn` copy chain.

### Code Paths Examined

- `ai-summary/fail/soroban/001-single-stage-direct-thread-ledgertxn-commit.md:1-80` — prior reviewed hypothesis covers the same one-stage-only direct commit mechanism, same `commit_from_thrds + commit_to_ltx` timing basis, same `mGlobalEntryMap` bypass, and same PoC guidance for preserving RO TTL and restored-entry semantics.
- `ai-summary/fail/soroban/002-one-stage-global-state-bypass.md:43-76` — prior duplicate ruling explicitly identifies the direct-commit portion as duplicating `001-single-stage-direct-thread-ledgertxn-commit.md`.
- `src/simulation/ApplyLoad.cpp:2301-2334` — the model benchmark resolves bucket futures before timing, closes the ledger, and asserts exactly one Soroban stage with the configured max cluster count.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` builds thread states in stage cluster order, runs worker futures, joins them, and returns completed thread states in deterministic vector order.
- `src/ledger/LedgerManagerImpl.cpp:2622-2724` — `applySorobanStage` always commits worker results through `globalParState.commitChangesFromThreads`; `applySorobanStages` then always calls `globalParState.commitChangesToLedgerTxn(ltx)`.
- `src/transactions/ParallelApplyUtils.h:183-273` — `GlobalParallelApplyLedgerState` owns `mGlobalEntryMap` and exposes only the existing merge-to-global and commit-to-`LedgerTxn` APIs.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `commitChangesToLedgerTxn` scans `mGlobalEntryMap`, skips clean entries, writes dirty live/init entries to an inner `LedgerTxn`, handles deletes via `load()+erase()`, and marks restored entries.
- `src/transactions/ParallelApplyUtils.cpp:821-922` — `maybeMergeRoTTLBumps`, `commitChangeFromThread`, and `commitChangesFromThreads` implement the same RO TTL max-merge, first-touch `mIsNew`, rescope, and restored-entry merge semantics called out by both hypotheses.

### Why It Failed

This is not a novel reviewer-stage finding. It is substantially equivalent to `ai-summary/fail/soroban/001-single-stage-direct-thread-ledgertxn-commit.md`: both target the single-stage soroswap shape, bypass `commitChangesFromThreads` plus the final `mGlobalEntryMap` dirty scan, write thread-state changes directly to an inner `LedgerTxn` in deterministic cluster order, and require the same special handling for RO TTL max-merge, restored entries, `mIsNew`, and delete semantics. The "source-present" wording does not create a new mechanism; it restates the earlier PoC requirement that the direct commit API be implemented in the checked-out source.

### Lesson Learned

Do not re-promote the one-stage direct thread-state-to-`LedgerTxn` design as a fresh reviewer hypothesis unless the new file contains a materially different mechanism or new benchmark evidence that changes the prior duplicate/final-review outcome. The correct next step for this idea is a source-present implementation and PoC under the existing reviewed hypothesis, not another reviewer-stage duplicate.
