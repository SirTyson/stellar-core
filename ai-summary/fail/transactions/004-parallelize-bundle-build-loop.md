# H004: Move the serial TxBundle/TxEffects/MetaBuilder construction loop in `applyParallelPhase` onto cluster worker threads

**Date**: 2026-05-26
**Subsystem**: transactions
**Severity**: Low
**Impact**: serial-phase shortening (sub-noise)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `LedgerManagerImpl::applyParallelPhase` (`src/ledger/LedgerManagerImpl.cpp:2967`), the bundle-build loop constructs, **serially on the main thread**, one `TxBundle` per transaction in the stage. Each bundle construction includes constructing a `TransactionMetaBuilder` (`src/transactions/TransactionMeta.cpp:924`), which in turn constructs N `OperationMetaBuilder` instances (one per op; ~1 for soroswap) and per-op `OpEventManager` instances. The loop also calls `getTxEventManager().newFeeEvent(...)` per tx for fee-event emission.

The expected optimal behavior is to defer bundle construction (or at least the meta-builder portion of it) into the parallel worker phase, where each `applyThread` would construct its cluster's bundles concurrently with peer clusters. With T=8 clusters and ~2000 txs/ledger (~250 txs/cluster), the worker-amortized cost would be ~8× lower on the critical path than the current fully-serial construction.

## Mechanism

The bundle-build loop is in `applyParallelPhase`'s serial section before `applySorobanStages` dispatches workers. Every per-tx construction in this loop adds to the critical path serially. Even if each `TxBundle` + `TransactionMetaBuilder` + `OperationMetaBuilder` + `OpEventManager` construction is microsecond-scale, multiplying by 2000 txs yields aggregate serial time. The deviation from optimal is that this work is sequential when it could be parallelized across the existing cluster worker pool.

## Trigger

Apply soroswap workload. Add a Tracy zone around the bundle-build loop (`for (auto const& txBundle : stage)` body) inside `applyParallelPhase`; measure aggregate self-time. Expected total: a few ms per ledger.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:applyParallelPhase:2967-3020` — the serial bundle-build loop
- `src/transactions/TransactionMeta.cpp:TransactionMetaBuilder ctor:924` — meta-builder construction per tx
- `src/transactions/TransactionMeta.cpp:OperationMetaBuilder ctor:477` — per-op meta-builder
- `src/transactions/EventManager.cpp:OpEventManager:236` — per-op event manager (mEnabled=false in benchmark but constructor still runs)
- `src/ledger/LedgerManagerImpl.cpp:applyThread:2480-2521` — where workers would receive un-built bundles and finish construction

## Evidence

- The loop is unambiguously in the serial critical path between `processFeesSeqNums` and `applySorobanStages`.
- With 2000 txs/ledger the loop iteration count is large; even cheap per-iteration cost compounds.
- Workers in `applySorobanStageClustersInParallel` already have natural per-cluster work granularity, so moving bundle construction into `applyThread` is structurally feasible.

## Anti-Evidence

- Transactions fail 016 (`bundle-build-loop-optimization`) and Meta-Pattern #15 ("Per-Tx Micro-Costs Exhaustively Sub-Threshold") established that the per-tx serial work in `applyParallelPhase`'s bundle loop totals sub-medium in aggregate.
- `OperationMetaBuilder` and `OpEventManager` are constructed with `mEnabled=false` in the benchmark config; the constructors are nearly empty (no XDR variant allocation, no event-vector reserves).
- `TxBundle`/`TxEffects` are tightly coupled to `ApplyStage`'s storage layout (a `std::vector<TxBundle>` inside `ApplyStage`). Moving construction into workers requires changing ownership/lifetime semantics in `ParallelApplyStage.h/.cpp` — a large refactor for sub-medium gain.
- Bundle ordering must be deterministic; per-cluster worker construction must produce bundles in a stable observable order. Adds complexity without addressing the dominant critical-path costs.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — the *parallelize-into-workers* framing is novel relative to the existing `bundle-build-loop-optimization` fail (which proposed shrinking per-iteration cost, not relocating the loop). But the underlying impact ceiling is the same.

### Why It Failed

The bundle-build loop's aggregate serial cost is sub-medium (per fail 016 and Meta-Pattern #15). Even fully eliminating its critical-path contribution by moving it into workers would yield <3% apply-time reduction — below the Medium threshold for this objective. The associated refactor of `ApplyStage`/`TxBundle`/`TxEffects` ownership is high-risk (determinism-sensitive, touches the parallel-apply data-structure invariants used by `checkAllTxBundleInvariants` and `processPostTxSetApply`) for a Low-tier projected win. The risk/reward ratio fails the SEVERITY_SCALE Medium criteria, and Low-tier hypotheses are not accepted per the objective's stated severity threshold.

### Lesson Learned

When considering parallelization of a serial phase, first quantify the phase's self-time as a fraction of `applyLedger`. For the bundle-build loop, fail 016 already measured this as sub-3%; even theoretically perfect parallelization cannot lift a sub-medium serial cost above the Medium threshold. Restructuring `ApplyStage` ownership for sub-medium gains is not viable. Future optimizers should look for parallelization opportunities only on phases whose serial self-time is *already* >5% of `applyLedger` (e.g., `processFeesSeqNums` at 3.52% is the borderline candidate, and that has its own existing fails — 002, 012 — explaining why parallelizing it does not clear the bar either).
