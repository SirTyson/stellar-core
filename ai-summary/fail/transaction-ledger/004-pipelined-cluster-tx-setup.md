# H004: Pipeline tx N+1 setup with tx N finalization inside cluster workers

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / parallel apply cluster worker
**Severity**: Low
**Impact**: Within a single cluster worker, overlap the post-host finalize work of the current tx (recordStorageChanges, setEffectsDeltaFromSuccessfulTx) with the pre-host setup of the next tx (addReads, addFootprint, bridge buffer construction).
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each cluster worker processes its assigned `TxBundle`s sequentially. For tx N the worker runs `addFootprint` → `addReads` → bridge-buffer construction → `invokeHostFunction` (Rust) → `extract_ledger_effects` → `recordStorageChanges` → `setEffectsDeltaFromSuccessfulTx`. Tx N+1 only begins after tx N's finalize work returns. Since tx N's post-host finalize work touches only that tx's `TxParallelApplyLedgerState` and tx N+1's pre-host setup touches only the cluster's footprint loaders + tx N+1's own footprint, these two phases have disjoint data and could in principle execute on a small per-cluster two-stage internal pipeline (one helper thread per cluster worker).

## Mechanism

Inside `LedgerManagerImpl::applyThread` each cluster worker iterates `TxBundle`s strictly serially. Tracy shows that the per-tx C++ envelope around `invokeHostFunction` (`addReads` 196 ms self over 13,648 calls, `addFootprint` 272 ms self over 6,824 calls, `recordStorageChanges` 55 ms self over 6,776 calls, `InvokeHostFunctionParallelApplyHelper` 627 µs over 6,824 calls) is mostly setup/finalize bookkeeping that does not depend on the same ledger state slot tx N's host call modifies. A per-cluster lightweight pipeline (e.g. a single follower task that executes `recordStorageChanges` + `setEffectsDeltaFromSuccessfulTx` for tx N while the main worker thread starts `addFootprint`/`addReads` for tx N+1) could overlap them.

## Trigger

Run the current soroswap apply-load Tracy benchmark from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Each cluster worker iterates ~850 soroswap txs sequentially.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` strictly-serial bundle loop.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:540-643` — `addFootprint`, `addReads`, `recordStorageChanges` per-tx setup/finalize.
- `src/transactions/ParallelApplyUtils.cpp` — `setEffectsDeltaFromSuccessfulTx`, `commitChangesFromSuccessfulTx` per-tx finalize.

## Evidence

- The C++ envelope around the host call is structurally sequential and not currently overlapped with the next tx.
- All target zones are confirmed inside `applyLedger` via timestamp-filtered counts (13k–14k call counts per zone matching the txs/ledger × ledger count).

## Anti-Evidence

- Each per-tx envelope zone is small in absolute terms.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — intra-cluster two-stage pipelining (setup of tx N+1 overlapped with finalize of tx N) has not been investigated. Prior failures targeted cross-ledger pipelining (`004-pipeline-seal-with-next-ledger-setup.md`), folding `preParallelApplyReadOnly` into workers, and rebalancing clusters — not intra-worker overlap.

### Why It Failed

Sizing the recoverable critical-path savings:

- Aggregate post-host finalize work in cluster workers: `recordStorageChanges` 55 ms + `setEffectsDeltaFromSuccessfulTx`/`commitChangesFromSuccessfulTx` together a few tens of ms + `InvokeHostFunctionParallelApplyHelper` 0.6 ms ≈ ~60 ms aggregate.
- Aggregate pre-host setup work that could be hoisted: `addFootprint` 272 ms + `addReads` 196 ms + bridge buffer construction (small) ≈ ~470 ms aggregate.
- Critical-path overlap window per cluster: `min(finalize_N, setup_(N+1))` ≈ 60 ms aggregate / 8 clusters / 71 ledgers ≈ **0.10 ms / ledger**.
- Even being generous and treating the full setup-side aggregate as overlappable: 470 ms / 8 / 71 ≈ 0.83 ms / ledger ≈ 0.30% of the 272 ms baseline.

This is sub-Low (below the 1% benchmark-noise floor and far below the Medium 3% floor). It also violates the established meta-pattern #6: aggregate worker time must be divided by cluster count before estimating the critical-path opportunity. Additionally, introducing an extra helper thread per cluster worker pushes total active worker count above `NUM_CLUSTERS = 8`, which is explicitly out of scope per the objective ("Optimizations that exceed `NUM_CLUSTERS` parallelism").

### Lesson Learned

Intra-worker pipelining inside a parallel-apply cluster cannot reach Medium severity for the soroswap shape: the per-tx C++ envelope work (footprint setup, reads, finalize bookkeeping) is dwarfed by the per-tx Rust host invocation (`invokeHostFunction` aggregate 12,180 ms vs. envelope ≈ 530 ms aggregate), so even a perfect overlap of the full envelope with itself would be a single-digit percent of the *envelope*, not of apply time. Future apply-thread pipelining hypotheses must size the recoverable aggregate against `cluster_count × ledger_count` and must respect the `NUM_CLUSTERS` worker cap — adding helper threads beyond the configured cluster count is out of scope regardless of speedup.
