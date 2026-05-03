# H001: Lazy storage rollback points for successful Soroban host frames

**Date**: 2026-05-03
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Apply-time reduction by removing eager per-frame storage-map rollback cloning on the soroswap host invocation path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Successful Soroban contract frames should commit the same storage changes, emit the same events, consume the same authorization entries, and produce the same result/meta as they do today. Failed frames must still roll back all storage, events, and authorization mutations to the exact pre-frame state. The implementation should not eagerly copy rollback state that is never consulted on the overwhelmingly common successful-frame path.

## Mechanism

`Host::push_context` eagerly constructs a `RollbackPoint` for every frame, including `self.try_borrow_storage()?.map.metered_clone(self)?`, before the frame body is known to fail or succeed. On success, `Host::with_frame` later calls `pop_context(None)` and discards this storage snapshot without using it. In the current soroswap diagnostic trace, `push context` is a descendant of `Host::invoke_function`/`applyLedger` and totals 537,767,407 ns across 54,270 frame pushes, with 107,863,542 ns self-time; a lazy storage checkpoint or mutation journal could remove the successful-frame storage-map clone while preserving rollback semantics for rare failures.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with the accepted baseline from `ai-summary/CURRENT_STATE.md`. Each ledger invokes thousands of nested Soroban frames, most of which succeed; the issue is triggered by normal successful calls through Wasm contracts and built-in SAC frames under `closeLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:186-205` — `Host::push_context` always snapshots storage into `RollbackPoint`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:556-562` — successful frames call `pop_context(None)`, proving the eager rollback point is unused on success.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:31-42,357-365` — `StorageMap` rollback cloning walks the backing vector and pays metered clone costs.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:27,182-233` — enforcing-mode host storage stores all loaded footprint entries in a `MeteredOrdMap`.

## Evidence

The current diagnostic trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -f "push context"` reports `push context,soroban-env-host/src/host/frame.rs,191,537767407,...,54270,9909,...`; `csvexport-release -e -f "push context"` reports 107,863,542 ns self-time. This zone is reached from `Host::invoke_function` under `InvokeHostFunctionOpFrame doParallelApply`, which is inside `applySorobanStageClustersInParallel` and therefore inside the `applyLedger` measurement window. The structural waste is success-biased: the rollback storage snapshot is materialized before the frame body, but success discards it.

## Anti-Evidence

Rollback behavior is consensus-critical: a lazy design must still restore nested storage mutations, instance-storage persistence, events, and auth state exactly on every error path. The current clone is also metered, so a p26-preserving implementation would need to replay equivalent charges or gate any accounting change behind the next protocol version. A PoC should first isolate storage-clone time from the broader `push context` wrapper because the wrapper also includes authorization-frame work.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban` or `success/soroban`
**Failed At**: reviewer

### Trace Summary

The inefficiency exists: every `Host::with_frame` call goes through `push_context`, which eagerly clones the full `StorageMap` into a `RollbackPoint`, and successful frames later call `pop_context(None)` without using that cloned storage. The path is in scope for soroswap apply: `LedgerManagerImpl::applyTransactions` enters the parallel Soroban phase, worker threads call `InvokeHostFunctionOpFrame::doParallelApply`, C++ crosses the Rust bridge, and `e2e_invoke::invoke_host_function` invokes the p26 host. However, the current diagnostic trace bounds the entire `push context` self-time at 107,863,542 ns against 5,230,315,999 ns of aggregate `applyLedger` time, so even removing all self-time would be about 2.1% before subtracting unavoidable context/auth bookkeeping and p26 metering-preservation costs. This falls below the optimize-soroswap objective's Medium severity threshold.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-2884` — `applyTransactions` loads Soroban config and dispatches parallel phases during `closeLedger`.
- `src/ledger/LedgerManagerImpl.cpp:2966-3030` — `applyParallelPhase` builds Soroban apply stages and calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2508` — apply worker threads call `TransactionFrame::parallelApply` for each Soroban `TxBundle`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` launches cluster workers and waits on their futures inside the apply path.
- `src/transactions/TransactionFrame.cpp:2385-2430` — `TransactionFrame::parallelApply` dispatches the single Soroban operation to `OperationFrame::parallelApply`.
- `src/transactions/OperationFrame.cpp:175-188` — `OperationFrame::parallelApply` forwards to the concrete `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `InvokeHostFunctionOpFrame::doParallelApply` constructs the parallel helper and runs host-function apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` — helper apply performs footprint loading, invokes the Rust host, records returned storage changes, collects events, consumes refundable resources, and finalizes success.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` calls `rust_bridge::invoke_host_function` with ledger entries, TTL entries, resources, auth, ledger info, PRNG seed, and module cache.
- `src/rust/src/soroban_invoke.rs:7-38` — Rust bridge dispatches to the protocol-specific host module for the ledger protocol.
- `src/rust/src/soroban_proto_any.rs:408-481` — protocol-agnostic Rust wrapper deserializes inputs, builds `Storage`, creates `Host`, installs ledger/auth/module-cache state, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-521` — p26 host invocation builds the enforcing storage map, clones an initial storage map for post-success diffing, invokes the host function, then computes ledger changes only after success.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` pushes a context, runs the frame body, persists/reloads instance storage on success, then rolls back only when `res.is_err()`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` constructs `RollbackPoint { storage: self.try_borrow_storage()?.map.metered_clone(self)?, events, auth }` before the frame body runs.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:210-229` — `pop_context` restores rollback storage/events/auth only when passed `Some(rp)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — top-level `HostFunction::InvokeContract` uses `with_frame(Frame::HostFunction(...))` before calling into contract execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-783` — Wasm and SAC contract calls both use `with_frame`, so the rollback clone repeats for nested successful frames.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:187-255,397-407` — `metered_clone` charges shallow copy and substructure; `Vec<C>` clone charges allocation and shallow copy per element.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:14-42,357-365` — `MeteredOrdMap` is backed by a `Vec` and delegates clone substructure charging to the backing vector.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28,178-183,333-357` — `StorageMap` stores `Rc<LedgerKey> -> Option<(Rc<LedgerEntry>, live_until)>`, and writes replace the map with a newly inserted copy.

### Why It Failed

This is a real optimization opportunity, but not a Medium-or-better one under the objective's acceptance criteria. The current trace reports `push context` self-time of 107,863,542 ns over 54,270 calls, while `applyLedger` totals 5,230,315,999 ns over the same soroswap Tracy run; the entire self-time is only about 2.1% of aggregate apply work. The removable storage snapshot is only a subset of that self-time because frame push must still perform authorization frame work, event checkpointing, context-stack metering, context push/pop, instance-storage success handling, and either preserve released-protocol clone charges or gate accounting changes behind a new protocol. Since the objective rejects Low findings, the hypothesis does not clear review.

### Lesson Learned

For Soroban frame rollback optimizations, compare the isolated rollback component against aggregate `applyLedger` time and subtract mandatory frame bookkeeping and consensus-metering costs. Parent-zone totals such as `push context` are useful for locating code, but the accepted severity must be based on the removable self-time, not the full zone total or a single successful-path intuition.
