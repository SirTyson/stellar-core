# H001: Replace per-frame host context snapshots with rollback journals

**Date**: 2026-05-03
**Subsystem**: ledger / Soroban host invocation during apply
**Severity**: Medium
**Impact**: 4-8% soroswap apply-time reduction by removing repeated full auth/storage rollback snapshots from nested contract frames
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Nested Soroban contract/SAC frames should preserve exact rollback semantics when a frame fails, but successful frames should not need to clone the entire host storage map and snapshot every authorization tracker on every `with_frame` entry. The host should be able to restore only the storage, event, and authorization mutations performed after the frame was pushed, while successful frames pay only a cheap checkpoint marker.

## Mechanism

`Host::push_context` currently calls `AuthorizationManager::push_frame`, immediately snapshots authorization state, then clones `storage.map` into the `RollbackPoint` before pushing every contract or SAC frame. In the soroswap trace this happens 54,270 times inside `applyLedger`; `push context` totals 537,767,407 ns, `push auth frame` totals 402,098,282 ns, and `snapshot auth` alone contributes 176,060,644 ns of self-time. A journaled rollback design would record old values at mutation sites (`Storage::put_opt_helper`, TTL extension, event append, and auth tracker mutation) and store only frame-local journal lengths in the rollback point, so successful nested frames avoid the repeated shallow-but-wide map/auth snapshot copies.

## Trigger

Run the current soroswap apply-load diagnostic trace
`9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Each successful swap enters multiple Wasm and Stellar Asset Contract frames through `Host::call_contract_fn`; every frame pushes a context, snapshots auth state, clones the storage map, executes, and then pops without using the snapshot for most successful calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` snapshots auth and clones `storage.map` into `RollbackPoint` before every frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:210-229` — `pop_context` rolls storage/events/auth back from the snapshot on failure.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1190` — `AuthorizationManager::snapshot` walks account trackers and allocates tracker snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `push_frame` eagerly pushes auth call-stack state and snapshots it for every contract/SAC frame.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-515` — storage mutation sites that could append old values to a rollback journal instead of requiring a full map clone at frame entry.

## Evidence

The current soroswap trace confirms these zones are descendants of `applyLedger`: all 54,270 `push context`, `push auth frame`, and `snapshot auth` events overlap `applyLedger` windows. `push context` totals 537,767,407 ns, or about 10.3% of the 5,230,315,999 ns `applyLedger` total; its direct auth child totals 402,098,282 ns, and the `snapshot auth` child has 176,060,644 ns self-time. Source structure explains the cost: `push_context` snapshots rollback state before knowing whether the frame will fail, while soroswap frames overwhelmingly complete normally and only need the rollback point for exceptional unwind paths.

## Anti-Evidence

Rollback snapshots are correctness-critical: storage, events, account auth trackers, invoker-contract trackers, and call-stack updates must roll back exactly when a contract catches an error. A journal must preserve current metering semantics or be protocol-gated if avoiding clone/access charges changes observable budgets. Some frames do perform writes, TTL extensions, or auth checks, so the expected win is not the entire `push context` envelope; the viable PoC needs to show the mutation-journal overhead on successful soroswap frames stays below the current eager snapshot cost.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `ai-summary/fail/ledger`, `ai-summary/success/ledger`, or cross-subsystem records
**Failed At**: reviewer

### Trace Summary

The claimed eager rollback work is real: every host frame calls `push_context`, which pushes authorization frame state, snapshots auth trackers, and clones the host storage map before executing the frame body. On success, `with_frame` calls `pop_context(None)`, so the precomputed storage/auth rollback snapshot is not used; on error, `pop_context(Some(rp))` restores storage, events, and authorization state. However, for the soroswap benchmark this work sits inside the parallel Soroban worker path, so the aggregate 537.8 ms `push context` total cannot be compared directly to serial `applyLedger` wall time.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — each cluster worker executes `LedgerManagerImpl::applyThread`, applying every `TxBundle` in that cluster and calling `TransactionFrame::parallelApply`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` launches one `std::async` worker per stage cluster and waits for all futures; per-worker host time is therefore parallel aggregate time, not serial apply-thread time.
- `src/ledger/LedgerManagerImpl.cpp:2622-2709` — each Soroban stage runs cluster workers in parallel and only then commits thread results back into global state and finally into the `LedgerTxn`.
- `src/transactions/TransactionFrame.cpp:2385-2448` and `src/transactions/OperationFrame.cpp:175-188` — the parallel worker transaction path dispatches the single Soroban operation through `OperationFrame::parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — p23+ Soroban operations use `InvokeHostFunctionOpFrame::doParallelApply`, whose helper invokes the Rust host.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` and `src/rust/src/soroban_invoke.rs:7-39` — C++ calls the Rust bridge `invoke_host_function` with ledger entries, auth entries, resources, and module cache.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — Rust builds enforcing storage, initializes auth and ledger context, and calls `host.invoke_function(host_function)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1149` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — an invoke-contract host function enters a top-level host-function frame and then nested Wasm/SAC contract frames via `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` calls `AuthorizationManager::push_frame`, snapshots auth, and clones `storage.map` into `RollbackPoint`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` computes the rollback point before execution, then discards it on success and only passes it to `pop_context` on error.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1219` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — auth snapshotting walks account trackers and invoker-contract trackers after pushing the call-stack/tracker frame.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-515` — storage writes and TTL extensions are the mutation sites a journal design would need to cover.

### Why It Failed

The mechanism is plausible, but the Medium severity projection is not. The trace name and objective context identify the target as an 8-thread soroswap run, and the C++ path confirms host invocation happens inside per-cluster parallel workers. The hypothesis treats 537,767,407 ns of aggregate worker `push context` time as 10.3% of `applyLedger`; normalized across eight parallel clusters, even eliminating the entire `push context` envelope would project to roughly 67 ms over 5.23 s, about 1.3% of apply time. The proposed journal cannot eliminate the entire envelope because it still needs frame push/pop, event checkpoints, auth call-stack updates, mutation-site journaling, and either preserved metering or a protocol-gated budget change.

Under the optimize-soroswap objective, Low-tier 1-3% projections are rejected at review time. This hypothesis therefore fails below the required Medium threshold even though the eager snapshot cost is real.

### Lesson Learned

For Soroban apply optimizations, Tracy zones inside `applySorobanStageClustersInParallel` must be normalized by the worker critical path rather than summed as serial work. A large aggregate host cost can still be sub-Medium if it is distributed across the configured cluster parallelism and only the slowest worker portion affects top-line `closeLedger` apply time.
