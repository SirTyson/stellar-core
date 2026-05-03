# H002: Lazy authorization snapshots for successful Soroban call frames

**Date**: 2026-05-03
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Apply-time reduction by avoiding per-frame auth tracker snapshots that are discarded on successful soroswap contract calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Authorization enforcement should consume each matching `AuthorizedInvocation` exactly once, preserve invoker-contract authorization semantics, and roll back all auth mutations if a nested frame fails. Successful frames should leave the same exhausted auth tree state as today. The implementation should not eagerly snapshot all auth trackers for frames that complete successfully without requiring rollback.

## Mechanism

`AuthorizationManager::push_frame` pushes the current contract invocation, pushes a tracker frame into every account/invoker tracker, and then immediately calls `snapshot`. `snapshot` iterates the account tracker list and invoker-contract tracker list, constructing per-tracker snapshots even though `Host::with_frame` only passes the snapshot back to `pop_context` on error. In the current soroswap trace, `push auth frame` totals 402,098,282 ns over 54,270 frames and `snapshot auth` totals 235,801,940 ns, with 176,060,644 ns self-time; replacing eager full snapshots with a per-frame mutation journal or lazy first-mutation checkpoint should remove most successful-frame snapshot work without changing auth ordering or parallelism.

## Trigger

Run soroswap apply-load on the current baseline. Each successful swap transaction enters multiple Wasm and SAC frames and repeatedly calls `require_auth`; the frame push path snapshots authorization state for all those frames even when the frame succeeds and no rollback snapshot is consumed.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `AuthorizationManager::push_frame` pushes call-stack/tracker frames and eagerly snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` — `AuthorizationManager::snapshot` walks account and invoker trackers and allocates snapshot vectors.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1222-1304` — rollback consumes the snapshot only on failure.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:222-229,556-562` — successful frame pop passes no rollback snapshot, while failed frame pop restores from the saved snapshot.

## Evidence

The current diagnostic trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -f "push auth frame"` reports `push auth frame,soroban-env-host/src/auth.rs,1345,402098282,...,54270,7409,...`; `csvexport-release -f "snapshot auth"` reports `snapshot auth,soroban-env-host/src/auth.rs,1170,235801940,...,54270,4344,...`; self-time for `snapshot auth` is 176,060,644 ns. These zones execute under Soroban host invocation (`Host::invoke_function` -> contract/SAC frame push) inside `InvokeHostFunctionOpFrame doParallelApply`, which is part of `applyLedger`. The code shape is a classic success-path rollback tax: all frames pay snapshot cost, while only failing frames need rollback data.

## Anti-Evidence

Auth rollback is subtle because `require_auth`, invoker-contract auth, custom account `__check_auth`, and nested frame failures can mutate different tracker layers. A lazy design must preserve p26 metering or be next-protocol-gated, and it must not change which invocation node is exhausted when multiple auth trees could match. The raw `snapshot auth` zone alone is smaller than the full host-execution phase, so the PoC must measure end-to-end apply time and not rely only on aggregate worker self-time.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban` or `success/soroban`
**Failed At**: reviewer

### Trace Summary

The inefficiency exists: every `Host::with_frame` pushes an auth frame, and `AuthorizationManager::push_frame` eagerly snapshots all account and invoker-contract trackers before the frame body runs. Successful frames later call `pop_context(None)`, so `AuthorizationManager::pop_frame` receives no rollback snapshot and the eager snapshot work is discarded. The path is in scope for soroswap apply through `LedgerManagerImpl::applyTransactions` -> `applyParallelPhase` -> `applySorobanStageClustersInParallel` -> `InvokeHostFunctionOpFrame::doParallelApply` -> Rust `invoke_host_function` -> p26 `Host::invoke_function`. However, the projected top-line impact does not clear the optimize-soroswap Medium threshold because the 176 ms `snapshot auth` self-time is aggregate worker CPU across a trace whose soroswap workload is intentionally spread over 8 independent pairs/clusters; per-ledger critical-path savings are therefore well below the raw aggregate percentage.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-2964` — `applyTransactions` loads Soroban config and dispatches parallel phases during ledger close.
- `src/ledger/LedgerManagerImpl.cpp:2966-3030` — `applyParallelPhase` builds `TxBundle`s and calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` launches one async worker per cluster and waits on the futures inside the apply path.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — worker threads iterate cluster transactions and call `TransactionFrame::parallelApply`.
- `src/transactions/TransactionFrame.cpp:2385-2430` — `parallelApply` dispatches the single Soroban operation to `OperationFrame::parallelApply`.
- `src/transactions/OperationFrame.cpp:175-188` — `OperationFrame::parallelApply` forwards to the concrete Soroban `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `InvokeHostFunctionOpFrame::doParallelApply` runs the parallel invoke helper.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` — invoke helper applies the footprint, invokes the Rust host, records returned storage changes/events, consumes refundable resources, and finalizes success.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ crosses the Rust bridge through `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-38` — Rust bridge dispatches to the protocol-specific host module.
- `src/rust/src/soroban_proto_any.rs:408-490` — protocol-agnostic wrapper creates the budget, invokes the p26 host wrapper, and returns resource/timing/output data.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-521` — p26 e2e invocation builds enforcing storage, installs auth entries and ledger info, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` pushes a rollback point, runs the frame body, and calls `pop_context(Some(rp))` only on error; success calls `pop_context(None)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-229` — `push_context` obtains the auth snapshot from `AuthorizationManager::push_frame`, while `pop_context` passes it back only when rolling back.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-783` — Wasm contract and SAC calls both use `with_frame`, so nested successful soroswap calls repeatedly exercise the auth snapshot path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — top-level `InvokeContract` host function also uses `with_frame`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` — `snapshot` allocates account tracker snapshot vectors and recursively snapshots account/invoker authorization trees.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1222-1304` — rollback consumes `AuthorizationManagerSnapshot` only for failed frames.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `push_frame` pushes the contract/SAC frame, pushes tracker frames, and eagerly calls `snapshot`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1376-1425` — `pop_frame` rolls back only if a snapshot is provided, then pops call-stack and tracker frames.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:729-758,1782-1798,2193-2216` — snapshots preserve only mutable exhaustion/verification state, while rollback restores those fields.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1671-1732,1900-1944,2264-2270` — `require_auth` mutates tracker match/exhaustion/verification state that a lazy design would need to checkpoint before first mutation.
- `src/simulation/ApplyLoad.cpp:2672-2682,3389-3393` — soroswap creates one pair per configured dependent cluster and round-robins swaps across pairs to maximize parallelism; the reviewed run log confirms 8 pairs for 8 clusters.

### Why It Failed

The claim is technically real, but it is below the objective severity threshold. The trace reports `snapshot auth` self-time of 176,060,644 ns over 54,270 frames; compared optimistically to the previously recorded 5,230,315,999 ns aggregate `applyLedger` time for the same diagnostic run, that is only about 3.4% before accounting for parallel dilution, lazy-checkpoint overhead, and any p26 metering-preservation cost. The soroswap benchmark constructs 8 independent swap pairs/clusters and round-robins transactions across them, so aggregate worker CPU does not translate one-for-one to apply wall time: even a perfect removal of snapshot self-time projects to sub-1% to roughly Low-tier top-line savings, not the required 3-10% Medium range. Under the optimize-soroswap reviewer objective, Low findings are rejected.

### Lesson Learned

For Soroban host-frame micro-optimizations inside parallel apply, aggregate worker self-time must be converted to critical-path apply-time savings before assigning severity. Auth snapshotting is a real success-path rollback tax, but in the balanced 8-cluster soroswap workload its aggregate CPU cost is too small to justify promotion without a stronger measurement showing Medium-or-better end-to-end improvement.
