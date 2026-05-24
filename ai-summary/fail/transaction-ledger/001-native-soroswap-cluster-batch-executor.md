# H001: Native Soroswap cluster batch executor for ordered same-pool swap clusters

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / Soroban native Soroswap apply
**Severity**: High
**Impact**: Soroswap apply-time reduction by restructuring the dominant parallel-apply worker phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Soroban apply stage whose clusters are true same-pool Soroswap conflict groups, stellar-core should still apply transactions in canonical transaction order and produce identical per-transaction results, events, refundable fees, ledger changes, and metadata. However, once a cluster is known to contain only next-protocol native Soroswap router/pair swap transactions with compatible footprints, the efficient path should initialize a cluster-local native executor once, then execute each swap in order against a typed pool/SAC state journal instead of rebuilding a fresh generic host/storage/VM pipeline for every transaction.

The observable behavior should remain exactly ordered: tx `i+1` must see tx `i`'s reserve and SAC balance changes, failed transactions must not commit changes, and the worker must return the same `ParallelTxReturnVal` sequence consumed by `commitChangesFromThreads`.

## Mechanism

The current worker loop in `LedgerManagerImpl::applyThread` processes a cluster sequentially and calls `TransactionFrame::parallelApply` for every transaction. Each swap then enters `InvokeHostFunctionOpFrame::doParallelApply`, serializes C++ ledger inputs, calls `rust_bridge::invoke_host_function`, builds a fresh Rust host/storage map, dispatches router/pair/SAC calls, extracts ledger changes, and returns XDR buffers. This repeats even when the cluster is already a deterministic ordered batch of swaps against the same pool and SAC balance keys.

A protocol-gated native cluster executor can use the cluster's existing conflict isolation as the determinism boundary: keep at most one worker per cluster (`NUM_CLUSTERS` unchanged), walk transactions in canonical order, maintain typed in-memory pool reserves and SAC balance slots, run the native swap arithmetic and auth-equivalent checks per transaction, and emit per-tx effects in the same order. This would remove the repeated per-tx generic host/VM/setup envelope rather than a micro-slice inside it, targeting the dominant apply descendant: `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStage -> applySorobanStageClustersInParallel -> parallelApply`.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on protocol 27/native-hook-enabled builds. The trigger is a Soroban stage whose clusters contain ordered swaps for the same Soroswap pool, recognized by the same allowlisted pool Wasm hash and native `swap`/getter paths currently handled in `host/frame.rs`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2500-2511` — per-cluster worker loop currently invokes every transaction through the full per-tx parallel apply path and commits successful tx state immediately into `ThreadParallelApplyLedgerState`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` already limits work to one worker per cluster; the batch executor would preserve this `NUM_CLUSTERS` bound.
- `src/transactions/TransactionFrame.cpp:2385-2448` — `parallelApply` creates the per-tx operation apply envelope and meta/ledger-change extraction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ bridge invocation currently rebuilds input buffers and crosses into Rust for every transaction.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-580` — fresh host/storage setup, host invocation, finish, ledger-change extraction, and event encoding are repeated per tx.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1304` — native Soroswap pool swap logic already implements the ordered swap semantics for a single transaction and can be lifted into a cluster-local typed executor.

## Evidence

- Current Tracy self-time confirms the targeted zones are descendants of `applyLedger`: `applyLedger@ledger/LedgerManagerImpl.cpp:1484` total is 4.802s; `applySorobanStageClustersInParallel@ledger/LedgerManagerImpl.cpp:2537` self-time is 3.008s over 44 non-empty stage executions, representing the apply thread waiting for cluster workers.
- Worker descendants dominate the non-empty stage: `parallelApply@TransactionFrame.cpp:2392` totals 11.574s over 8,379 calls, `InvokeHostFunctionOpFrame doParallelApply@InvokeHostFunctionOpFrame.cpp:1367` totals 11.566s, and `invokeHostFunction@InvokeHostFunctionOpFrame.cpp:559` totals 10.964s. These are not TX-set-construction zones; they sit under the parallel apply worker path.
- The Rust side still spends substantial per-tx time in the generic invoke envelope even after the accepted native hooks: `invoke_host_function@e2e_invoke.rs:488` self-time is 870.9ms over 8,379 calls, `Host::invoke_function@e2e_invoke.rs:550` total is 8.191s, `Vm::invoke_function_raw@vm.rs:400` total is 7.146s, and `SAC transfer@contract.rs:212` total is 2.602s. A cluster executor targets the repeated envelope around these operations, not just a sub-threshold helper.
- Source confirms the current native Soroswap hook exists (`try_call_native_soroswap_pool_swap`, `call_native_soroswap_pool_swap`, and direct SAC balance read helpers), so this is not one of the earlier failed hypotheses against absent native paths.

## Anti-Evidence

- A generic cluster-batched Soroban invocation was previously rejected because decoded-value reuse skips protocol-visible metering. This hypothesis must therefore be narrow and protocol-gated to the already-protocol-gated native Soroswap path, with explicit per-tx budget/resource accounting rather than unmetered reuse of generic decoded host values.
- True same-pool clusters cannot be reordered or parallelized internally; the batch executor only amortizes setup/dispatch/state-carrier work while preserving serial transaction order.
- Per-tx result/meta boundaries remain load-bearing. The design must still create each transaction's `TxEffects`, refundable fee tracker updates, events, and success/failure rollback boundary, or it will not be consensus-equivalent.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `002-native-router-trampoline-refined.md + 002-fused-native-router-exact-swap-executor.md` in `ai-summary/fail/transaction-ledger/summary.md`; also overlaps the prior `002-cluster-batched-soroban-invocation.md` cluster-batching rejection
**Failed At**: reviewer

### Trace Summary

The soroswap benchmark transactions invoke the router contract function `swap_exact_tokens_for_tokens`; the current host only contains native Soroswap hooks for the pair/pool code hash after the router Wasm makes a nested pair call. The ledger apply worker still loops over each `TxBundle`, calls `TransactionFrame::parallelApply`, creates per-tx operation metadata/result state, serializes each footprint/auth/resource set, invokes a fresh Rust host, extracts per-tx ledger changes/events/rent, and commits only successful tx state. A cluster-local typed executor that bypasses the router/pair/SAC host path is substantially the same native fused Soroswap executor already recorded as failed: preserving auth, rollback, TTL, rent, event, resource, and metadata semantics retains per-transaction work, while skipping those semantics would break consensus equivalence.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md` — records `002-native-router-trampoline-refined.md + 002-fused-native-router-exact-swap-executor.md` as below threshold after native pool hooks, and records `002-cluster-batched-soroban-invocation.md` as rejected because decoded-value reuse crosses protocol-visible metering boundaries.
- `src/simulation/ApplyLoad.cpp:3427-3439,3447-3475,3477-3496` — generated soroswap apply-load transactions call router `swap_exact_tokens_for_tokens`, carry router/pair/SAC/trustline footprints, and include a source-account auth tree for the router and input SAC transfer.
- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — parallel phases are converted to generic `TxBundle` clusters and then handed to Soroban stage application; the cluster structure does not itself prove a native router/pair swap shape.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520,2530-2574` — each cluster worker applies transactions sequentially, flushes RO TTL bumps per transaction, calls `parallelApply`, and commits successful tx changes before moving to the next transaction.
- `src/transactions/TransactionFrame.cpp:2385-2448` — `parallelApply` enforces the per-tx success gate, calls the single Soroban operation, and then records per-transaction meta/ledger changes.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:537-584,982-1017,1358-1377` — each invoke-host-function operation builds footprint buffers, calls `rust_bridge::invoke_host_function`, records returned ledger changes/events, consumes refundable resources, finalizes the success hash, and returns a `ParallelTxSuccessVal`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-580` — every transaction builds a Rust footprint/storage map, host, auth entries, host function, source account, PRNG seed, module cache attachment, result value, ledger changes, and encoded events.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-838` — `call_contract_fn` checks the native Soroswap pool getter/swap hooks only for `ContractExecutable::Wasm` matching the pool hash, then otherwise instantiates Wasm; there is no native router hook in this file.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1304,1330-1393` — the existing native pool swap is still a single-transaction host-frame implementation; it performs SAC transfer/balance subcalls or direct SAC balance reads, storage TTL updates, event construction, and host-object conversions under the current per-tx host/budget.
- `src/rust/apply-load-wasm/README.md:1-6` — router/pair/factory Wasms are vendored benchmark artifacts, with only external source references in-tree; the router semantics are not implemented as an audited native production path here.

### Why It Failed

This hypothesis is substantially covered by the prior native router/fused Soroswap executor failure. The only new wrapper is "cluster-local", but the traced apply path shows the consensus-critical boundaries are still per transaction: auth replay, rollback on failure, resource-limit checks, rent/refundable-fee accounting, event emission, success-hash construction, operation meta, RO TTL flushing, and `ParallelTxSuccessVal` commit ordering. A typed cluster journal can preserve serial visibility of pair reserves, but it cannot amortize or skip those per-tx observable boundaries without changing results; preserving them collapses back to the already-reviewed fused/native executor class that was recorded below the objective's Medium threshold.

The mechanism also overstates the current native coverage. `host/frame.rs` has native pair getter/swap hooks, but the benchmark's top-level host function is the router Wasm `swap_exact_tokens_for_tokens`, and there is no native router dispatch in the reviewed source. Building the proposed executor would therefore require a new native router+pair+SAC implementation against vendored Wasm behavior, not simply lifting the existing single-tx pool hook into the cluster loop.

### Lesson Learned

Native pair hooks do not make cluster-level Soroswap batching novel by themselves. Future hypotheses in this area need to distinguish themselves from the failed native router/fused executor record and quantify a remaining per-cluster saving that survives active-cluster normalization while preserving per-transaction auth, rollback, rent, TTL, event, result, and metadata semantics.
