# H001: Batch metered XDR `ValSer` charges during Soroban host serialization

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host metering
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing per-leaf budget-metering overhead from hot XDR serialization paths
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Host XDR serialization should charge exactly the same `ContractCostType::ValSer` CPU and memory budget that it charges today, but it should not re-enter `Budget::charge`, borrow the `BudgetImpl`, look up both cost models, update trackers, and emit a Tracy `charge` span for every tiny `Write::write` chunk produced by the XDR encoder. For successful soroswap invocations, serializing host values, event payloads, hashes, and byte outputs should produce the same bytes and the same final budget totals with fewer repeated budget-accounting calls on the apply hot path.

## Mechanism

`metered_write_xdr` wraps the destination `Vec<u8>` in `MeteredWrite`, and every low-level `write(&[u8])` immediately calls `budget.charge(ContractCostType::ValSer, Some(buf.len()))`. The XDR encoder emits many small writes for scalar fields and nested objects, so soroswap pays a full `Budget` borrow/model/tracker/limit-check path for each leaf written even though the cost type and most input lengths are repeated. A serialization-local accumulator can count writes by input length, perform the real XDR write without re-borrowing budget per leaf, then apply an exact batched `ValSer` charge by length bucket, preserving the same per-leaf cost totals while reducing budget-metering overhead.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) and inspect the longest `applyLedger` interval in the Tracy trace. Inside that single `applyLedger` window, `write xdr` appears 58,393 times for 495.803 ms of worker total, while the generic `charge` zone appears 8,204,892 times for 787.714 ms of worker total; the serialization calls occur under `invoke_host_function` / `SAC transfer` / event and host-object conversion paths, not TX-set construction.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:11-25` — `MeteredWrite::write` charges `ValSer` once per encoder write chunk before forwarding to the destination `Vec<u8>`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` constructs the metered writer for every host serialization.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates tracker state, charges CPU and memory dimensions, and checks both limits.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1301-1325` — `Budget::{bulk_charge,charge}` expose only identical-input bulk charging and single-input charging today.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — the linear cost model can compute exact repeated per-input costs; a batched-by-length helper can preserve current rounding by multiplying each `evaluate(1, Some(len))` by that length's count.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-248` — soroswap reaches the serialization-heavy paths through Wasm calls and repeated SAC transfers inside parallel apply.

## Evidence

- Tracy scope check: the cited `write xdr` and `charge` events are inside the longest `applyLedger` interval (`ledger/LedgerManagerImpl.cpp:1484`, 1,810.920 ms). The enclosing stack includes `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> `applySorobanStageClustersInParallel` -> `InvokeHostFunctionOpFrame doParallelApply` -> `invoke_host_function`.
- The local code performs one budget charge per `Write::write` call, not per logical serialized value. XDR serialization of nested `ScVal` maps/vectors and event payloads produces many short writes, so the fixed overhead of metering is amplified independently of the bytes being serialized.
- `Budget` already has a bulk-charge concept, but it assumes identical input values. A `ValSer`-specific histogram or a generic exact repeated-input helper can group identical write lengths and still charge `count * evaluate(1, Some(len))`, preserving today's per-leaf rounding and tracker totals.
- The expected win is materially larger than the rejected standalone `xdr_size(LedgerKey)` skip: this path accounts for hundreds of milliseconds of worker time in the current apply window and directly overlaps the soroswap host invocation critical path. Removing even 25-40 ms wall time from per-leaf metering overhead clears the 3% Medium threshold on the 620.996 ms baseline.

## Anti-Evidence

- Budget errors are protocol-visible. A PoC must preserve final CPU/memory totals exactly and avoid changing accepted/rejected outcomes for resource-limit-boundary transactions; grouping by total byte count alone is not enough because it would change the per-leaf constant term and possibly rounding.
- Current `MeteredWrite` fails before appending a chunk when the budget is exhausted. Deferring all charges until after serialization could do extra work before returning the same budget error and might change precedence if serialization itself fails; an implementation should either precompute exact charges cheaply, charge incrementally in coarse batches with the same error semantics, or explicitly prove that delayed failure is non-observable for this path.
- Tracy instrumentation inflates the apparent `charge` self-time in Tracy-enabled builds because `BudgetDimension::charge` emits a `charge` span for CPU charges. The production win must come from reduced budget bookkeeping and RefCell/model/tracker overhead, not merely from hiding profiler spans.
- Some `write xdr` time is real XDR encoding and vector growth, not budget charging. The hypothesis is Medium, not High, unless the PoC shows that the metering portion dominates serialization wall time on non-Tracy repeated runs.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transaction-ledger fail/success records

### Trace Summary

The soroswap benchmark builds one invoke-host-function transaction per swap and applies them through the protocol-26 parallel Soroban path inside `LedgerManagerImpl::applyLedger`. Each worker calls `InvokeHostFunctionOpFrame::doParallelApply`, crosses the C++/Rust bridge into `e2e_invoke::invoke_host_function`, and serializes the return value, changed ledger entries, and contract events before returning effects to Core. Those serializations all route through `metered_write_xdr`, whose `MeteredWrite::write` invokes `Budget::charge(ValSer, Some(buf.len()))` for every low-level XDR write chunk, so the claimed per-leaf budget-metering overhead is real and sits directly in the apply hot path.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1462-1491` — `applyLedger` is the profiled ledger-close apply window; it is the objective's hot path.
- `src/ledger/LedgerManagerImpl.cpp:2488-2511` and `src/ledger/LedgerManagerImpl.cpp:2531-2574` — each Soroban cluster is applied on worker threads, and each transaction calls `TransactionFrame::parallelApply`.
- `src/transactions/TransactionFrame.cpp:2386-2430` and `src/transactions/OperationFrame.cpp:175-188` — parallel Soroban transactions have one operation and dispatch to the operation's `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1359-1377` — invoke-host-function parallel apply calls `rust_bridge::invoke_host_function`, passing host function, resources, auth, ledger entries, TTL entries, PRNG seed, rent config, and module cache.
- `src/rust/src/soroban_invoke.rs:7-39`, `src/rust/src/soroban_proto_all.rs:95-129`, and `src/rust/src/soroban_proto_any.rs:408-459` — the Rust bridge selects the protocol host module, creates the budget from ledger cost parameters, invokes the p26 host, and exports consumed CPU/memory back to Core.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-508` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:874-889` — successful host invocation serializes the result `ScVal`, computes ledger changes that serialize keys/old/new entries, and serializes each emitted contract event.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:11-68` — `MeteredWrite::write` performs one `ValSer` budget charge per low-level write before forwarding to the destination, and `metered_write_xdr` wraps every host serialization with it.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284`, `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:157-187`, and `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — each charge updates trackers, charges CPU and memory dimensions, checks limits, and evaluates scaled linear cost models; Tracy `charge` spans are emitted for CPU charges when enabled.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1301-1325` and `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:146-161` — current `bulk_charge` can batch identical `(type, input)` calls but uses `evaluate(iterations, input)`, which is not bit-for-bit equivalent to repeated single charges when scaled linear rounding is involved.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225`, `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113`, and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:211-248` — SAC transfers used by soroswap record contract events that are externalized and later serialized by `encode_contract_events`.
- `src/simulation/ApplyLoad.cpp:3382-3505` — the soroswap generator creates invoke-contract swap transactions with source-account auth and SAC transfer sub-invocations, so this serialization work repeats per transaction in the benchmark shape.

### Findings

The inefficiency exists: `MeteredWrite::write` calls `Budget::charge` for every XDR encoder chunk, and each charge performs a `RefCell` mutable borrow, tracker lookup/update, CPU model charge, CPU limit check, memory model charge, and memory limit check. In Tracy builds, each CPU dimension charge also emits a generic `charge` span, explaining why the profile shows very high `charge` event counts nested under `write xdr`.

The path is hot for soroswap apply, not setup: the serializations happen after `Host::invoke_function` in `e2e_invoke::invoke_host_function` while Core is applying each transaction, and they include returned `ScVal`, changed ledger entries, and every successful contract event. The benchmark's generated swaps execute through the router and SAC transfer path and emit events, so the work scales with transaction count and is repeated across parallel apply workers.

There is no existing optimization that removes this overhead. `Budget::bulk_charge` is close but cannot be used naively for exact protocol preservation: `MeteredCostComponent::evaluate(iterations, Some(len))` shifts the scaled linear term after multiplying by `iterations`, whereas repeated current charges shift once per leaf. A correct implementation needs either a new exact repeated-single-input helper or a `ValSer`-specific batch path that computes and charges `count * evaluate(1, Some(len))` for CPU and memory while preserving tracker CPU/memory totals and resource-limit outcomes.

The projected impact plausibly meets the Medium floor. The provided trace attributes hundreds of milliseconds of worker-total time to `write xdr` inside the apply window and tens of milliseconds of recoverable wall time would clear the 3% objective threshold on the cited roughly 621 ms soroswap baseline. The hypothesis should remain Medium, not High, because some `write xdr` time is real encoding/vector work and Tracy instrumentation inflates the visible `charge` cost.

### PoC Guidance

- **Target code**: Modify `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs` and add the smallest needed internal helper in `src/rust/soroban/p26/soroban-env-host/src/budget.rs` / `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs`.
- **Change description**: Replace per-chunk immediate `ValSer` charging with a serialization-local histogram keyed by `buf.len()`, then perform exact batched accounting per length bucket. Do not use existing `Budget::bulk_charge(ValSer, count, Some(len))` unless the helper is changed to preserve repeated-single-charge rounding; the safe formula is `count * cost_model.evaluate(1, Some(len))` independently for CPU and memory, with tracker input/iteration fields reflecting the same logical leaves as today.
- **Correctness check**: Existing `budget_metering::metered_xdr` and `budget_metering::metered_xdr_out_of_budget` cover the basic `ValSer` path. Add a focused test that serializes a nested `ScVal` through old-style per-write accounting and the new batched path under fractional scaled linear terms, asserting identical bytes, CPU total, memory total, tracker input/iteration totals, and budget-limit success/failure at boundary values.
- **Benchmark focus**: Run the soroswap apply-load matrix for the same shape cited by the hypothesis (`soroswap`, around 4000 tx, 8 clusters/threads) and compare top-line apply time across repeated runs. The expected signal is a 3-6% apply-time reduction if per-leaf metering overhead, rather than real XDR encoding, is the dominant part of the `write xdr` zone.
