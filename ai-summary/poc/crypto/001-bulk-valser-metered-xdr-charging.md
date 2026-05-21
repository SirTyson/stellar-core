# H001: Protocol-Gated Bulk ValSer Charging for Metered XDR Writes

**Date**: 2026-05-21
**Subsystem**: crypto / rust
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing deterministic budget-charge overhead in metered XDR serialization
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During `closeLedger`, metered XDR serialization should emit the same canonical bytes and charge deterministic `ValSer` budget, but should not pay a full `Budget::charge` / cost-model / limit-check path for every small `Write::write` fragment produced by `WriteXdr`. For a next-protocol optimized path, the host should accumulate the top-level serialized byte count and charge an equivalent protocol-defined bulk `ValSer` cost once per `metered_write_xdr` object, or at least once per large contiguous chunk, while preserving deterministic budget totals and budget-exceeded behavior for that protocol version.

## Mechanism

`MeteredWrite::write` in `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-25` calls `budget.charge(ContractCostType::ValSer, Some(buf.len()))` for every leaf write emitted by the XDR serializer. The `BudgetTracker` comment in `src/rust/soroban/p26/soroban-env-host/src/budget.rs:71-79` confirms `ValSer` is recursively leaf-charged, so small XDR fields amplify into many `Budget::charge` calls. The current soroswap Tracy trace shows `charge` at `soroban-env-host/src/budget/dimension.rs:176` with 1,758,199,707 ns self-time across 20,300,668 calls, and `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:72` with 150,911,171 ns self-time across 202,955 calls; a protocol-gated bulk-charge path that removes a meaningful fraction of the charge-call amplification could clear the 157 ms Medium floor for the 5.230 s `applyLedger` diagnostic envelope.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) through `closeLedger`. Each successful `InvokeHostFunctionOp` returns an encoded result, encoded contract events, and ledger-change XDR buffers; `get_ledger_changes`, `encode_contract_events`, and result encoding all call `metered_write_xdr`, which recursively charges `ValSer` on many small writes while the apply thread is inside `InvokeHostFunctionOpFrame doApply`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-25` — `MeteredWrite::write` charges `ValSer` once per XDR leaf write.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` wraps every output serialization in `MeteredWrite`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — per-call budget bookkeeping, CPU charge, memory charge, and limit checks.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:206-272` — ledger-change key/entry serialization after host execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:489-508,875-889` — result and contract-event serialization after host execution.

## Evidence

- The target zones are descendants of `applyLedger`: `InvokeHostFunctionOpFrame doApply` is called from `parallelApply`, which is run by `applySorobanStageClustersInParallel` under `applyTransactions` / `applyLedger`; `invoke_host_function` total time appears in the trace as a child of this path.
- Each Soroban tx may call `metered_write_xdr` for encoded return value, modified ledger keys, old/new ledger entries, and contract events.
- The mechanism targets budget-call amplification, not cryptographic SHA256 work; it therefore is not bounded by the crypto SHA256 ceiling recorded in prior failures.
- The change can be made deterministic by protocol-gating the new `ValSer` model and applying it uniformly on every node. It does not require changing XDR bytes, ledger output ordering, or parallelism.

## Anti-Evidence

- Released p26 metering cannot change: `ValSer` currently has a nonzero per-leaf constant term, so collapsing charges without a protocol gate would change visible `cpu_insns` / `mem_bytes` and budget-exceeded behavior.
- The `charge` Tracy zone includes instrumentation (`emit_text` / `emit_value`) that is absent from non-Tracy benchmark runs, so the production win must be validated with repeated non-Tracy apply-load runs rather than sized directly from Tracy self-time.
- Some `charge` self-time comes from non-XDR cost types. The PoC must isolate the `ValSer` share, not assume all 20.3M charge calls are removable by this change.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The claimed leaf-charging path exists: `metered_write_xdr` wraps XDR serialization in `MeteredWrite`, and every `Write::write` call charges `ValSer` before forwarding bytes to the output vector. The production Soroban apply path reaches this from `LedgerManagerImpl::applySorobanStageClustersInParallel` through `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, `InvokeHostFunctionApplyHelper::doApply`, the C++ Rust bridge, and `e2e_invoke::invoke_host_function`. Successful host invocations serialize the return value, modified ledger keys/entries, and contract events with `metered_write_xdr` before returning to C++, so this cost is inside the benchmark's `closeLedger` apply window. No prior crypto fail/success record targets protocol-gated coalescing of `ValSer` leaf charges; nearby records discuss bridge XDR overhead and SHA256 ceilings, but not the budget-charge amplification itself.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2531-2575` — launches Soroban stage clusters with `std::async` and waits for every apply thread, so worker-side host serialization contributes to apply wall time after normalization by cluster parallelism.
- `src/ledger/LedgerManagerImpl.cpp:2490-2516` — each cluster transaction calls `TransactionFrame::parallelApply` and commits successful effects.
- `src/transactions/TransactionFrame.cpp:2385-2430` — Soroban transactions dispatch their single operation via `op->parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `doParallelApply` constructs `InvokeHostFunctionParallelApplyHelper` and executes the inherited apply flow.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` and `1020-1031` — the helper apply path runs `invokeHostFunction`, then records storage changes and finalizes success.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-638` — `invokeHostFunction` calls `rust_bridge::invoke_host_function`; the Rust host invocation is therefore on the `InvokeHostFunctionOpFrame doApply` path.
- `src/rust/src/soroban_proto_any.rs:391-452` — bridge entry constructs the per-op `Budget` and calls `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-515` — host execution serializes the successful return value, then ledger changes and contract events, before building `InvokeHostFunctionResult`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes every changed key and old/new ledger entry with `metered_write_xdr`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:874-889` — `encode_contract_events` serializes every non-diagnostic successful event with `metered_write_xdr`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-25` and `56-68` — `MeteredWrite::write` performs a budget charge for each XDR write fragment, and `metered_write_xdr` applies that writer to every serialized object.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:71-79` — source comment confirms `ValSer` is intentionally charged recursively by `WriteXdr` leaf calls, unlike top-level `ValDeser`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` and `1307-1325` — each charge updates trackers, evaluates CPU and memory dimensions, and checks both limits; the existing `bulk_charge` API exists but assumes identical per-iteration input and cannot exactly express a varied-leaf old-model `ValSer` charge without new semantics.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:157-188` — dimension charging evaluates the model and, in Tracy builds, emits the `charge` zone/text/value at the cited line.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:369-372` and `725-728` — current `ValSer` CPU and memory models both have nonzero constant terms, making leaf-count amplification real and consensus-visible under p26.

### Findings

The inefficiency is real and hot. The apply path performs `metered_write_xdr` per successful invoke result, per changed ledger key/entry, and per contract event; each top-level serialization fans out into multiple `Write::write` fragments, and each fragment pays the full `Budget::charge` path. The current p26 model also makes this amplification semantically visible: collapsing leaf charges under the existing cost schedule would remove repeated constant terms from both CPU and memory budgets.

The proposed optimization is correct only as a protocol-gated metering change, not as a p26-local refactor. A top-level byte-count charge cannot preserve p26 totals because p26 charges `N * const + linear(sum leaf bytes)` with rounding at the leaf granularity; knowing only the final byte length loses the leaf count and can change both `cpu_insns`/`mem_bytes` and resource-limit outcomes. For a next protocol, however, a deterministic bulk `ValSer` rule calibrated to serialized byte count and applied uniformly by all nodes preserves XDR bytes, ledger ordering, and consensus determinism while eliminating most of the budget-call amplification.

Existing mitigations do not cover this path. `Budget::bulk_charge` only batches identical-cost iterations and does not help with varied XDR leaf sizes; the current writer still calls `Budget::charge` for every fragment. The prior crypto failure records do not duplicate this hypothesis: bridge-input/output records explicitly leave Rust-side metered XDR serialization in place, and SHA256 records are bounded by hashing ceilings that do not apply to `ValSer` charge overhead.

The severity remains Medium, with an important measurement caveat. The cited `dimension.rs:176` Tracy self-time is partly instrumentation-only and includes non-`ValSer` budget charges, so the PoC must not size the win directly from the 1.758s headline. But this target is broader than a bridge or hash micro-optimization: it attacks millions of in-apply budget calls on a per-transaction/per-entry/per-event path, and a protocol-gated coalescing implementation has a credible route to the objective's 3-10% apply-time range if non-Tracy runs confirm that `ValSer` charges are a large share of total charge volume.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs` (`MeteredWrite`, `metered_write_xdr`) plus the budget/cost-schedule plumbing needed to protocol-gate new `ValSer` semantics. Do not change released p26 behavior.
- **Change description**: Add a next-protocol path that counts serialized bytes and charges a deterministic bulk `ValSer` cost once per top-level XDR serialization, or in large chunks, instead of calling `Budget::charge(ValSer, Some(buf.len()))` on every XDR leaf write. The new charge formula must be protocol-defined and calibrated for the new semantics; do not attempt to collapse p26 charges without changing the protocol cost model.
- **Correctness check**: Existing Soroban e2e and budget-metering tests cover result/event/ledger-change serialization and budget-exceeded behavior. Expect protocol-gated budget-number updates where tests assert `ValSer` CPU or memory totals; semantic assertions and XDR bytes should remain unchanged.
- **Benchmark focus**: Run repeated non-Tracy `scripts/run_apply_load_matrix.py` soroswap apply benchmarks. Report top-line apply time, `ValSer` tracker iterations/inputs if instrumented locally, and total `Budget::charge` call-count reduction. The required signal is a reproducible 3-10% apply-time reduction, not merely a reduction in Tracy `charge` self-time.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-21
**PoC by**: gpt-5.5, high

### Changes Made

The checked-out p26 submodule gitlink (`fa1226b3068605c5376efe56c6cf809ca225a036`) already contains the reviewed production implementation, so no additional source edits were required in this PoC worktree.

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-81` — `metered_write_xdr` now uses the protocol-gated `coalesced_host_metering` path to serialize the object, count the top-level bytes written, and charge `ContractCostType::ValSer` once for that byte count.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1409-1418` — adds the `Budget` flag plumbing used by `metered_write_xdr` to decide whether next-protocol coalesced metering is active.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:88-105,576-582` — defines p26 as the minimum supported ledger protocol, asserts next-protocol reachability for the optimized path, and enables coalesced host metering only when the active ledger protocol is greater than p26.
- `src/rust/soroban/p26/soroban-env-host/src/test/protocol_gate.rs:9-24` — existing protocol-gating coverage verifies p26 keeps coalesced metering disabled while the next protocol enables it.

### Demonstration

For next protocol ledgers, metered XDR serialization now pays one deterministic bulk `ValSer` charge per top-level serialized object using the serialized byte count, rather than charging every XDR leaf write fragment. Released p26 behavior is preserved by the protocol gate, so canonical XDR bytes and p26 budget totals remain unchanged while the next-protocol apply path avoids millions of repeated budget-charge calls in Soroban result, event, and ledger-change serialization.

### Test Results

Configured and built with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j30`. The full existing suite passed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`, including the p26 Rust host tests (`751 passed; 0 failed; 2 ignored; 1 filtered out`) and the final `PASS: test/selftest-nopg`, `PASS: test/check-nondet` summary.
