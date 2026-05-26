# H001: Batched Alternating Soroswap Cluster Execution

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: High
**Impact**: Soroswap apply-time reduction by amortizing per-transaction host invocation across deterministic same-pair swap clusters
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the apply-load Soroswap workload, transactions in a pair cluster should produce the same per-transaction result codes, events, refundable-fee accounting, trustline updates, pair balance changes, pair reserve updates, and metadata as today, in the same transaction order. The apply implementation should not need to pay a full C++→Rust host invocation, router VM entry, native pair frame setup, and output extraction cycle independently for every swap when a cluster is a deterministic sequence of homogeneous swaps against one pair.

The benchmark generator deliberately creates `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` pairs and round-robins swaps across them. Within each pair, swap direction alternates and amount-in is constant (`100`), so a cluster can be recognized as a same-pair ordered stream and evaluated by a protocol-gated batch executor that preserves the sequential state transition while amortizing fixed per-tx setup.

## Mechanism

`LedgerManagerImpl::applyThread` currently iterates each `TxBundle` and invokes `parallelApply` one transaction at a time. In the current Soroswap trace, `applySorobanStageClustersInParallel` is wholly inside `applyLedger` and consumes 2.718s total across 43 steady-state stage calls, while `parallelApply` / `InvokeHostFunctionOpFrame doParallelApply` total 11.58s across worker threads for 8,039 txs. That time is not launch overhead; it is the serial per-cluster worker execution that remains after previous native pair and direct-balance wins.

A batch executor for the exact apply-load two-token `swap_exact_tokens_for_tokens` shape could decode/validate a run of same-pair txs once, then perform the ordered reserve/balance recurrence in a tight native loop, emitting each tx's effects in tx-number order. This is different from prior direct-SAC-transfer or router-only precompile proposals: the win comes from amortizing the whole per-transaction host-invocation envelope across a recognized cluster, not from shaving a single SAC subcall or caching a VM artifact.

## Trigger

Run the current accepted Soroswap benchmark with `TX=2000, T=8`. The generated workload uses eight pairs, fixed amount-in, alternating direction per pair, and one Soroban component per ledger:

```sh
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
```

Confirm clusters contain same-pair runs by instrumenting `ApplyStage` construction or by checking each tx footprint's pair instance key. Then compare a batch executor against the current per-tx `applyThread` loop on the three authoritative non-Tracy runs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` applies every tx in a cluster sequentially and commits each successful tx independently.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` waits for cluster workers; Tracy self-time here is worker wait/critical-path time.
- `src/simulation/ApplyLoad.cpp:3382-3506` — benchmark Soroswap tx generation: round-robin pairs, alternating direction, constant input amount, and fixed two-token path/auth shape.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1340` — existing protocol-gated native pair swap semantics that a batch executor would need to call or mirror per transaction.

## Evidence

The source generator explicitly shapes the workload for pair-level independence and deterministic per-pair ordering: `pairIndex = i % numPairs`, `swapAForB = (mSoroswapSwapCounters[pairIndex] % 2 == 0)`, and `swapAmount = 100`. The trace shows the hot apply critical path is the per-cluster worker execution, not setup: `applySorobanStageClustersInParallel` totals 2.718s inside `applyLedger`; `parallelApply` totals 11.586s across worker threads; `InvokeHostFunctionOpFrame doParallelApply` totals 11.578s.

Prior failures rejected intra-cluster DAG scheduling because same-pair swaps genuinely conflict, and rejected single-subcall cleanups as sub-threshold after 8-way normalization. This hypothesis accepts the conflict and preserves ordered execution, but changes the execution granularity: a whole same-pair run becomes one deterministic native batch with per-tx outputs materialized in order. That targets a dominant worker envelope rather than a micro-slice.

## Anti-Evidence

A batch executor is only viable as a next-protocol native-contract feature with an explicit metering schedule. It must still emit per-tx events/meta/refunds, preserve source-account auth semantics, stop at the same first failing transaction if any swap fails, and avoid changing observable ordering. If equivalence requires re-entering the existing host for every tx to produce events/auth/refunds, the saving collapses to the previously rejected native-router/native-SAC surfaces.

---

## Review

**Verdict**: VIABLE
**Severity**: High
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The exact workload shape exists: `ApplyLoad::generateSoroswapSwaps` round-robins pairs, alternates direction per pair, uses constant amount-in, and declares the same router/pair/SAC footprint and source-account auth shape per swap. The apply path then bins conflicting same-pair transactions into ordered clusters and `LedgerManagerImpl::applyThread` invokes `TransactionFrame::parallelApply` once per `TxBundle`, committing each successful tx before the next tx in the cluster. Each tx pays the full `InvokeHostFunctionOpFrame` envelope: C++ footprint materialization, C++→Rust bridge, fresh Rust budget/storage/host construction, router Wasm entry, native pool/SAC calls, ledger-change/event extraction, C++ storage replay, refundable-fee accounting, and success-hash/meta construction. Existing native Soroswap pool paths only bypass selected pool Wasm calls after the host has already been entered for a single tx, so they do not amortize the dominant per-transaction host invocation envelope across a same-pair run.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3506` — constructs benchmark swaps with `pairIndex = i % numPairs`, alternating per-pair direction, fixed `swapAmount = 100`, two-token path, fixed router function, exact read-only/read-write footprint shape, and source-account auth for the router plus token-in transfer.
- `src/herder/ParallelTxSetBuilder.cpp:57-60,88-93,400-426,534-544` — transactions sharing a read-write footprint key become dependent clusters; final stage clusters may be capped bins, so a batch recognizer must verify the actual cluster/run shape rather than assuming every apply cluster is homogeneous.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — worker loop applies each `TxBundle` sequentially, flushes read-only TTL bumps, derives a per-tx PRNG seed from `txNum`, calls `parallelApply`, and commits successful tx changes into thread state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — stage execution waits for all cluster futures; worker runtime is on the `applyLedger` critical path.
- `src/transactions/TransactionFrame.cpp:2386-2454` — Soroban parallel apply skips already-failed txs, requires a single operation, calls the operation's `parallelApply`, and materializes per-tx ledger-change meta on success.
- `src/transactions/OperationFrame.cpp:175-188` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — operation parallel apply dispatches directly to `InvokeHostFunctionParallelApplyHelper::apply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-554,575-584,640-928,982-1017` — the helper serializes footprint entries and TTLs, calls `rust_bridge::invoke_host_function` once per tx, replays modified ledger entries, collects contract events, consumes refundable resources, and hashes return value plus events into the operation result.
- `src/rust/src/soroban_proto_any.rs:391-488` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-581` — the Rust bridge builds a fresh budget, storage footprint/map, host, auth entries, host function, ledger info, PRNG seed, and module cache attachment for each invocation, then encodes result, ledger changes, events, and rent fee back to C++.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825,1127-1375,1465-1528,2001-2026` — `Host::call_contract_fn` still enters router/pool execution per tx; native Soroswap pool swap validates the hash/schema, performs SAC transfer/balance calls, updates reserves, emits the pool swap event, and persists native frame instance storage when the frame pops.

### Findings

The inefficiency exists and is hot. The current worker loop is intentionally sequential within a dependent same-pair cluster, but the unit of execution is still a full Soroban transaction invocation. For the accepted `TX=2000, T=8` trace cited in the hypothesis, `InvokeHostFunctionOpFrame doParallelApply` accounts for 11.578s aggregate worker time across 8,039 txs; normalized by eight clusters and the 71-ledger window, the removable envelope is on the order of tens of milliseconds per ledger, large enough to clear the objective's Medium threshold and plausibly High if the batch path bypasses most router/host/extraction overhead.

The proposed change is distinct from the retained prior work. The fail/success set covers cross-stage ready-queue scheduling, hash-gated compiled/AOT VM backends, native pool raw instance storage, host metering coalescing, and footprint-key hash caching. Those either change scheduling, optimize one host-internal surface, or bypass selected pool Wasm calls per tx. This hypothesis instead changes the granularity of the exact same ordered same-pair stream from per-tx host invocation to a protocol-gated native batch executor that produces per-tx results.

The correctness bar is high but not inherently blocking. A viable PoC must not merely "validate once" globally: it must pattern-match every tx in the run, validate each tx's source account/auth/resource/footprint shape, apply each transaction's ledger effects in original `TxBundle::getTxNum()` order, and emit the same per-tx success hash inputs, events, return value, meta, refundable-fee consumption, and modified-entry set expected by C++ post-processing. Also note that `applyThread` does not stop the cluster on a failed transaction; the batch path must match that behavior by committing no failed-tx effects and continuing with the next tx unless the existing code would abort internally. For the all-success apply-load target, the fast path can conservatively fall back to the existing per-tx path for any mismatch or non-success case while still proving the performance claim on the intended workload.

### PoC Guidance

- **Target code**: Start at `src/ledger/LedgerManagerImpl.cpp::applyThread` or a helper it calls, with support code near `src/transactions/ParallelApplyStage.h` / `InvokeHostFunctionOpFrame.cpp` for extracting exact Soroswap swap shape and producing `ParallelTxSuccessVal` plus `OperationMetaBuilder` effects. The batch executor should be protocol-gated to the next protocol and hash/schema-gated to the known router/pair/SAC workload.
- **Change description**: Recognize contiguous same-pair `swap_exact_tokens_for_tokens` runs inside a cluster by checking host function, auth tree, fixed amount/path/deadline shape, footprint keys, pair instance key, token-in/out SAC keys, and tx order. Execute the ordered reserve/balance recurrence natively against `ThreadParallelApplyLedgerState`, updating each user's trustlines, pair SAC balances, pair reserves, TTL bumps, events, return value, success hash, rent/refundable fee, and meta per tx without entering `rust_bridge::invoke_host_function` for each transaction. Fall back to the current per-tx loop on any non-exact shape.
- **Correctness check**: Existing Soroban invoke/native-pool tests cover the underlying pool and SAC semantics; the PoC should add focused coverage only for the new recognizer/batch path and run the full suite at handoff. The fast path must preserve original tx-number order, per-tx PRNG seed derivation where relevant, rollback/no-commit behavior for failed txs, and diagnostic-event behavior or explicitly gate diagnostics off if existing protocol rules allow that.
- **Benchmark focus**: Measure three non-Tracy `scripts/run_apply_load_matrix.py` runs for `soroswap, TX=2000, T=8`, plus one diagnostic Tracy run. The top-line target is at least a reproducible 3% median apply-time reduction; Tracy should show reduced `InvokeHostFunctionOpFrame doParallelApply` / Rust `invoke_host_function` descendants for matched swap txs, not merely shifted time into C++ batch bookkeeping.
