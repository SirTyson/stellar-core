# H002: Cluster-Level Native Batch Execution for Repeated Soroswap Pair Swaps

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: High
**Impact**: restructure the dominant soroswap parallel-apply worker phase by batching deterministic same-pair swaps within each conflict cluster
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within a Soroban apply cluster, transactions must be applied in the exact cluster order and must produce the same per-transaction result code, fee/refund accounting, contract events, diagnostic behavior, metadata, and final ledger state as executing each swap independently through `TransactionFrame::parallelApply`. If a cluster consists of the fixed apply-load soroswap shape for one pair, the worker should be able to execute the whole ordered run through a protocol-gated native batch that computes each swap sequentially and emits per-transaction effects in order, rather than paying full router/pair Wasm instantiation and interpretation for every transaction.

## Mechanism

The current `LedgerManagerImpl::applyThread` loop applies each `TxBundle` one at a time, and each successful tx enters `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge, builds a fresh host, instantiates router/pair Wasm, executes SAC transfers, records storage changes, then commits the tx delta to the thread state. Soroswap clusters are intentionally conflict-heavy: every tx in a cluster mutates the same pair reserves and pair SAC balances, so generic scheduling cannot add parallelism, but the conflict pattern is exactly what makes an ordered batch profitable. A native batch path keyed by the known router/pair code hashes, fixed two-token ABI, and same-pair cluster can load the pair reserves and relevant SAC balances once into a batch-local state, replay the exact constant-product formula (`get_amount_out`, pair `swap` K check, reserve update), emit each tx's SAC and router/pair events in order, and flush per-tx `TxEffects`/`ParallelTxReturnVal` objects back to the existing deterministic commit machinery.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`). `ApplyLoad::generateSoroswapSwaps` cycles transactions across configured pairs, and the retained failure summary confirms soroswap clusters contain true same-pair write conflicts rather than exploitable independent antichains. The batch path should trigger only when every tx in a `Cluster` has the known router code hash, known pair code hash, `swap_exact_tokens_for_tokens`, path length 2, source-account auth for the input SAC transfer, `amount_out_min=0`, and all read/write footprint keys matching the expected pair/SAC/user balance shape; otherwise the worker must use the existing per-tx path.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2484-2520` - `applyThread` currently applies txs in a cluster one by one and is the branch point for a whole-cluster batch executor.
- `src/ledger/LedgerManagerImpl.cpp:2531-2575` - `applySorobanStageClustersInParallel` already caps execution at one worker per cluster and preserves deterministic merge order; the batch must stay inside this `NUM_CLUSTERS` model.
- `src/transactions/ParallelApplyUtils.cpp:433-467` - pre-apply setup already validates and buffers per-tx read-only/signature work before worker execution.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` - current per-tx Rust bridge invocation and host input construction avoided or replaced for batchable swaps.
- `src/transactions/ParallelApplyUtils.cpp:724-923` - existing thread/global commit machinery that the batch should feed with ordered per-tx deltas instead of changing observable merge order.
- `src/simulation/ApplyLoad.cpp:3382-3505` - generator fixes the transaction ABI, pair footprint, SAC balance keys, and source-account auth tree.
- External semantic reference: `soroswap/core@bb90a655/contracts/router/src/lib.rs:577-620`, `contracts/library/src/quotes.rs:get_amount_out`, and `contracts/pair/src/lib.rs:swap/update` - swap math, reserve checks, event order, and storage keys.

## Evidence

The accepted trace shows the dominant measured apply work is the Soroban parallel worker phase: `applySorobanStageClustersInParallel` is 3,520,949,405 ns total across 43 stage calls, all contained in `applyLedger`, while worker-side `parallelApply`/`InvokeHostFunctionOpFrame doParallelApply` totals are about 12.66 s aggregate across 6,776 txs. VM zones inside those workers are also fully apply-contained: `Vm::invoke_function_raw` totals 12,842,366,133 ns across 20,313 calls, `call` totals 9,353,235,883 ns across 40,605 imports, and `SAC transfer` totals 2,153,411,257 ns across 13,527 calls. Since the prior cluster-scheduler failures established that same-pair conflicts prevent additional parallelism, reducing per-tx work inside each conflict cluster is the remaining high-leverage path.

This is distinct from the prior "debin" and conflict-DAG scheduler failures: it does not claim hidden independence inside a cluster. It is also narrower than a generic native Soroswap precompile because the batch trigger is the apply-load cluster shape and preserves tx order explicitly; the optimization opportunity is amortizing repeated host/VM setup and repeated reserve/balance reads across a serial run that must execute on one worker anyway.

## Anti-Evidence

This is a large next-protocol redesign, not a local cleanup. It must define exact router/pair/SAC event ordering, per-tx budget and refundable-fee accounting, auth matching, failure rollback boundaries, result-vector encoding, diagnostic behavior, and metering for the native batch; preserving per-tx failure isolation is especially hard if a later swap fails after earlier swaps in the batch succeeded. The candidate should first instrument cluster composition and per-pair run lengths in the current benchmark, and should be rejected if clusters are too short or if reproducing per-tx host output requires re-running enough generic host machinery that the amortized saving falls below the 10% High or 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL - duplicate/combination of `ai-summary/fail/soroban/summary.md:77` (`001-cluster-rust-invoke-batching`) and `ai-summary/fail/soroban/summary.md:109` (`001-protocol-gated-soroswap-native-router-pair`)
**Failed At**: reviewer

### Trace Summary

The source trace confirms the current worker loop executes a cluster in order, one `TxBundle` at a time, and each successful Soroban tx crosses into the Rust host with independent resources, auth entries, PRNG seed, budget, storage map, events, result, refundable fee accounting, and metadata output. `ApplyLoad::generateSoroswapSwaps` does generate the fixed two-token `swap_exact_tokens_for_tokens` shape with source-account auth and a repeated pair/SAC footprint, so the workload shape is real. However, the proposed native batch is not novel: it combines the already-rejected cluster-local invoke batching idea with the already-retained native router/pair bypass, and it inherits both blockers rather than resolving them.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:77` - prior cluster Rust invoke batching rejected because per-tx budgets, auth, events, PRNG seeds, metadata output, rollback semantics, and C++ commit interfaces require independent per-tx effects.
- `ai-summary/fail/soroban/summary.md:109,117,155` - prior native Soroswap router/pair and pool-only records already identify the known-hash native bypass as requiring a full next-protocol semantic and metering spec before PoC.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` - `applyThread` flushes per-tx RO TTL bumps, derives a per-tx PRNG sub-seed, calls `TransactionFrame::parallelApply`, and commits each successful `ParallelTxSuccessVal` before moving to the next cluster transaction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` - `applySorobanStageClustersInParallel` assigns one async worker per cluster and joins all workers before deterministic stage merge.
- `src/transactions/TransactionFrame.cpp:2385-2430` and `src/transactions/OperationFrame.cpp:175-188` - parallel apply assumes one Soroban operation per tx and dispatches that operation to its own `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,640-928,1358-1378` - each tx builds auth buffers, invokes the Rust host, validates modified ledger entries, collects events, consumes refundable resources, sets result hash/return value/meta, and returns a per-tx success value.
- `src/transactions/ParallelApplyUtils.cpp:431-467,1164-1252` - pre-apply and commit code are per `TxBundle`; successful host deltas are merged into thread state one transaction at a time and per-tx `TxEffects` deltas are derived from the tx-local modified-entry map.
- `src/rust/src/soroban_proto_any.rs:391-452` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` - Rust invocation constructs a per-tx `Budget`, enforcing footprint, cloned initial storage map, `Host`, auth manager, source account, ledger info, PRNG seed, module cache, result value, ledger changes, and encoded contract events.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-785,1124-1194` - top-level invoke converts args and dispatches through a contract frame; Wasm contracts instantiate `Vm`, while SAC transfers use the native SAC frame, both of which provide current-frame context for auth/events.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - SAC `transfer` performs auth, TTL extension, balance mutation, and transfer event emission that any native swap replay would have to reproduce exactly per transaction.
- `src/simulation/ApplyLoad.cpp:3382-3505` - confirms the fixed benchmark transaction ABI, footprint, alternating pair direction, and two-node source-account auth tree.

### Why It Failed

This is substantially equivalent to two retained failed investigations. The "batch through one cluster-local path" half repeats `001-cluster-rust-invoke-batching`: the C++ and Rust apply contracts require independent per-transaction state and outputs, so a batch cannot amortize budget/auth/rollback/result/meta machinery unless it reimplements those semantics itself. The "native replay router/pair math" half repeats `001-protocol-gated-soroswap-native-router-pair`: the hot VM path is known, but an allowlisted native Soroswap implementation still needs exact code hashes, ABI conversion, pair/router/SAC storage schema, event order, auth matching, recoverable error/trap mapping, return-value encoding, fee/refund accounting, and a next-protocol metering schedule.

The batching wrapper does not make the native bypass novel or solve the missing specification. It narrows the trigger to same-pair clusters, but the existing failure summary explicitly warns that narrower benchmark triggers are insufficient without a complete native-contract semantic and metering spec. If the implementation preserves per-tx observability by running enough generic host machinery, the claimed amortization disappears; if it bypasses that machinery, it becomes the same under-specified native router/pair precompile already rejected before PoC.

### Lesson Learned

For Soroswap-native ideas, first resolve the retained router/pair semantic and metering specification, then measure isolated code-hash-specific cost after cluster normalization. Adding a cluster-level batch wrapper around an under-specified native bypass is not a new finding; it inherits the prior per-tx isolation and native-equivalence blockers.
