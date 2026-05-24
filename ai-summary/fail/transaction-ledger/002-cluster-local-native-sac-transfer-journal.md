# H002: Cluster-local native SAC transfer journal for Soroswap pair output legs

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / Soroban native SAC and Soroswap apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating repeated external SAC child-call dispatch inside native pair swaps
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the native Soroswap pool swap path performs the output-token transfer from the pair contract to the recipient, the ledger effects should be identical to a Stellar Asset Contract `transfer(pair, to, amount)`: authorization must be checked for the pair address in the same semantic frame, balances and authorization flags must update identically, TTL extensions and events must be emitted identically, and failures must roll back only the current transaction.

The efficient native path should not re-enter the generic external-call machinery for each transfer when the caller is already inside the allowlisted native Soroswap pair swap and the target token is known to be a native SAC contract. It should use a per-cluster typed SAC transfer journal that preserves ordered per-tx semantics while carrying the hot pair/user balance slots and TTL state between transactions in the same cluster.

## Mechanism

`call_native_soroswap_pool_swap` currently invokes SAC transfers through `soroswap_pool_invoke_sac_transfer`, which constructs the amount symbol/argument values and calls `call_n_internal` back into the generic contract-call path. That path creates another frame, dispatches the generated SAC function wrapper, performs generic argument conversion, and then reaches typed SAC balance helpers. For soroswap clusters this happens in the same worker, against the same pair contract and token contracts, with strongly typed `ContractId`, `AddressObject`, and `i128` values already available.

A cluster-local typed SAC journal can provide a synthetic SAC-equivalent transfer frame: record the same auth invocation shape, execute the existing typed SAC balance read/write/event logic directly, and preserve one transaction-local rollback boundary while keeping hot pair/user balance entries in typed journal slots until the transaction commits to `ThreadParallelApplyLedgerState`. This removes the external `call_n_internal` dispatch and repeated balance-slot rediscovery without changing transaction order or exceeding `NUM_CLUSTERS` parallelism.

## Trigger

Run the current native Soroswap benchmark with swaps that produce either `amount_0_out > 0` or `amount_1_out > 0`. Each successful native pair swap calls `soroswap_pool_invoke_sac_transfer` for the output leg, then reads the post-transfer SAC balances to compute `amount_in` and the K-invariant. Clusters with many swaps against the same pair repeatedly hit the same pair-side SAC balance slots.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — native pair swap validates reserves, invokes output SAC transfer(s), then reads post-transfer balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1346` — `soroswap_pool_invoke_sac_transfer` currently re-enters generic `call_n_internal` for SAC `transfer`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1392` — direct SAC balance read helper already proves native pair code can safely inspect SAC contract balance state for known `StellarAsset` contracts.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC transfer body whose authorization, spend, receive, and event behavior must be reproduced through a synthetic frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs` — accepted typed SAC balance storage helpers to reuse rather than routing through generated `Val`/`ScVal` storage APIs.

## Evidence

- The relevant zones are apply descendants: the C++ path reaches `InvokeHostFunctionOpFrame doParallelApply@transactions/InvokeHostFunctionOpFrame.cpp:1367` under `applySorobanStageClustersInParallel@ledger/LedgerManagerImpl.cpp:2537`.
- Current Tracy shows `SAC transfer@soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` totals 2.602s over 16,738 calls, with 668.8ms self-time. This is inside the worker invoke path, not transaction-set construction.
- The generic VM/host call envelope around these transfers is still large: `call@soroban-env-host/src/vm/dispatch.rs:304` totals 4.871s over 25,183 calls, `push context@host/frame.rs:223` totals 479.3ms over 50,389 calls, `push auth frame@auth.rs:1345` totals 355.8ms, and `require auth@auth.rs:835` totals 142.9ms. A native SAC transfer journal targets this external child-call envelope plus repeated balance-slot discovery while retaining the required auth/event/storage semantics.
- The source already contains two prerequisites that earlier rejected variants lacked or did not combine: native Soroswap pair swap dispatch (`try_call_native_soroswap_pool_swap`) and direct typed SAC balance reads (`soroswap_pool_read_sac_contract_balance`, backed by typed SAC balance storage helpers). The remaining external transfer call is therefore a concrete seam.

## Anti-Evidence

- A prior direct native SAC transfer idea failed because auth-frame semantics are required: the transaction must authorize `token.transfer(pair, to, amount)`, not merely the outer `pair.swap(...)`. This hypothesis is viable only if the synthetic frame records and checks exactly the SAC transfer auth shape and preserves diagnostics.
- Much of SAC transfer is mandatory ledger work: TTL extension, balance mutation, authorization flags, and transfer event emission cannot be elided. The expected win is the generic external-call/frame/conversion envelope and repeated slot lookup, not the transfer semantics themselves.
- The journal must be transaction-scoped even if its storage slots are cluster-local. A failed transaction must discard its tentative SAC mutations before the next tx in the same cluster observes state, matching the existing per-tx `TxParallelApplyLedgerState` commit behavior.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate/subset of `001-direct-native-sac-transfer-for-pair-swap.md`, `001-fused-sac-transfer-fast-lane.md`, and `002-sac-transfer-balance-slot-context.md` as condensed in `ai-summary/fail/transaction-ledger/summary.md`
**Failed At**: reviewer

### Trace Summary

The traced apply path is `LedgerManagerImpl::applyThread` -> `TransactionFrame::parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply` -> Rust `invoke_host_function` -> native Soroswap pair swap. Inside the native pair swap, output legs still call `soroswap_pool_invoke_sac_transfer`, which enters `call_n_internal`, dispatches the SAC `transfer` frame, runs `from.require_auth()`, extends instance/code TTL, mutates balances, and emits the transfer event. The proposed synthetic frame and journal are exactly the follow-on shape identified in prior failed SAC-transfer reviews: preserving auth, rollback, TTL, event, diagnostics, storage, and per-tx commit semantics leaves only the already-reviewed residual child-call/bookkeeping slice, while the cluster-local balance-slot context overlaps the prior rejected transfer-local context.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:86` — prior `002-sac-transfer-balance-slot-context.md` reached final review and was rejected after reusing SAC balance-slot context regressed soroswap and barely moved max-sac.
- `ai-summary/fail/transaction-ledger/summary.md:108` — prior `001-fused-sac-transfer-fast-lane.md` rejected the remaining SAC transfer fast lane after typed SAC balance storage because auth-frame construction, storage reads/writes, TTL, diagnostics, and event externalization remain mandatory.
- `ai-summary/fail/transaction-ledger/summary.md:190` — prior `001-direct-native-sac-transfer-for-pair-swap.md` identified the same seam and concluded a correct implementation requires a synthetic SAC-equivalent auth frame; inclusive SAC transfer time is not removable dispatch overhead.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — each cluster worker still applies each transaction in order, flushes tx-scoped RO TTL bumps, and only commits successful `ParallelTxSuccessVal` changes before moving to the next tx.
- `src/transactions/TransactionFrame.cpp:2385-2454` — `parallelApply` preserves the per-transaction operation result, metadata builder, success gate, and ledger-change recording boundary.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:537-585,982-1017,1358-1377` — each Soroban transaction constructs auth/footprint/resource inputs, invokes the Rust host, records storage changes/events, consumes refundable resources, and finalizes the success hash.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-580` — Rust host invocation builds per-tx storage/auth/host state, invokes the host function, finishes the host, and extracts ledger changes/events.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-838,1013-1176,1330-1393` — native Soroswap pair swap exists and uses direct SAC balance reads for known SAC contract balances, but output transfers still require a SAC contract call frame and then the same typed SAC transfer semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1531-1729` — `call_n_internal` performs external-call validation, reentry checks, diagnostics, and dispatches to `call_contract_fn`; bypassing it must still recreate the SAC call frame for auth and rollback semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:219-237,434-630` — `with_frame`/`push_context` create rollback points covering storage, events, and auth; this is required for failed child-call rollback.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3614-3658` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-849,1144-1220,1336-1370` — `require_auth()` derives the authorized invocation from the current `Frame`; a correct SAC transfer must push a `Frame::StellarAssetContract` or equivalent carrying `token.transfer(pair, to, amount)`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` and `balance.rs:303-427,431-448` — SAC transfer still checks nonnegative amount and authorization, extends TTL, reads/writes balance state, preserves authorization flags, and emits the SAC transfer event.

### Why It Failed

This is not novel against the prior fail/success corpus. The "synthetic SAC-equivalent frame" is the exact requirement recorded by the direct native SAC transfer failure, and the proposed journaled balance-slot reuse is covered by the transfer-local balance context that already failed final review. The trace also confirms the remaining work after the accepted typed SAC balance storage fast path is consensus-visible and per-transaction: auth frame matching, rollback snapshots, TTL extension, balance mutation, diagnostics/events, refundable-resource accounting, metadata, and ordered `ThreadParallelApplyLedgerState` commits.

Because the prior fused fast-lane and balance-context attempts already covered the removable slice and failed the objective's Medium threshold, reframing the same mechanism as cluster-local does not create a viable optimization. Any implementation that skips the mandatory SAC frame/storage/event work would change authorization or metadata semantics; any implementation that preserves them reduces to the previously investigated below-threshold/residual fast lane.

### Lesson Learned

After native pair hooks and typed SAC balance storage, SAC output-leg optimizations must be justified with a new isolated cost center, not inclusive `SAC transfer` or broad dispatch-frame timings. A correct direct transfer path still needs the SAC auth frame and per-tx rollback/event/storage boundaries, and balance-slot journaling for this path has already been measured as non-beneficial for the soroswap objective.
