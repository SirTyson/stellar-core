# H002: Positional native Soroswap pool instance frame

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Soroban native Soroswap apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing repeated native pool instance `ScMap` scans and full-map reserve cloning with a typed positional frame
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a native Soroswap pool call is accepted, the host should decode the pool instance storage layout once into a deterministic typed frame containing token addresses, reserves, and the positions of the storage slots that must be written back. The swap body should then read and update those typed fields directly and materialize the final canonical `ScMap` once, preserving the same ledger entry, event, error-code, and auth semantics as the current native pool swap.

## Mechanism

The current native pair path retains the pool instance as a generic `ScMap`. `match_native_soroswap_pool_swap` first performs multiple linear key probes to validate keys 0 through 3, then `call_native_soroswap_pool_swap` re-reads the same keys through `soroswap_pool_required_native_i128` / `soroswap_pool_required_native_scaddress`, and `soroswap_pool_reserves_updated_scmap` scans and metered-clones every instance-storage entry to update only reserve keys 2 and 3. A positional native frame would do one sorted-layout validation, carry direct typed values/indices through the swap, and rebuild only the changed reserve values in canonical order, reducing repeated `ScMap` traversal and host-object/`ScVal` conversion work on every native swap.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with next-protocol native Soroswap pool hooks enabled. Each router swap reaches `match_native_soroswap_pool_swap`, enters `Frame::NativeContract`, reads token/reserve fields from instance storage, invokes one output SAC transfer, reads balances, updates reserves, and records the native pair swap event.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — native pool swap matcher repeatedly probes the instance `ScMap` to validate token and reserve keys.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1252` — native pool swap body re-fetches reserves and token addresses from the same instance storage before invoking SAC helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1333-1375` — reserve update and event emission after the swap.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1378-1448` — `soroswap_pool_reserves_updated_scmap` scans and clones the full instance-storage map to replace two reserve entries.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:901-1089` — generic helper probes used for native pool instance key lookup.

## Evidence

- The current trace confirms the native swap path is inside `applyLedger`: timestamp-filtered `InvokeHostFunctionOpFrame doParallelApply` has 8,013 calls / 11,549.175 ms inside `applyLedger` windows, and the native pool swap is reached from those invocations.
- The same apply windows still contain large generic map/conversion categories: `map lookup` totals 1,273.252 ms, `new map` totals 458.269 ms, `ScVal to Val` totals 884.241 ms, `Val to ScVal` totals 347.177 ms, and `Compare<HostObject>` totals 266.812 ms. Not all of this is native-pool instance work, but the current source has a concrete repeated-scan/full-clone pattern in the native pair path that contributes once per pool swap.
- The current matcher/body/update sequence reuses the same fixed Soroswap pool layout keys repeatedly. For the optimized benchmark's next-protocol native path, a single typed `NativeSoroswapPoolFrame` can validate and preserve the canonical layout once, then update reserve slots deterministically without changing transaction ordering or exceeding `NUM_CLUSTERS` parallelism.
- The change targets a different seam from event-only or balance-only optimizations: it carries the native pool instance representation through the whole matched native frame, including matcher, body, and reserve writeback.

## Anti-Evidence

- Broad map/conversion Tracy totals include many unrelated host operations. A PoC must add narrow spans around native pool instance matching, field extraction, and reserve writeback before claiming the full category reduction.
- The typed frame must preserve exact metering or be protocol-gated. Skipping `metered_clone`, comparison, or map-construction charges in released p26 would change visible resource counters and budget-exceeded behavior.
- The instance storage layout is consensus-critical. The frame must reject noncanonical, missing, or duplicate pool storage exactly as the current fallback path does, and must fall back to Wasm for any shape that is not the recognized official Soroswap pool layout.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `002-typed-native-pair-swap-frame.md` (and overlaps `002-invocation-scoped-soroswap-pool-view-cache.md`)
**Failed At**: reviewer

### Trace Summary

The native Soroswap swap hook is on the `closeLedger` apply path through `InvokeHostFunctionOpFrame::doParallelApply`, the Rust bridge, `e2e_invoke::invoke_host_function`, and `Host::call_contract_fn`. The local inefficiency exists: the matcher linearly probes the raw instance `ScMap`, the swap body re-reads the same reserve/token slots, and reserve writeback clones every `ScMapEntry` to replace keys 2 and 3. However this is substantially the same pair-local typed-frame/cache family already condensed as `002-typed-native-pair-swap-frame.md`, whose normalized best-case ceiling was ~1.06 ms/ledger (~0.5% of the 218 ms baseline), far below this objective's required Medium threshold.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:189` — prior `002-typed-native-pair-swap-frame.md` review rejected the same native-pair typed-frame idea as below threshold after correct 8-cluster normalization.
- `ai-summary/fail/transaction-ledger/summary.md:164` — prior invocation-scoped pool view cache review rejected repeated native pool instance reads as sub-threshold and warned against projecting from broad host map/conversion totals.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — Soroban clusters run via `std::async` and the apply thread waits on worker futures, so aggregate worker Tracy time must be normalized by the active cluster count.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1358-1377` — protocol 23+ Soroban transactions enter Rust host execution through `doParallelApply` and `rust_bridge::invoke_host_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-556` — each invocation builds the enforcing host and calls `Host::invoke_function` inside the apply worker.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-824` — `call_contract_fn` retrieves the contract instance, recognizes native Soroswap pool getter/swap calls, pushes `Frame::NativeContract`, or falls back to Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:901-917,1005-1095` — native pool helpers search raw instance `ScMap` entries by immediate `U32` keys and convert/cloned typed values for addresses and reserves.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — `match_native_soroswap_pool_swap` validates fixed pool layout keys 0, 1, 2, and 3 with repeated `ScMap` probes before accepting the native path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — accepted native swaps re-read reserves/tokens, perform mandatory SAC transfer/balance calls, update reserves, and emit the pair swap event.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1378-1448` — reserve update on a native frame rebuilds instance storage by scanning and `metered_clone`ing the whole `ScMap`, then replacing reserve values for keys 2 and 3.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1528` — SAC transfer and direct SAC balance-read work remains mandatory child work around the pair-local instance handling.

### Why It Failed

This hypothesis is not novel: it rephrases the previously investigated typed native pair swap frame / pool view cache seam, now focusing on positional reserve slots and writeback. The specific repeated scans and full-map reserve clone are real, but the prior review already sized this pair-local residual after native pair swap and direct SAC balance reads; once broad map/conversion categories are filtered to the native-pool instance portion and divided across `NUM_CLUSTERS=8`, the best-case savings are well below 3% apply-time reduction. Under the optimize-soroswap objective, Low/sub-1% findings must be rejected rather than accepted with downgraded severity.

### Lesson Learned

Native Soroswap hook refinements must not attribute broad `map lookup`, `new map`, `ScVal to Val`, or `Val to ScVal` totals to the pool instance frame. Pair-local instance optimizations need narrow spans around matcher probes, reserve/token reads, and reserve writeback; absent a new dominant seam, this family remains below the objective's Medium floor.
