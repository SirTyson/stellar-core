# H001: Bundled C++ Parallel-Apply Envelope Slimming

**Date**: 2026-05-24
**Subsystem**: transaction-ledger
**Severity**: Medium
**Impact**: soroswap apply-time reduction by aggregating several known sub-threshold C++ envelope costs around each Soroban invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the soroswap benchmark with metadata and Soroban metrics disabled, the C++ parallel-apply envelope should do only the consensus-visible work needed to invoke the host and commit the returned ledger effects. It should not repeatedly serialize immutable transaction inputs, construct disabled metadata/event scaffolding, perform per-tx metric registry lookups, or scan read-write footprint keys with work that can be pre-indexed once when building `TxBundle`.

The observable transaction result hash, refundable-fee accounting, event/meta behavior when meta is enabled, and deterministic ledger changes must remain identical.

## Mechanism

Prior failed records show several individual C++ envelope optimizations are each Low or sub-Low: precomputing host/resources/source/auth `CxxBuf`s, caching footprint XDR sizes/TTL keys for `recordStorageChanges`, skipping disabled `TransactionMetaBuilder` scaffolding, caching fee-event constants, and caching the operation timer reference. The deviation is that the current implementation pays all of these small costs independently on every soroswap transaction even though the benchmark's per-tx C++ envelope is on the critical worker path before and after `rust_bridge::invoke_host_function`.

A single cohesive "slim parallel Soroban envelope" refactor would thread immutable per-tx bridge payloads and a pre-indexed RW-footprint descriptor through `TxBundle`/`TxEffects`, use a no-op meta/event representation when `enableTxMeta == false`, and resolve the operation timer at `LedgerApplyMetrics` construction rather than through `MetricsRegistry::NewTimer` per tx. The theory is that the individually sub-threshold pieces can clear the 3% Medium floor when removed together without changing any Soroban host semantics.

## Trigger

Run `scripts/run_apply_load_matrix.py` for `soroswap, TX=2000, T=8` on the current native-hook baseline. Compare three non-Tracy runs before/after a bundled refactor that simultaneously removes the per-tx immutable `toCxxBuf` calls in `InvokeHostFunctionApplyHelper::invokeHostFunction`, the disabled-meta `TransactionMetaBuilder`/fee-event path in `applyParallelPhase`, the per-tx operation timer registry lookup, and the linear RW-footprint reclassification work in `recordStorageChanges`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` constructs `TxBundle`/`TxEffects`, disabled meta builders, and pre-apply fee events for every Soroban tx.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` runs the per-tx critical worker envelope and remains capped by the existing cluster count.
- `src/transactions/ParallelApplyStage.h:19-114` — `TxEffects`/`TxBundle` are the natural carriers for immutable precomputed bridge payload and no-meta fast-path state.
- `src/transactions/TransactionFrame.cpp:2414-2430` — `parallelApply` performs the per-tx operation timer lookup/scope and dispatches to operation apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — immutable `hostFunction`, `resources`, `sourceID`, auth entries, and PRNG seed are serialized into `CxxBuf`s per invocation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — `recordStorageChanges` reclassifies every returned modified entry against the RW footprint using a per-output linear scan.
- `src/transactions/TransactionMeta.cpp:924-1036` — disabled metadata builders and event managers should collapse to a cheaper no-op representation on the benchmark path.

## Evidence

- Existing trace-backed fail records size the individual pieces close to, but below, Medium: CxxBuf precompute alone was capped near ~2.5%, RW-footprint/TTL/XDR-size work near ~1-1.5%, disabled meta construction at ~0.5-1.7%, fee-event constant derivation at ~3.6 ms/ledger, and timer-registry lookup at ~1.0-1.5 ms/ledger.
- `ai-summary/fail/transaction-ledger/summary.md` Meta-Pattern 5 explicitly notes that these narrow transaction-ledger fixes are sub-threshold individually but that a combined approach touching multiple paths might reach Medium.
- The targeted functions are descendants of `applyLedger`: `applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> `applySorobanStageClustersInParallel` -> worker `parallelApply` -> `InvokeHostFunctionOpFrame doParallelApply`.

## Anti-Evidence

- This must be an actual bundled refactor, not another single-site micro-optimization; any component alone has already been rejected as sub-threshold.
- The no-meta path must not change behavior when metadata is enabled, and `TransactionResultSet` hashing must still observe the same per-tx result ordering.
- The RW-footprint descriptor must preserve exact create/update/delete classification and TTL-pair validation. A hash-map preindex that costs more than the current small linear scans would erase the combined gain.
- The expected win is borderline Medium; the hypothesis depends on additive savings surviving cache effects and three-run benchmark variance.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `001-bundled-cpp-apply-path-micro-optimizations.md` as condensed in `ai-summary/fail/transaction-ledger/summary.md`
**Failed At**: reviewer

### Trace Summary

The traced path matches the claimed C++ parallel-apply envelope: `applyParallelPhase` creates a `TxBundle` and `TxEffects` for each Soroban transaction, `applyThread` then invokes `TransactionFrame::parallelApply`, and `InvokeHostFunctionOpFrame` serializes bridge inputs, invokes the Rust host, and records returned storage changes. However, the prior fail corpus already contains the same bundled-C++ optimization class and rejected it because the Medium projection was an arithmetic sum of historical upper bounds rather than independent, still-present, removable costs on the current baseline. The current source confirms the individual operations are still small per-tx envelope pieces, not a new dominant phase distinct from the already-reviewed bundle.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:15,18,23,93,211` — records the relevant individual failures (`xdr_size`, CxxBuf precompute, disabled `TransactionMetaBuilder`) and the prior bundled-C++ apply-path rejection; Meta-Pattern 5 states these narrow fixes are sub-threshold individually.
- `ai-summary/success/transaction-ledger/001-bulk-build-host-storage-maps.md:47-91` — confirmed a broader host-storage setup optimization, but later notes show sub-3% measured effect, so it does not make residual C++ envelope bundling novel.
- `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md:49-95` — confirmed a Soroban-host/SAC optimization on a different path; it is not this C++ envelope bundle.
- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` constructs `TxBundle`/`TxEffects`, creates disabled-meta builders, and emits the fee event through the transaction meta builder path before parallel execution.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` processes each cluster transaction sequentially, scopes the transaction timer when metrics are enabled, flushes RO TTL bumps, calls `parallelApply`, and commits successful effects.
- `src/transactions/ParallelApplyStage.h:19-114` — `TxEffects` owns `TransactionMetaBuilder`, `LedgerTxnDelta`, and pre-apply info; `TxBundle` carries the transaction, result payload, tx number, and effects.
- `src/transactions/TransactionFrame.cpp:2414-2430` — `parallelApply` still performs the per-operation timer lookup/scope when metrics are enabled, obtains operation meta, and dispatches to `OperationFrame::parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,641-767` — each invoke serializes auth/host function/resources/source/PRNG inputs and then linearly scans RW footprint keys while recording returned modified entries.
- `src/transactions/TransactionMeta.cpp:924-1036` — disabled metadata still constructs the meta builder/event managers and operation meta builders, while heavy finalization remains gated by `mEnabled`.

### Why It Failed

This is not novel against the required fail/success corpus. The summary already records `001-bundled-cpp-apply-path-micro-optimizations.md` with the same core premise: stack C++ apply-path micro-optimizations into a single PoC to overcome the Medium threshold. That prior review rejected the bundle because it added historical upper bounds without proving independent additive savings on the current baseline, and because parts of the projected win were already addressed or bounded by narrower failures.

The present hypothesis is a renamed and slightly more specific version of that same bundle: CxxBuf precompute, disabled-meta/no-op meta scaffolding, timer lookup caching, and footprint/`recordStorageChanges` pre-indexing are the same class of residual C++ envelope micro-optimizations. Under the optimize-soroswap objective, Low/sub-Low components cannot be promoted by arithmetic aggregation unless the review can identify a new combined mechanism or dominant phase; the traced source shows ordinary per-tx bookkeeping around the host call, not a new mechanism beyond the prior failed bundle.

### Lesson Learned

For this objective, "bundle several rejected C++ envelope micro-optimizations" is already an investigated pattern. A future viable C++ apply-path hypothesis needs fresh direct measurements on the current baseline showing a single cohesive removable cost center above the Medium threshold, not a recombination of known sub-threshold CxxBuf, metadata, metric, and footprint bookkeeping costs.
