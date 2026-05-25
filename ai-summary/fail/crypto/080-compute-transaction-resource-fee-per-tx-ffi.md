# H080: Per-Transaction `compute_transaction_resource_fee` Rust-FFI Hop In Pre-Apply Is Sub-Threshold

**Date**: 2026-05-25
**Subsystem**: crypto / rust
**Severity**: Low
**Impact**: per-tx Rust-bridge fee-computation FFI dispatch on the apply path

**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For every Soroban transaction applied during `closeLedger`, the `commonPreApply` / `commonParallelPreApplyReadOnly` path must compute the pre-apply non-refundable resource fee from the declared `SorobanResources`. The computation is pure integer arithmetic over a fixed `CxxTransactionResources` struct (instructions, disk_read_entries, write_entries, disk_read_bytes, write_bytes, transaction_size_bytes, contract_events_size_bytes) and a per-ledger-cached `CxxFeeConfiguration`. A viable optimization would replace the Rust-FFI hop with an equivalent C++ implementation only if the per-tx FFI overhead represented Medium-tier wall-clock apply time. Output (`FeePair`) must be identical and protocol-versioned dispatch must remain correct.

## Mechanism

`TransactionFrame::computePreApplySorobanResourceFee` (`src/transactions/TransactionFrame.cpp:1205-1219`) is called per Soroban transaction during apply via `commonPreApply` (line 1936), the serial `commonPreApplyClassicAndReadWrite` path (line 2109), and `commonParallelPreApplyReadOnly` (line 2174). It calls `TransactionFrame::computeSorobanResourceFee` (line 1158-1195) which constructs `CxxTransactionResources`, then calls into `rust_bridge::compute_transaction_resource_fee`. The Rust side (`src/rust/src/soroban_invoke.rs`) dispatches via `get_host_module_for_protocol` (linear scan over `HOST_MODULES`) and runs the per-protocol soroban-env-host fee arithmetic.

For soroswap (2000 tx/ledger × 65 ledgers = ~130k FFI calls), the candidate optimization would inline the fee math in C++ to avoid the per-tx cxx round-trip and the linear `HOST_MODULES` scan. The deviation from expected Medium impact is that this work runs almost entirely inside `commonParallelPreApplyReadOnly` worker threads, and the per-call cost is single-digit microseconds — too small even before parallelism normalization.

## Trigger

Run the protocol-27 soroswap apply-load benchmark and timestamp-filter the `computeSorobanResourceFee` Tracy zone (and its descendant FFI call) against `applyLedger`. The path fires once per Soroban tx pre-apply (and at least once more per refund computation in `RefundableFeeTracker::consumeRentFee` if reached), distributed across the 8 parallel worker clusters.

## Target Code

- `src/transactions/TransactionFrame.cpp:1158-1195` — `computeSorobanResourceFee` builds `CxxTransactionResources` and calls the Rust bridge.
- `src/transactions/TransactionFrame.cpp:1205-1219` — `computePreApplySorobanResourceFee` per-tx entry point.
- `src/transactions/TransactionFrame.cpp:2109,2174` — apply-path serial / parallel pre-apply call sites.
- `src/transactions/MutableTransactionResult.cpp:61-67` — `RefundableFeeTracker::consumeRentFee` post-op recompute call site.
- `src/rust/src/soroban_invoke.rs` — `compute_transaction_resource_fee` FFI entry; dispatches through `get_host_module_for_protocol`.
- `src/rust/src/soroban_proto_all.rs:1143-1175` — `HOST_MODULES` array and `compute_transaction_resource_fee` function-pointer slot.

## Evidence

The path is genuinely on the apply critical path and crosses cxx per-tx. The FFI surface includes function-pointer dispatch and `CxxTransactionResources` marshaling on each call. The `rustBridgeFeeConfiguration` argument is already cached per H071, but the resources struct is freshly built each invocation.

## Anti-Evidence

The per-call cost is structurally tiny. `compute_transaction_resource_fee`'s body is pure integer arithmetic over a small struct; the cxx-generated thunk plus a 5–6 entry linear scan in `get_host_module_for_protocol` is bounded by ~0.5–1 µs per call on modern x86. For 2000 tx/ledger:

- Aggregate per-ledger worker time ≈ 2000 × 0.75 µs = 1.5 ms aggregate.
- Wall-clock (8-way parallel pre-apply per Meta-Pattern 12) ≈ 0.19 ms / ledger.
- 0.19 ms / 207.6 ms baseline ≈ **0.09% of apply** — well below the 1% Low floor and far below the 3% Medium floor.

This is also bounded by Meta-Pattern 8 (~50 ms FFI bridge ceiling across the whole trace) and Meta-Pattern 12 (NUM_CLUSTERS = 8 parallel normalization). The path additionally cannot be removed: protocol-versioned dispatch is required for correctness, and the C++-side `CxxTransactionResources` construction (a stack-allocated POD) is not the bottleneck.

`RefundableFeeTracker::consumeRentFee` runs post-op on InvokeHostFunctionOp success and is similarly bounded — at most one additional call per soroban operation, still inside parallel apply workers.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — `compute_transaction_resource_fee` per-tx FFI in `commonPreApply`/`commonParallelPreApplyReadOnly` was not separately recorded. Closest priors are H037 (cost-param decode, addressed by `getCachedLedgerInfo`), H070 (HostModule dispatch cache), and H071 (CxxFeeConfiguration caching), none of which target the per-tx fee FFI hop.

### Why It Failed

The per-tx Rust-FFI fee computation runs on parallel pre-apply workers; aggregate per-ledger cost is ~1.5 ms aggregate (~0.19 ms wall-clock after 8-way parallelism), structurally below the 1% Low floor on the 207.6 ms soroswap baseline. The path is further bounded by Meta-Patterns 8 (FFI bridge ceiling) and 12 (parallel-worker normalization). Inlining the fee arithmetic in C++ would preserve correctness but cannot move the headline metric.

### Lesson Learned

Per-tx FFI hops on the apply path that perform only small integer arithmetic in Rust are bounded by Meta-Pattern 8 even when call counts approach 10⁵ per ledger. Combine with Meta-Pattern 12 normalization for any pre-apply work that runs inside `commonParallelPreApplyReadOnly`. Before proposing FFI inlining, multiply realistic per-call FFI overhead (~0.5–1 µs) by `per_ledger_calls / NUM_CLUSTERS` and reject up-front if the product is below the 1% Low floor.
