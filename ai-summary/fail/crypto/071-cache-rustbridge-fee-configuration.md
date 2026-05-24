# H071: Cache `CxxFeeConfiguration` in `SorobanNetworkConfig` instead of rebuilding per pre-apply Soroban tx

**Date**: 2026-05-24
**Subsystem**: rust (FFI bridge inputs) + crypto-adjacent
**Severity**: Low (below objective floor)
**Impact**: per-tx struct rebuild + FFI marshalling overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`SorobanNetworkConfig::rustBridgeFeeConfiguration(uint32_t ledgerVersion)`
(`src/ledger/NetworkConfig.cpp:2848-2869`) rebuilds an 8-field
`CxxFeeConfiguration` struct on every invocation. Because the network config
and ledger protocol version are invariant for the duration of a ledger close,
this struct should be computed once per `(NetworkConfig epoch, protocolVersion)`
pair and reused for every `computePreApplySorobanResourceFee` call within the
ledger. The deviation is that the struct is rebuilt for each Soroban tx
(`computePreApplySorobanResourceFee` is called once per Soroban tx — in
`TransactionFrame::commonPreApply` and `commonParallelPreApplyReadOnly`,
lines 1936/2109/2174).

## Mechanism

For a soroswap ledger of ~2000 Soroban txs:
1. `computePreApplySorobanResourceFee` is called once per tx (one of the three
   call sites listed above).
2. Each call invokes `sorobanConfig.rustBridgeFeeConfiguration(protocolVersion)`,
   constructing a fresh `CxxFeeConfiguration` POD with 8 `int64_t` fields by
   reading 8 `SorobanNetworkConfig` member accessors plus one protocol-version
   branch.
3. The struct is then passed by value across the cxx bridge to
   `rust_bridge::compute_transaction_resource_fee`, which is a `Result<FeePair>`
   FFI call.

A cache (e.g., a `mutable std::optional<CxxFeeConfiguration>` on
`SorobanNetworkConfig`, invalidated whenever the upgrade ledger applies a
network-config change, plus a protocol-version key) would replace the
per-tx rebuild with a single load.

## Trigger

Standard soroswap workload at p26: ~2000 Soroban txs/ledger × 65 ledgers
≈ 130K `rustBridgeFeeConfiguration` invocations and matching
`compute_transaction_resource_fee` FFI calls.

## Target Code

- `src/ledger/NetworkConfig.cpp:2848-2869` — `rustBridgeFeeConfiguration`
  struct builder
- `src/transactions/TransactionFrame.cpp:1192-1194` — FFI call site
- `src/transactions/TransactionFrame.cpp:1936,2109,2174` — three callers of
  `computePreApplySorobanResourceFee`

## Evidence

- 8 inline member reads + 1 branch per call: roughly 5–10 ns in optimized
  builds.
- 130K calls per soroswap run ≈ 0.65–1.3 ms aggregate just for the struct
  build (excluding the FFI call itself).
- The cxx-generated wrapper for `compute_transaction_resource_fee` performs
  exception-translation prelude + Rust dispatch on every call.

## Anti-Evidence

- Meta-Pattern 8 caps the entire FFI bridge input-marshalling surface at
  ~22 ms aggregate across the soroswap trace; the per-tx fee-config rebuild
  is a tiny subset of that.
- Meta-Pattern 12 (8× parallel-worker normalization): the pre-apply fee
  computation runs inside worker threads (`commonParallelPreApplyReadOnly`),
  so aggregate-thread time must be divided by 8 for wall-clock impact. A
  1.3 ms aggregate becomes ~160 µs wall-clock per run — three µs per ledger,
  five orders of magnitude below the 6.5 ms/ledger Medium floor.
- The FFI call cost itself (Rust-side dispatch + actual fee computation) is
  not eliminated by this change; only the C++-side struct construction is
  amortized. Realistic savings are a small fraction of the already
  sub-threshold aggregate.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H037 (`getCachedLedgerInfo` cost-params
caching, which targets `invoke_host_function` inputs) and H038 (per-tx
`SorobanResources` pre-encode). H037 caches `CxxLedgerInfo` (ledger info +
cost params) per-ledger per-thread; the fee-configuration struct on the
`rust_bridge::compute_transaction_resource_fee` path has not been previously
investigated.

### Why It Failed

Bounded by Meta-Pattern 8 (FFI input bridge ~22 ms aggregate) and Meta-Pattern
12 (8× parallel-worker normalization). The struct rebuild is genuinely
redundant within a ledger, but the absolute cost is single-digit µs per ledger
after normalization — five orders of magnitude below the Medium floor. The
FFI call itself dominates and cannot be eliminated by C++-side caching.

### Lesson Learned

`SorobanNetworkConfig::rustBridge*Configuration` builder calls fall inside the
~22 ms FFI input-marshalling ceiling (Meta-Pattern 8); after parallel-worker
normalization they cannot reach any meaningful severity threshold. The
analogous `rustBridgeRentFeeConfiguration` call at
`src/transactions/InvokeHostFunctionOpFrame.cpp:584` is bounded by the same
ceiling. Future hypotheses against per-call FFI input struct builders for
already-cached network configuration should be rejected up-front unless they
also eliminate the FFI crossing itself.
