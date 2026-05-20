# H006: Hoist ledger-constant `cpu_cost_params` / `mem_cost_params` CxxBuf serializations out of per-tx setup

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Rust bridge
**Severity**: Low
**Impact**: Removes redundant per-tx XDR serialization of `ContractCostParams` (CPU + memory) which are identical across every Soroban tx in a given ledger.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`SorobanNetworkConfig::cpuCostParams()` and `SorobanNetworkConfig::memCostParams()`
return XDR `ContractCostParams` structures whose values are fixed for the
duration of a single ledger (only mutated by network-config upgrades at
ledger boundaries). On the apply path, every Soroban tx ultimately needs
these structures handed to the Rust host as `CxxBuf`s inside `CxxLedgerInfo`
(see `InvokeHostFunctionOpFrame.cpp:43-73`). The efficient apply path should
serialize each of these two params to bytes *once per ledger* and reuse the
serialized form across all Soroban tx invocations in that ledger.

## Mechanism

`buildLedgerInfo` (`InvokeHostFunctionOpFrame.cpp:43-73`) constructs a
fresh `CxxLedgerInfo` for callers, and lines 61-65 call
`toCxxBuf(sorobanConfig.cpuCostParams())` and
`toCxxBuf(sorobanConfig.memCostParams())` — each of which performs an XDR
serialization (`xdr::xdr_to_opaque`) into a fresh `std::vector<uint8_t>`
wrapped in a `std::unique_ptr` inside a `CxxBuf`. If every Soroban tx
called `buildLedgerInfo` directly, this would represent ~2 × 1554 redundant
serializations per ledger.

## Trigger

Run the soroswap apply-load benchmark. Inspect the call path for the
`CxxLedgerInfo` flowing into each `rust_bridge::invoke_host_function` call,
and verify whether the cost-param `CxxBuf`s are constructed per-tx.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:43-73` —
  `buildLedgerInfo` and the cost-param serialization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:75-94` —
  `getCachedLedgerInfo` (the existing caller path).

## Evidence

Aggregate per-ledger XDR serialization cost for the two cost-param
structures is ~1-2 µs each; multiplied across 1554 txs × 2 params = ~6 ms
per ledger if no caching existed.

## Anti-Evidence

**This optimization is already implemented in the codebase.**
`getCachedLedgerInfo` at `InvokeHostFunctionOpFrame.cpp:75-94` already uses
a `thread_local` cache keyed on `ledgerSeq`:

```cpp
thread_local std::optional<uint32_t> cachedLedgerSeq;
thread_local std::optional<CxxLedgerInfo> cachedLedgerInfo;

if (!cachedLedgerSeq || *cachedLedgerSeq != ledgerSeq)
{
    cachedLedgerSeq = ledgerSeq;
    cachedLedgerInfo = buildLedgerInfo(...);
}
```

Each worker thread builds the `CxxLedgerInfo` (including the
`cpu_cost_params` and `mem_cost_params` CxxBufs) exactly once per ledger
and reuses it for every subsequent tx. The cached struct is returned by
const reference, so no re-serialization occurs for subsequent txs.

There is no opportunity to remove. A finer reduction (e.g. one global
ledger-level cache instead of one per worker thread) would save at most
`(num_workers - 1) * 2` extra serializations per ledger ≈ 14 × 2 = 28
serializations totaling ~50 µs across the ledger, which is orders of
magnitude below benchmark noise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in fail/transaction-ledger
as a cost-param specific hypothesis.

### Why It Failed

Already implemented. `getCachedLedgerInfo` thread_local cache already
amortizes the cost-param `toCxxBuf` calls to one per ledger per worker
thread. There is no measurable per-tx redundancy left to remove on this
particular call path. A global (vs per-worker) cache would save at most
sub-millisecond per ledger, far below benchmark noise.

### Lesson Learned

Before proposing per-tx hoisting hypotheses targeting `toCxxBuf` /
`CxxLedgerInfo` construction, check for existing thread_local or
ledger-scoped caches around `buildLedgerInfo`. The
`getCachedLedgerInfo` thread_local pattern is the existing answer for
per-ledger `CxxLedgerInfo` reuse; future hypotheses about ledger-constant
CxxBuf reuse must explicitly identify a serialized payload that is *not*
already cached this way.
