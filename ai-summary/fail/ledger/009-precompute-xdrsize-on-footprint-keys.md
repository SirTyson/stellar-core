# H009: Precompute and cache `xdr::xdr_size(lk)` for footprint keys on `TransactionFrame` to skip per-tx key-size recomputation in `addReads`

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban parallel apply footprint validation
**Severity**: Low (claimed); actually below threshold
**Impact**: Skip per-tx `xdr::xdr_size(LedgerKey)` recomputation for every footprint key entering `InvokeHostFunctionApplyHelper::addReads`, by caching the size at `TransactionFrame` construction time (Soroban resources are known and immutable from txset assembly through apply).
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`addReads` (`src/transactions/InvokeHostFunctionOpFrame.cpp:386-535`) is called twice per Soroban tx — once each for the RO and RW footprints. For every key, line 398 computes `uint32_t keySize = static_cast<uint32_t>(xdr::xdr_size(lk));` and uses the size for resource metering and entry-size validation. The `xdr_size` of a `LedgerKey` is fully determined by the immutable contents of the key, which are already known when the transaction enters the apply path (the Soroban footprint is part of `mInvokeHostFunction`/`SorobanResources` and never mutated). Expected behavior: each footprint key's XDR size should be computed at most once per `TransactionFrame` lifetime, not per `addReads` call inside parallel apply.

## Mechanism

`xdr::xdr_size(LedgerKey)` recursively walks the LedgerKey structure. For `CONTRACT_DATA` keys with an `SCVal` payload that contains nested `SCMap`/`SCVec`, the size walk follows every nested element. Across all soroswap apply work the same set of footprint keys is sized on every transaction. If `TransactionFrame` were to compute and cache the per-key XDR size at construction (or at first `addReads` call) and reuse it on subsequent parallel-apply invocations, the recomputation would be eliminated. Caching shape: a per-`TransactionFrame` `std::vector<uint32_t> mFootprintKeyXdrSizes` aligned with the footprint order, populated once and reused.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap TX=2000 T=8 exercises `addReads` for every Soroban tx in parallel apply. Each tx footprint has roughly 5-9 keys (token contract instance, code, balance entries, pair pool). Soroban-only ledgers process all 2000 tx through `addReads`, so this work runs ~16,000-18,000 times per ledger across the 8 worker threads.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-398` — `addReads`, the per-tx footprint walk that calls `xdr::xdr_size(lk)`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:537-554` — `addFootprint`, the wrapper that invokes `addReads` for RO then RW footprints.
- `src/transactions/TransactionFrame.h` / `TransactionFrame.cpp` — candidate site for the `mFootprintKeyXdrSizes` cache (immutable across the tx lifetime).
- `src/transactions/InvokeHostFunctionOpFrame.h` / `InvokeHostFunctionOpFrame.cpp` — alternative site if scoped to invoke-host-function ops only.

## Evidence

The current Tracy trace from `ai-summary/CURRENT_STATE.md`
(`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`)
shows `addReads` self-time of 230,336,866 ns over 15,890 in-apply calls (aggregate
worker time ~2.24% of trace). The footprint key set is part of the immutable
`SorobanResources` in the transaction envelope, so the size walk is fundamentally
recomputable work. The targeted savings would be a strict subset of that 230 ms
aggregate.

## Anti-Evidence

The 230 ms aggregate self-time of `addReads` covers far more than `xdr_size`
calls: `getLedgerEntryOpt`, `toCxxBuf`, hot-archive checks, `getTTLKey`, and
`isLive` checks all run inside the same scoped zone and dominate the per-call
time (mean 14.5 µs per call). The `xdr_size` portion alone is on the order of
50-200 ns per key (a few hundred bytes traversed). For soroswap shaped at
~7 footprint keys/tx × 2000 tx = ~14,000 size walks per ledger × 150 ns ≈
2.1 ms aggregate / 8-way cluster parallelism ≈ 260 µs wall per ledger.
That is well under 0.15% of the 218 ms soroswap median apply baseline — orders
of magnitude below both the 3% Medium floor and the 1% Low floor.

Even an absolute-best-case bound (every footprint key is a worst-case nested
SCVal with 1 µs xdr_size cost): 14,000 × 1 µs = 14 ms aggregate / 8 = 1.75 ms
wall = ~0.8% — still sub-Medium and sub-Low.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — fail history covers cached old-entry XDR *sizes for rent
accounting* in the host (`success/ledger/002-cache-old-entry-xdr-sizes.md`),
TTL-key SHA256 caches, and `addReads`-side encoded-byte caches (fails 003, 010,
011), but no prior investigation targets `xdr_size(LedgerKey)` recomputation in
`addReads` specifically.

### Why It Failed

Below this objective's Medium severity threshold (3-10%) and even below the Low
floor (1%). The addressable cost is the per-key `xdr_size` walk for soroswap
footprints: ~14,000 calls/ledger at ~50-200 ns each (the LedgerKey XDR layouts
are small; the Soroban footprint averages ~7 keys/tx). Aggregate worker time
ceiling is ~2-3 ms/ledger; divided by 8-way cluster parallelism the wall-clock
saving is at most ~260-400 µs/ledger, roughly 0.1-0.2% of the 218 ms soroswap
median. Even a generous 5× upper bound stays under the 1% Low floor. The
optimization is also retrofitted onto a code path that already accumulates the
size as a side effect of building the CxxBuf (`leBuf.data->size()`), so the
"removed" work is limited to the keySize line specifically, not any downstream
serialization.

### Lesson Learned

Per-key XDR-size walks on footprint LedgerKeys cost on the order of hundreds of
nanoseconds — adding a TransactionFrame-side cache cannot reach Medium or even
Low on soroswap. Pre-quantify (keys/tx × tx/ledger × per-key µs) and divide by
configured cluster parallelism before drafting a TransactionFrame-cache
hypothesis for footprint-key metadata.
