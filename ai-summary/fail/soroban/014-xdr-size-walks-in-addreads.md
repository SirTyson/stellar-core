# H014: Eliminate Per-Tx xdr_size(LedgerKey) Walks in addReads/addFootprint

**Date**: 2026-04-29
**Subsystem**: transactions / soroban
**Severity**: Low
**Impact**: Apply-time reduction in per-tx footprint metering
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For an immutable footprint key whose XDR encoding has a deterministic byte
length, `xdr::xdr_size(lk)` should be computed at most once per
`TxBundle` lifetime and reused across all per-tx call sites that need the
key size for resource metering. The cached `ParallelApplyLedgerKey`
infrastructure landed by success #4 already keeps a per-key cached hash
and TTL key on `TxBundle`; extending it to also hold `keySize` would
eliminate redundant XDR-tree walks during `addReads`,
`recordStorageChanges` write metering, and the autorestore handler.

## Mechanism

`InvokeHostFunctionOpFrame::ApplyHelper::addReads`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:398`) computes
`uint32_t keySize = xdr::xdr_size(lk)` for every footprint key on every
operation apply. Two additional sites (`:701`, `:1128`) repeat the same
computation for the writeback path and the autorestore-handler path.
For ContractData keys with complex `SCVal` keys (SAC ledger keys carry an
SCVec topic plus token-specific args), `xdr_size` recursively walks the
entire structure. The cached `ParallelApplyLedgerKey` on `TxBundle` is
the natural place to also memoize `keySize` once per key per tx.

## Trigger

Run the soroswap apply-load benchmark. Each Soroban tx pays
`xdr::xdr_size(lk)` for every footprint key during `addReads` (via
`addFootprint`) and again during `recordStorageChanges` for written
keys. With ~3335 invoke-host operations and roughly 5–7 footprint keys
per tx, this is ~17k–24k repeated `xdr_size` calls per benchmark run.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:398` — `xdr_size(lk)`
  in the read-metering loop.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:701` — `xdr_size(lk)`
  in the writeback metering loop (`recordStorageChanges`).
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1128` — `xdr_size(lk)`
  in the parallel-apply autorestore handler.
- `src/transactions/ParallelApplyStage.h:18-245` — `TxBundle` already
  carries cached `ParallelApplyLedgerKey` values per footprint key.

## Evidence

The soroswap diagnostic Tracy trace shows `addReads` at 137 ms total
across 6748 calls and `addFootprint` at 138 ms across 3374 calls. Both
zones include the `xdr_size` walks alongside `getTTLKey`,
`getLedgerEntryOpt`, `toCxxBuf`, and `validateContractLedgerEntry`.
ContractData footprint keys for SAC operations contain
`SCV_VEC{Symbol, Address}` or similar small structures, so per-key
`xdr_size` is on the order of 100–500 ns; multiplied across 17k–24k
calls this is at most ~12 ms across the benchmark.

## Anti-Evidence

`xdr::xdr_size` for ACCOUNT/TRUSTLINE keys is essentially constant
(direct field-size sum). Even for ContractData with SCVal keys, the walk
is shallow because soroswap keys are short SCVecs. The dominant cost in
`addReads` is `getLedgerEntryOpt` (in-memory map probe), `getTTLKey`
(SHA256 — already cached by success #4), and `toCxxBuf` (XDR encoding
of the entire entry). `xdr_size` is a small fraction of total per-key
cost.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — `xdr_size` caching is distinct from prior LedgerKey
hash caching (success #4) and TTL-key caching (fail/001).

### Why It Failed

Even an upper-bound estimate puts the savings at ~12 ms across the
soroswap benchmark, which is roughly 0.2% of total apply time — far
below the 1% Low noise floor and an order of magnitude below the 3%
Medium threshold. The work that genuinely dominates `addReads` is the
ledger-entry materialization (`toCxxBuf` of full entry bytes) and the
TTL/footprint map probes, neither of which is affected by caching the
key-size scalar. Adding a `keySize` field to the cached
`ParallelApplyLedgerKey` would invasively touch the addReads/writeback/
autorestore paths for sub-percent gain.

### Lesson Learned

`xdr::xdr_size(LedgerKey)` for soroswap-shaped footprint keys is cheap
enough that caching it cannot cross the Low severity floor. Any future
hypothesis targeting `addReads` should focus on the
`getLedgerEntryOpt`/`toCxxBuf` portion, not the metering scalars — and
those already have rejected fails (`004-xdr-bridge-serialization-hotspot`,
`006-cache-encoded-xdr-in-memory-soroban-state`).
