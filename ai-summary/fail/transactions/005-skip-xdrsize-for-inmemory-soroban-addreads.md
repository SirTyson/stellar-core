# H005: Skip xdr_size(lk) computation in addReads for in-memory Soroban entries (p23+)

**Date**: 2026-05-22
**Subsystem**: transactions
**Severity**: Low
**Impact**: per-key serialized XDR-size computation in the hot footprint walk
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`addReads` (`transactions/InvokeHostFunctionOpFrame.cpp:386`) should
only compute the XDR-encoded size of each footprint `LedgerKey` when
that size will actually be consumed downstream. In protocol 23+, the
`meterDiskReadResource` call (line 522) — the sole user of `keySize`
in this function — is gated such that it fires only for non-Soroban
entries or for protocol versions earlier than the parallel-Soroban
phase. For a pure-Soroban tx on protocol 26 (the soroswap workload),
`meterDiskReadResource` is never invoked for any of the iterated
keys, so the expected cost of `xdr::xdr_size(lk)` per key should be
zero.

## Mechanism

Actual behavior: the first line of the per-key loop unconditionally
computes
`uint32_t keySize = static_cast<uint32_t>(xdr::xdr_size(lk));`
(line 398) on every iteration regardless of whether `keySize` will be
read. `xdr::xdr_size` walks the discriminated-union/variable-length
substructure of the `LedgerKey` to compute its serialized byte length.
For `ContractDataEntry` keys (the Soroswap pool/token storage keys)
this traverses the `SCAddress`, the durability tag, and the full
`SCVal` key payload (vector or symbol).

Deviation: the computed value is dead for all Soroban keys on p23+,
yet it is paid for every key in both RO and RW footprints of every
Soroban tx. The deviation is "wasted CPU on the worker's per-tx
critical path."

## Trigger

Any soroswap apply-load run on p23+ that closes a Soroban tx whose
footprint contains a non-trivial number of Soroban keys (which is
every soroswap tx — the SAC instance/code, pool storage, and reserves
are always in the footprint).

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads`
  loop body that computes `keySize` unconditionally.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:518-526` — the sole
  call site that consumes `keySize` (gated by
  `!isSorobanEntry(lk) || protocolVersionIsBefore(...,
  PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION)`).

## Evidence

Tracy zone `addReads,transactions/InvokeHostFunctionOpFrame.cpp,388`
(latest accepted soroswap trace, run id
`2ff900fcd176-20260522-031343`) reports total 282.677 ms across 14,092
calls (worker-aggregate, mean 20,059 ns/call). The wasted
`xdr::xdr_size(lk)` is a small fraction of that total.

## Anti-Evidence

`xdr::xdr_size` is dominated by stack walks of small structs and is
inlinable for common types; its per-call cost is on the order of
100–300 ns for a typical `ContractDataEntry` key. With ~99 InvokeHost
ops per ledger × 2 calls per op × ~5 keys per call ≈ 1,000 wasted
`xdr_size` invocations per ledger; at 200 ns each, that's ≈ 200 µs
per ledger of avoidable work, or ≈ 0.003% of `applyLedger`. This is
roughly two orders of magnitude below the 1% noise floor and three
orders below the 3% Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (prior `addReads`
fails H006/H010 targeted `toCxxBuf` re-encoding, not the keySize
computation, and Meta-Pattern 10 only covers the read-side
re-encoding angle).

### Why It Failed

Below objective severity threshold. The wasted work is real and
structurally avoidable, but its absolute cost is bounded at roughly
0.003% of `applyLedger`, far below the 1% Low floor (which the
objective excludes) and the 3% Medium floor (which the objective
accepts). After T=8 worker division and considering that the
benchmark-measured close time is the critical path, no realistic
implementation can clear the floor.

### Lesson Learned

Per-key "dead work" inside hot loops over Soroban footprints
(e.g., unused `xdr_size` or other cheap-but-redundant computations)
is structurally pleasing to fix but quantitatively negligible at the
soroswap scale: ≤ ~5 keys × ≤ ~200 txs × ≤ ~70 ledgers × sub-µs cost
keeps the addressable surface well under 1 ms/ledger. Future
optimizations in `addReads` should target heap allocations or
per-key SHA256s (the TTL key) rather than `xdr_size`.
