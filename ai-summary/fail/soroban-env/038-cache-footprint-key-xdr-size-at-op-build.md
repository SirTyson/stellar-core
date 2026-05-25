# H038: Cache Footprint Key `xdr_size` at Op-Build Time

**Date**: 2026-05-25
**Subsystem**: transactions (InvokeHostFunctionOpFrame ingress + write-side)
**Severity**: Low (sub-Medium; below benchmark noise after parallelism)
**Impact**: Avoid redundant `xdr::xdr_size(lk)` walks for footprint
keys recomputed in `addReads` per Soroban entry and again in
`recordStorageChanges` per written entry.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The Soroban apply-path C++ ingress and write-side bookkeeping should
compute `xdr::xdr_size(footprintKey)` at most once per unique footprint
`LedgerKey` per operation. The XDR-size of a `LedgerKey` is a pure
function of its contents and is needed in three places per op:

1. `addReads` line 398 — `keySize = xdr::xdr_size(lk)` per footprint
   entry, used for `validateContractLedgerEntry` and read-byte
   metering.
2. `recordStorageChanges` line 701 — `keySize = xdr::xdr_size(lk)`
   per written entry, used for write-byte metering and the
   resource-budget check at line 704.
3. `handleArchivedEntry` / restore paths — similar `keySize`
   computation when an entry is restored.

The same `LedgerKey` is XDR-walked twice for every read-write footprint
entry that is also modified (the steady-state soroswap case for SAC
balance and pair-reserve writes).

## Mechanism

`xdr::xdr_size(LedgerKey)` recursively walks the variant tree counting
bytes. For typical Soroban LedgerKeys (ContractData with an
AddressObject and an ScVal Vec key for SAC balances), this is ~10-30
nanoseconds of pure CPU per call but allocates no memory. In the
soroswap apply window, each op touches ~6-10 footprint entries; ~3-5
of those are read-write (SAC balances, pair reserves), and most of
them produce one or more output entries that re-walk the same key in
`recordStorageChanges`.

The deviation from expected behavior: the second walk inside
`recordStorageChanges` is fully redundant. The operation already has
the per-footprint key size from `addReads`; persisting that small
array (one `uint32_t` per footprint key) and indexing it by rwKey
position would eliminate the second walk entirely.

This is novel relative to the Rust-side success
`cached-old-entry-xdr-sizes`, which caches *entry* XDR sizes inside
the Soroban host's storage map. That success does not address the C++
side's repeated *key* XDR-size computation, which lives outside the
Rust host.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, soroswap TX=2000 T=8). Every
Soroban op pays the addReads keySize walk for each footprint entry
and recordStorageChanges keySize walk for each written entry. The
recordStorageChanges walks are the redundant subset.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:398` — initial
  `keySize` walk in `addReads`. Persist the resulting size into
  per-op arrays `mRoKeySizes` and `mRwKeySizes` parallel to the
  footprint vectors.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:672-695` — match
  loop that identifies `matchedRwKey`/`relatedRwKey`. The matched
  index unlocks reuse of `mRwKeySizes[j]` in place of the line 701
  walk.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:701` — `keySize`
  recomputation in `recordStorageChanges` (the redundant call site).
- `src/transactions/InvokeHostFunctionOpFrame.cpp:761` — `getTTLKey(lk)`
  for uncovered RW erase; ttl-key size is `sizeof(Hash)`, no walk
  needed, but the data-key size for the rwKey itself comes from the
  cached array.
- `src/transactions/InvokeHostFunctionOpFrame.h` — add per-op
  `std::vector<uint32_t> mRwKeySizes` member, mirroring
  `mRwKeyExisted`.

## Evidence

- Source inspection confirms two independent `xdr::xdr_size(lk)`
  call sites for footprint keys at lines 398 and 701; no shared
  cache exists today.
- Trace `f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`:
  `addReads` 262 ms self / 17,504 events,
  `recordStorageChanges` 70 ms self / 8,705 events. The xdr_size
  walks are a small unmeasured subset of each.
- Soroswap apply window: ~250 ops/ledger × ~5 RW writes/op × ~20 ns
  per walk = ~25 µs/ledger of redundant work per worker.

## Anti-Evidence (and Self-Rejection)

Quantifying the ceiling:

| component | aggregate | per-ledger wall (÷8 workers) | % of 207 ms |
|-----------|-----------|------------------------------|-------------|
| Redundant `xdr_size(lk)` in recordStorageChanges | ~250 ops × 5 writes × 20 ns × 71 ledgers ≈ 1.8 ms aggregate | 1.8 ms ÷ 8 ÷ 71 ≈ 3 µs/ledger | ~0.0015% |
| Per-op `mRwKeySizes` push overhead | ~250 × 5 × 5 ns | negligible (offset) | ~0 |
| **Total** | | **~3 µs/ledger** | **~0.0015%** |

A typical Soroban `LedgerKey` is ~80-200 bytes of XDR; `xdr::xdr_size`
on this depth walks roughly 10-20 small variant branches in ~20 ns.
The redundant walk is real but vanishingly small compared to the
per-op work envelope (~8 µs in `recordStorageChanges`, dominated by
the per-output XDR deserialization of the modified `LedgerEntry`).

Even an unrealistically generous estimate (200 ns per walk on a
larger ContractData key, 10 writes per op) gives:
`250 × 10 × 200 ns × 71 / 8 = ~44 ms aggregate → 0.078 ms/ledger
≈ 0.04%` — still 70× below the 1% noise floor and 75× below the
3% Medium threshold.

Per Meta-Pattern 14 in `summary.md`: per-op micro-optimizations on
the soroswap parallel-apply path are bounded by
`per_op_ns × ops × writes / parallelism / ledger_count` and
consistently fall below 0.1% wall-clock. This proposal sits four
orders of magnitude below the objective severity floor.

The implementation also requires plumbing a per-op
`std::vector<uint32_t>` (extra allocation per op) and reasoning about
which keySize to use when `matchedRwKey == rwKeys.size()` (i.e., the
output is a TTL entry not directly in the rwKey footprint, which is
the common case for ContractData writes). The plumbing complexity is
disproportionate to the saving.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — distinct from the Rust-side
`cached-old-entry-xdr-sizes` success (which caches *entry* sizes in
the soroban host's storage map). H038 targets the C++ side's
*key* `xdr_size` redundancy, which is a separate code path. Also
distinct from H037 (which targets the SHA256 / linear scan in the
same function, not xdr_size).

### Why It Failed

The optimization saves at most `~ops × writes × 20 ns ≈ 25 µs/ledger`
per parallel worker, or `~3 µs/ledger wall ≈ 0.0015%` of the 207 ms
soroswap baseline. This is four orders of magnitude below the 3%
Medium threshold and three orders below the 1% benchmark-noise
floor. Even under the most generous per-call cost estimates
(~200 ns/walk, 10 writes/op), the ceiling remains under 0.05%.

Per the objective context ("Findings below 1% (within benchmark noise)
are not valid; do not produce slop PRs that don't actually improve
performance") and Meta-Pattern 14's parallel-worker normalization
rule, this proposal is structurally incapable of clearing the
severity floor.

### Lesson Learned

For C++ ingress/egress bookkeeping micro-optimizations, the saving
ceiling is `removable_ns_per_op × ops_per_ledger / parallelism`.
On the soroswap workload (250 ops/ledger, 8-way parallel), the
per-ledger wall savings for any per-op work unit ≤ 1 µs is
`<= 1 µs × 250 / 8 = ~30 µs/ledger ≈ 0.015%` — well below all
severity floors. Future redundant-pure-function-elimination
hypotheses targeting per-op C++ apply bookkeeping must first
confirm the removable per-op work exceeds ~10 µs (Medium ceiling
~3 ms/ledger ÷ 250 ops = ~12 µs/op of recoverable serial work) before
promotion.
