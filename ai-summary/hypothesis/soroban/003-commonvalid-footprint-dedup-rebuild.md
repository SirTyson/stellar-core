# H003: commonValidPreSeqNum rebuilds Soroban footprint dedup UnorderedSet on every call (apply + checkValid), hashing CONTRACT_DATA SCVal keys via xdr_to_opaque each time

**Date**: 2026-04-28
**Subsystem**: soroban (transactions / apply path)
**Severity**: Medium
**Impact**: Apply-time reduction; soroswap (CONTRACT_DATA-heavy footprints) primary beneficiary
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Footprint duplicate-detection is a property of the immutable transaction
envelope. For a given `TransactionFrame`, the set of `LedgerKey`s in
`sorobanData.resources.footprint.{readOnly,readWrite}` cannot change after
construction. The first successful dedup proves the property holds; every
subsequent call to `commonValid` for the same frame should reuse that
result rather than re-hashing every key into a fresh
`UnorderedSet<LedgerKey>`. In particular, the apply path
(`commonPreApply` -> `commonValid` -> `commonValidPreSeqNum`) should not
repeat hash work that the validation path
(`checkValidWithOptionallyChargedFee`) already performed when the tx was
admitted to the tx set, because the envelope is identical.

## Mechanism

`commonValidPreSeqNum` (TransactionFrame.cpp:1464–1489) unconditionally
constructs a fresh `UnorderedSet<LedgerKey> set;` on every invocation and
re-hashes/inserts every footprint key, for both the RO and RW vectors,
solely to detect duplicates. For soroswap swaps, the footprint is
dominated by `CONTRACT_DATA` keys whose `std::hash<LedgerKey>`
specialization (LedgerHashUtils.h:178–185) calls
`shortHash::xdrComputeHash(lk.contractData().key)`, which serializes the
`SCVal` to bytes via `xdr_to_opaque` and then runs SipHash over that
buffer — non-trivial per-key cost (hundreds of ns to a few µs each
depending on SCVal shape). With ~10 footprint keys per swap and 4000
swaps per measured ledger, the apply path alone performs ~40,000
SCVal serializations + SipHash + UnorderedSet bucket allocations per
ledger, all of which is pure waste because the same dedup already
succeeded during tx admission. (The validation path repeats the work
many more times per surge-pricing iteration, but those calls are
out-of-scope tx-set construction.) Caching a "footprint dedup OK" flag
on `TransactionFrame` (or moving the dedup into the constructor /
`postProcessSorobanData`-style one-shot path) eliminates the apply-path
cost entirely.

## Trigger

Run the soroswap apply-load benchmark at default size (4000 swaps /
ledger × 8 clusters). Tracy zone `commonValidPreSeqNum` is called once
per tx during apply (via `commonPreApply` -> `commonValid` ->
`commonValidPreSeqNum`). For each call, profile the time spent in
`UnorderedSet::emplace` and `std::hash<LedgerKey>::operator()` — that is
the recoverable cost.

## Target Code

- `src/transactions/TransactionFrame.cpp:1461-1489` —
  `commonValidPreSeqNum` builds `UnorderedSet<LedgerKey> set;` and runs
  the `checkDuplicates` lambda over RO and RW footprint vectors on every
  invocation.
- `src/transactions/TransactionFrame.cpp:2065-2125` —
  `commonPreApply` calls `commonValid(..., applying=true, ...)`, which
  re-enters the dedup loop on the apply path.
- `src/transactions/TransactionFrame.cpp:1665-1700` — `commonValid`
  always invokes `commonValidPreSeqNum`, regardless of whether the same
  envelope was previously validated.
- `src/ledger/LedgerHashUtils.h:136-200` —
  `std::hash<LedgerKey>::operator()`. For `CONTRACT_DATA`, calls
  `shortHash::xdrComputeHash(lk.contractData().key)`, which serializes
  the SCVal to a temporary buffer per call.
- `src/transactions/TransactionFrameBase.h:60-90` — existing pattern of
  caching a derived-from-immutable-envelope hash on the frame
  (`mLedgerKey` / `mHash`); extends naturally to a
  `mFootprintDedupOk` enum/flag.

## Evidence

- Tracy baseline trace
  (`/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/...-soroswap-tx-4000-t-8.tracy`):
  `commonValidPreSeqNum` total = 4.94 s / 187,782 calls (26 µs mean,
  18.2 µs self). The dedup loop is one of the few non-trivial pieces of
  per-call work that scales linearly with footprint size; protocol-check
  and fee-check work is ~constant per tx.
- `std::hash<LedgerKey>` for CONTRACT_DATA is the only LedgerKey variant
  that performs `xdrComputeHash` (XDR serialization + SipHash); for
  ACCOUNT/TTL/CONTRACT_CODE it is a single 256-bit hash. Soroswap
  footprints are ~100% CONTRACT_DATA + a CONTRACT_CODE/instance, so this
  is the worst case for the hasher.
- Memory cost per call: each `UnorderedSet<LedgerKey>` allocation
  triggers a heap allocation for the bucket array, then per-key node
  allocations (typically ≥10 small allocs). This is allocation churn in
  a per-tx hot path.
- `mLedgerKey` / `mHash` precedent (TransactionFrameBase.h) shows the
  codebase already caches derived-from-envelope state on the frame; the
  same pattern applies cleanly here.
- TransactionFrame is described in code as immutable after construction,
  so caching dedup status is safe (no synchronization needed beyond the
  existing envelope-immutability invariant).

## Anti-Evidence

- A large fraction of `commonValidPreSeqNum` calls in the trace come
  from tx-set construction (Tracy Trap), not the apply path. The
  apply-path share is bounded by ~4000 calls per measured ledger × N
  measured ledgers, vs many tens of thousands per ledger from surge
  pricing. The apply-path saving is therefore a fraction of the 4.94 s
  total — back-of-envelope: 4000 × ~7 µs of dedup work × ~1 measured
  ledger / 65 trace ledgers = single-digit-ms range per ledger,
  potentially ~3–6% of the 620 ms median (right at the Medium
  threshold). Empirical confirmation required.
- The dedup also enforces RO/RW disjointness, which must continue to be
  enforced. A cache on the frame is fine as long as it is set only after
  *both* `checkDuplicates` calls succeed.
- For the apply path, `checkValidWithOptionallyChargedFee` has already
  run during tx admission, so the dedup is provably redundant on the
  apply path; the optimization is "skip on apply if already validated"
  rather than removing the check entirely.
- `TransactionFrame` is `const`-passed in many places; the cache slot
  must be `mutable` or the dedup must be hoisted to a non-const
  initialization step at construction. The latter is cleaner and is the
  recommended approach.
- Hoisting dedup into the constructor would also benefit the tx-set
  construction path (out of scope but a free speedup), so the change is
  net-positive even if the apply-path share is at the lower end of the
  estimate.
