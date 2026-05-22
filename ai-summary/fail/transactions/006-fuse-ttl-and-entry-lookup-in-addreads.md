# H006: Fuse TTL+entry double LedgerEntryMap lookup in addReads for live Soroban keys

**Date**: 2026-05-22
**Subsystem**: transactions
**Severity**: Low
**Impact**: per-key duplicate scoped-LedgerEntryMap probe in the hot footprint walk
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `addReads`
(`transactions/InvokeHostFunctionOpFrame.cpp:386`) processes a
Soroban footprint key whose TTL says the entry is live, the host
should ultimately produce a `(LedgerEntry, TTLEntry)` pair to feed
into the host invocation. The minimum-work behavior is one lookup
into the scoped tx/thread/global `LedgerEntryMap` chain plus one
lookup of the corresponding TTL entry — and the two lookups should
share whatever scoped-map traversal infrastructure they have in
common. If the underlying storage already co-locates a key with its
TTL entry, a single fused lookup is the expected behavior.

## Mechanism

Actual behavior: for each Soroban footprint key the loop body
performs two independent `getLedgerEntryOpt` calls — first for the
TTL key (line 411) and, only after the TTL is found and the entry is
live, again for the data key itself (line 476). Each call walks the
scoped-state chain (tx-map → thread-map → global-map → snapshot),
hashing the `LedgerKey` and probing an `UnorderedMap` at every
level. The two keys are deterministically related — the TTL key is
`getTTLKey(lk)`, a SHA256 over the entry key — but the two lookups
do not amortize any of the scoped-chain traversal cost.

Deviation: the parallel-apply scoped-state chain does not provide a
fused "load entry + ttl" probe, so every live Soroban footprint key
pays the per-level hashing/probe cost twice when once would suffice.

## Trigger

Any soroswap apply-load run on protocol 23+. Soroswap tx footprints
typically contain ~5 RO and ~3–5 RW Soroban keys (SAC instance/code,
pool storage, reserves, TTLs), and `addReads` is invoked twice per
op (once per footprint half). The deviation triggers on every Soroban
key whose TTL says the entry is live (the common path for the
soroswap workload).

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:404-438` — TTL
  lookup branch in `addReads`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:474-498` — separate
  entry lookup branch following a successful live-TTL check.
- `src/transactions/ParallelApplyUtils.cpp` —
  `TxParallelApplyLedgerState`/`ThreadParallelApplyLedgerState`
  `getLedgerEntryOpt` implementations that would need a fused
  variant.

## Evidence

Tracy zone `addReads,transactions/InvokeHostFunctionOpFrame.cpp,388`
(latest accepted soroswap trace, run id
`2ff900fcd176-20260522-031343`) reports total 282.677 ms across
14,092 calls (worker-aggregate, mean 20,059 ns/call). With ~10
keys/op average (RO+RW), each call already amortizes two lookups
per key over ~5 keys; the per-tx duplicated lookup overhead is the
target of a fusion optimization.

## Anti-Evidence

The scoped-state chain probe is fast (sub-µs once the LedgerKey
hash is cached, which it now is — see commit `2d3387eee` "Cache
LedgerKey hash in parallel apply data structures"). With ~14,092
addReads invocations × ~5 keys × ~500 ns saved per fused probe ≈
35 ms total worker-aggregate. Critical-path after T=8 division and
71 ledgers: ≈ 4.4 ms total, ≈ 0.06 ms per ledger ≈ 0.09% of
`applyLedger`. Well below the 1% noise floor. A fused probe would
also require a non-trivial API change touching every level of the
scoped-state hierarchy, raising implementation cost above the win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Prior `addReads`
fails covered toCxxBuf re-encoding (H006, H010) and TTL hash caching
on the InMemorySorobanState lookup path (H005-cache-contract-data-ttl,
H011 — both targeting different code locations). No prior fail
addressed the duplicate scoped-LedgerEntryMap probe inside `addReads`.

### Why It Failed

Below objective severity threshold. The duplicate probe is real but
the LedgerKey-hash caching commit (`2d3387eee`) already removed the
dominant per-probe SHA256 cost, leaving only the bucket-chain walk
itself. The remaining addressable surface is ~0.09% of `applyLedger`
after T=8 division — an order of magnitude below the 1% noise floor
and ~30× below the 3% Medium floor. Additionally, fusing the
TTL+entry probe would require a new `getLedgerEntryWithTTL` API
propagated through `LedgerAccessHelper`, `TxParallelApplyLedgerState`,
`ThreadParallelApplyLedgerState`, `GlobalParallelApplyLedgerState`,
and `ApplyLedgerStateSnapshot` — substantial API surface for a
sub-noise win.

### Lesson Learned

The LedgerKey-hash caching commit (`2d3387eee`) substantially reduced
the per-probe cost in the parallel-apply scoped-state chain.
Subsequent "fuse two probes" style optimizations against the same
chain are bounded by the post-caching per-probe cost (~500 ns), and
therefore lose attractiveness relative to pre-caching estimates.
Future `addReads`-side optimizations should target the
`toCxxBuf`-style allocation/serialization work (already shown to be
sub-threshold) or move to eliminating entire footprint iterations
(e.g., shared RO-footprint reuse across clusters, already rejected
as H001-cluster-shared-readonly-footprint-prebuild).
