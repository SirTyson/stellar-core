# H005: Memoize TTL keys for shared RO Soroban footprint entries to skip repeated SHA256+xdr_to_opaque

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / parallel Soroban apply
**Severity**: Low
**Impact**: Removes redundant `sha256(xdr_to_opaque(LedgerKey))` work for the small set of Soroban contract code/data keys that every tx in a cluster references via its RO footprint.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The TTL key for a given `LedgerKey` is a deterministic function of the key's
XDR encoding (`sha256(xdr_to_opaque(key))`, see `LedgerTypeUtils.cpp:30-38`).
For a given ledger, the TTL key for a specific contract code or contract data
`LedgerKey` is identical across every invocation site that derives it. The
efficient apply path should compute each unique TTL key once and reuse the
cached `Hash` for all subsequent derivations within the apply window without
changing observable behaviour or budget accounting (the SHA256 done in
`getTTLKey` is *not* a metered host operation — it is C++-side bookkeeping).

## Mechanism

In the current code `getTTLKey(lk)` is called many times per tx for the same
`lk`:

- `InvokeHostFunctionOpFrame.cpp:406` inside `addReads` — once per Soroban
  footprint key
- `ParallelApplyUtils.cpp:127`, `:249`, `:691`, `:781`, `:794`, `:980`,
  `:1017` — multiple per-tx and per-cluster setup callers
- `InvokeHostFunctionOpFrame.cpp:685` inside the `recordStorageChanges`
  inner loop — once per rwKey iteration (already a known O(N×M) site,
  see fail `004-recordstoragechanges-on2-ttlmatch-loop.md`)
- `InvokeHostFunctionOpFrame.cpp:761` and `:1159` — restore/erase paths

Soroswap's hottest shared RO keys (router contract instance, router code,
pair contract instance, pair code) appear in *every* tx's RO footprint inside
a given cluster. Each call to `getTTLKey` does `xdr::xdr_to_opaque(lk)` (small
heap allocation + XDR walk) plus a SHA256 hash. The result is byte-identical
across all callers for the same `lk`. A per-`ThreadParallelApplyLedgerState`
`UnorderedMap<LedgerKey, Hash>` cache (or a `LedgerKey -> Hash` field added to
the parallel apply entry struct) would replace the repeated derivations with
one memoized lookup.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`)
against the baseline recorded in `ai-summary/CURRENT_STATE.md`. Each tx
inside a parallel cluster touches roughly four shared RO Soroban keys
(router instance + router code + pair instance + pair code) and at least
two per-tx unique RW Soroban keys; `getTTLKey` is invoked at multiple call
sites per tx per key.

## Target Code

- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey)` — the
  per-call SHA256 + xdr_to_opaque.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:406`, `:685`, `:761`,
  `:1159` — high-frequency call sites in the apply path.
- `src/transactions/ParallelApplyUtils.cpp:127`, `:249`, `:691`, `:781`,
  `:794`, `:980`, `:1017` — per-tx and per-cluster setup callers.
- `src/ledger/InMemorySorobanState.h` — natural place to colocate cached
  TTL keys alongside the entries themselves, since RO contract code/data
  entries are already served from `InMemorySorobanState` and would share
  the cache's lifetime.

## Evidence

- The 4 shared RO keys × ~10 distinct `getTTLKey` call sites = ~40
  redundant derivations per tx for the same set of shared keys.
- Soroswap baseline has ~1554 invoke-host-function txs per ledger;
  redundant aggregate ≈ 1554 × 40 = ~62k SHA256+xdr_to_opaque calls per
  ledger for keys whose TTL hash is identical.
- At ~500 ns per `getTTLKey` invocation (small XDR encode + SHA256 of
  ~50-100 bytes), the redundant aggregate ≈ **31 ms per ledger**.
- Critical-path savings after 8-way cluster normalization ≈ **~4 ms**
  ≈ **~1.5% of the 272 ms soroswap baseline**.

## Anti-Evidence

- The SHA256 in `getTTLKey` is *not* a metered Soroban host charge — it
  is C++ bookkeeping outside the `Budget` — so removing redundant
  derivations does not change protocol-visible budget totals. However:
- Many of the call sites are inside the parallel cluster worker; aggregate
  worker time must be divided by the active cluster count (8) to estimate
  critical path. This matches fail-summary lesson 6 ("Aggregate Worker
  Time ≠ Critical-Path Time").
- Some call sites are in cluster *setup* (`ParallelApplyUtils.cpp:980`,
  `:249`, `:127`) that are bounded by the slowest cluster's setup, not
  averaged across clusters. Even there, the absolute cost is small.
- The cache requires either (a) a new `UnorderedMap<LedgerKey, Hash>` per
  `ThreadParallelApplyLedgerState`, which adds allocation and lookup
  overhead that may erode the saving, or (b) modifying the
  `InMemorySorobanState` entry structs to carry the precomputed hash,
  which adds memory pressure on a hot cache (fail-summary lesson 7:
  "InMemorySorobanState Cache Pressure Can Negate XDR Savings").
- Several of the cited call sites (`addReads:406`, `addReads:761`,
  `recordStorageChanges:685`) are inside the per-tx hot loop where adding
  even a small `unordered_map` find may cost as much as the original
  SHA256 on cache-warm inputs.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a standalone TTL-key
memoization hypothesis. Fail `004-recordstoragechanges-on2-ttlmatch-loop.md`
covered only the `recordStorageChanges` inner loop and rejected it as a
subset of a broader reviewed precompute hypothesis; this proposal extended
the scope to *all* shared-RO call sites across the apply path.

### Why It Failed

After enumerating call sites and counting, the upper bound on critical-path
savings is approximately 1.5% of the soroswap baseline (~4 ms / 272 ms),
which falls below the objective's Medium floor (3%) and is essentially at
the boundary of run-to-run benchmark noise. The optimization is genuine —
the redundant SHA256 work *does* exist and *is* removable — but the
absolute cost is too small to clear the severity threshold for this
objective. Specifically:

- Meta-pattern lesson 5 in `fail/transaction-ledger/summary.md` already
  documents that several similar narrow CPU-savings optimizations in this
  region (xdr_size skip, medida histogram disable, recordStorageChanges
  TTL precompute, CxxBuf precompute) each project at 0.2–2.5%
  individually and do not clear Medium alone.
- Adding a per-thread `unordered_map<LedgerKey, Hash>` introduces its own
  allocation + lookup overhead that may erode the saving in practice.
- The cache cannot safely live in `InMemorySorobanState` without
  expanding the resident memory footprint of every entry — fail-summary
  lesson 7 establishes that this can flip into a net regression.

### Lesson Learned

The SHA256 inside `getTTLKey` is real C++ overhead but does not aggregate
to a Medium-severity savings on the soroswap shape. Any future TTL-key
caching attempt should be paired with the broader precompute hypothesis
already under review (see fail `004-recordstoragechanges-on2-ttlmatch-loop`
note) and must be measured *after* removing the per-cache lookup overhead,
not in isolation. Standalone TTL-key memoization is sub-Medium and should
not be re-proposed.
