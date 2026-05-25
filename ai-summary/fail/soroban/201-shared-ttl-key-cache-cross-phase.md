# H201: Cache per-cluster `getTTLKey` SHA-256 results across `collectClusterFootprintEntriesFromGlobal` and `collectModifiedClassicEntries`

**Date**: 2026-05-26
**Subsystem**: soroban (parallel apply ledger state setup)
**Severity**: Low
**Impact**: redundant per-ledger SHA-256 work during parallel-apply startup
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Every Soroban-typed `LedgerKey` has a corresponding `TTLKey` whose hash
is a deterministic function of the source key (a SHA-256 of the XDR-
encoded key). For a given ledger, the set of unique source keys across
all stages, clusters, and txs is fixed and small (soroswap shares one
contract instance key across the entire ledger; SAC transfers share
the same SAC contract instance). The expected behavior is to compute
the SHA-256 of each unique source key **at most once** per ledger and
reuse the result everywhere `getTTLKey` is called.

## Mechanism

`getTTLKey(LedgerKey const&)` (in `src/ledger/LedgerTypeUtils.cpp`) runs
`sha256(xdr_to_opaque(key))` on every call. It is currently invoked at
four distinct points during a ledger's parallel apply setup and apply
loop:

1. `GlobalParallelApplyLedgerState::collectModifiedClassicEntries`
   (ParallelApplyUtils.cpp:693 + 705) — serial pre-load on the apply
   thread, per Soroban RO key.
2. `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`
   (ParallelApplyUtils.cpp:973) — per worker, per tx, per Soroban
   key (RO + RW), at thread state construction.
3. `ThreadParallelApplyLedgerState::flushRoTTLBumpsInTxWriteFootprint`
   (ParallelApplyUtils.cpp:1004) — per tx per RW key during apply.
4. `InvokeHostFunctionOpFrame::recordStorageChanges` inner loop
   (InvokeHostFunctionOpFrame.cpp:684, 760) — per modified entry per
   RW key during result recording.

Each call re-hashes the same `LedgerKey` bytes. For soroswap the pool
instance key + SAC instance keys are shared by every swap, so the same
2–3 SHA-256s are recomputed dozens of times per ledger across the
serial-then-parallel pipeline. A `LedgerKey -> Hash` cache built once
during `collectModifiedClassicEntries` and threaded down to per-cluster
state could replace these recomputations with a hash-map lookup.

## Trigger

Run `scripts/run_apply_load_matrix.py` soroswap scenario; instrument
the four call sites above and count `getTTLKey` invocations per
ledger. Expect 4–6× redundancy on the shared instance keys (1 per
collect, 1 per cluster × NUM_CLUSTERS=8, 1 per tx during flush and
record).

## Target Code

- `src/ledger/LedgerTypeUtils.cpp:getTTLKey` — single SHA-256 site.
- `src/transactions/ParallelApplyUtils.cpp:693,705,973,1004,1090,1105`
  — call sites in collect/flush paths.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:684,760` — call
  sites in `recordStorageChanges`.

## Evidence

- Tracy `getTTLKey` is not a separate zone but is part of
  `collectModifiedClassicEntries` and `collectClusterFootprintEntriesFromGlobal`
  zone totals. Aggregate `applyLedger` SHA-256 cost is bounded by
  meta-pattern #5 at **~0.67% of apply time** (whole "SHA256/TTL-key
  total in apply").
- Soroswap pool instance + 2 SAC instance keys are shared across all
  120 swaps/ledger, so the four call sites cumulatively recompute the
  same 3 hashes hundreds of times per ledger. The redundancy is
  structurally real.

## Anti-Evidence

- Each individual SHA-256 is ~1 µs. Even with hundreds of redundant
  calls per ledger, the total is sub-millisecond per ledger per worker.
- Meta-pattern #5 explicitly caps the entire SHA-256/TTL-key category
  at ~0.67% — any subset (and this hypothesis is a subset, since not
  all SHA-256 calls are TTL-key recomputes) is strictly below that.
- A `LedgerKey -> Hash` cache adds map-lookup overhead at every call
  site; for the non-shared keys (per-tx swap-specific Account /
  TrustLine keys) the cache hit rate is 1 and lookup overhead is pure
  loss.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — meta-pattern #5 establishes the SHA-256/TTL-key
budget but no prior fail entry targets cross-phase TTL-key cache
sharing between global-collect, per-cluster collect, and
recordStorageChanges specifically.

### Why It Failed

The maximum achievable saving is bounded by meta-pattern #5
(~0.67% of apply time for **all** SHA-256/TTL-key work, including
the unavoidable first-time hashes). The proposed cache only removes
the **redundant** subset of that budget — at best a fraction of the
0.67% ceiling. Even an oracle-perfect cache that eliminated every
redundant call would land at sub-0.5% improvement, well below the
Low (1%) noise floor and far below Medium (3%).

Additional structural penalty: the three primary call sites
(`collectModifiedClassicEntries`, `collectClusterFootprintEntriesFromGlobal`,
`recordStorageChanges`) span the boundary between serial setup,
parallel worker startup, and per-tx apply. A shared cache across
that boundary would require lock-free or atomic access patterns, and
the per-cluster cache (no synchronization needed) only helps within
one worker — capturing at most the per-cluster redundancy (1 hash per
shared key per cluster), which is even smaller than the global
redundancy.

### Lesson Learned

For SHA-256-bound proposals on the apply path, compare directly
against meta-pattern #5's 0.67% ceiling first. The *redundant* subset
of TTL-key work is structurally smaller than the total, and the total
is already sub-Low. Cross-phase caches that span serial→parallel
boundaries trade synchronization cost against an already sub-Low
gain; the net effect rarely beats the noise floor.
