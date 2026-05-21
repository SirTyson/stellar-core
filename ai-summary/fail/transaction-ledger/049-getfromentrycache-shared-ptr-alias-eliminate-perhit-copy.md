# H049: Eliminate per-hit LedgerEntry copy + heap alloc in LedgerTxnRoot::Impl::getFromEntryCache via shared_ptr alias

**Date**: 2026-05-21
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: per-cache-hit allocation churn in LedgerTxnRoot serial paths (prefetch / pre-parallel-apply / fee-seq-num phases)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A read-only cache hit in `LedgerTxnRoot::Impl::getFromEntryCache` should not
allocate a new `InternalLedgerEntry` nor deep-copy the cached `LedgerEntry`
XDR. The cached `shared_ptr<LedgerEntry const>` already carries shared
ownership of an immutable entry; callers that need an `InternalLedgerEntry`
view should obtain a `shared_ptr<InternalLedgerEntry const>` that aliases the
cached storage (via `std::shared_ptr`'s aliasing constructor) or that is
constructed once at insertion time, so the per-hit cost is bounded by the
hash lookup and pointer manipulation — no XDR copy, no `malloc`.

## Mechanism

`getFromEntryCache` (`src/ledger/LedgerTxn.cpp:3789-3791`) calls
`std::make_shared<InternalLedgerEntry const>(*cached.entry)` on every cache
hit. `InternalLedgerEntry` wraps a `LedgerEntry` (or `MaxSeqNumToApply` /
`GeneralizedLedgerEntry`) by value, so the constructor deep-copies the entire
cached XDR `LedgerEntry` — for `AccountEntry` and `TrustLineEntry` that means
~150–250 B copy plus the `make_shared` control-block allocation. Each cache
hit therefore pays one `malloc` and one XDR copy that could be eliminated by
storing `shared_ptr<InternalLedgerEntry const>` directly in `CacheEntry`, or
by returning `std::shared_ptr<InternalLedgerEntry const>(cached.entry,
reinterpret_cast<InternalLedgerEntry const*>(...))` via aliasing.

## Trigger

Soroswap apply-load run. Hot callers during the *apply window* are:
- `LedgerTxn::Impl::getNewestVersion` (called via
  `LedgerTxnReadOnly::loadWithoutRecord` and from `getNewestVersionBelowRoot`)
  during the serial `requiresSequentialPreParallelApply` and
  `processFeeSeqNums` phases, plus any worker-thread fallthroughs that miss
  `ThreadParallelApplyLedgerState`'s local map.

## Target Code

- `src/ledger/LedgerTxn.cpp:3779-3803` — `LedgerTxnRoot::Impl::getFromEntryCache`
- `src/ledger/LedgerTxn.cpp:3805-3819` — `LedgerTxnRoot::Impl::putInEntryCache`
- `src/ledger/LedgerTxnImpl.h:598-640` — `CacheEntry { shared_ptr<LedgerEntry const>; LoadType; }` definition

## Evidence

- Code inspection confirms an unconditional `make_shared<InternalLedgerEntry const>(*cached.entry)` per cache hit.
- `InternalLedgerEntry`'s copy constructor copies the union'd XDR payload, so the cost scales with the cached entry's XDR size.
- `mEntryCache` is the canonical cache hit path on the apply thread for entries already pulled into the serial `LedgerTxnRoot` window.

## Anti-Evidence

- The Tracy zone `getNewestVersion` aggregates only ~70 ms self-time across
  the entire 71-ledger trace (~1 ms/ledger), and most of that is consumed by
  hash-map traversal and the prefetch-counter bump, not the `make_shared`.
  The apply-window share is a fraction of this, because the dominant caller
  count comes from TX-set construction zones (`commonValidPreSeqNum`,
  `verifySig`, `loadAccount`) — out of scope per the Tracy Trap.
- During parallel Soroban apply, workers consult
  `ThreadParallelApplyLedgerState` / `InMemorySorobanState` first; they only
  reach `LedgerTxnRoot::mEntryCache` for classic fallthrough, which is rare
  in soroswap.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (fail/010 targets a *different*
cache: a hypothetical per-cluster clean LCL snapshot cache; this hypothesis
targets the existing `mEntryCache` per-hit copy/alloc in `LedgerTxnRoot`).

### Why It Failed

Sizing kills it. Apply-window share of `getNewestVersion`'s ~1 ms/ledger
aggregate self-time is well below 1% of the 272 ms soroswap baseline. Even a
100% elimination of the `make_shared<InternalLedgerEntry>` cost saves at most
a few hundred microseconds per ledger — far below the 3% Medium threshold
(~8.2 ms/ledger). The change also requires modifying `CacheEntry`'s public
contract or adding a parallel `mInternalEntryCache`, which adds complexity
disproportionate to the expected gain. Filed below objective severity floor.

### Lesson Learned

Per-hit allocation elimination in `LedgerTxnRoot::mEntryCache` is bounded by
the apply-window share of `getNewestVersion` self-time. Tracy aggregates
include heavy TX-set-construction callers that inflate the visible total;
always split the apply-window slice out before projecting savings. The
`InternalLedgerEntry` wrapper does enforce a copy on each cache hit, which
*is* a real micro-cost, but at the observed call rate it cannot clear even
the Low (1%) threshold for soroswap.
