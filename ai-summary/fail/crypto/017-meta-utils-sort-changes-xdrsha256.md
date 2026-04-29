# H017: Eliminate per-LedgerEntryChange `xdrSha256` in `MetaUtils::sortChanges`

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Medium
**Impact**: Apply-time reduction by removing a per-change SHA256 computation in meta normalization, which would scale linearly with soroswap's per-tx storage write counts
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `LedgerCloseMeta` is finalized for the closed ledger, normalization of
per-operation `LedgerEntryChanges` should use a stable, deterministic
ordering that does not require hashing the full XDR-serialized change. The
hash is only required if two changes share the same `(LedgerKey, type)`
tuple — an extremely rare tiebreaker — so most comparisons should avoid the
SHA256 entirely.

## Mechanism

`src/util/MetaUtils.cpp:55-65` builds a 3-tuple `(LedgerKey, remap(type),
xdrSha256(LedgerEntryChange))` for every comparator invocation in
`std::sort`. `xdrSha256` runs the entire `LedgerEntryChange` through the
streaming `XDRSHA256` hasher on every comparator call, regardless of
whether the first two tuple elements would have already disambiguated the
order. For a soroswap ledger with thousands of CONTRACT_DATA writes per
op, `std::sort` invokes the comparator O(n log n) times, each comparator
producing two SHA256 hashes of full LedgerEntry bodies. A short-circuiting
comparator could compute the hash lazily — only when the cheaper
`(LedgerKey, type)` tuple ties — eliminating nearly all SHA256 work in the
common case.

## Trigger

Run the soroswap apply-load benchmark and inspect `LedgerCloseMeta`
normalization during `closeLedgerInternal`. Each Soroban contract op
produces a `LedgerEntryChanges` vector that is sorted before publishing.

## Target Code

- `src/util/MetaUtils.cpp:55-70` — `CmpLedgerEntryChanges::operator()` and
  `sortChanges`
- `src/util/MetaUtils.h:13-18` — `normalizeMeta` declarations

## Evidence

`xdrSha256` is structurally expensive per call (XDRHasher streaming
serialization plus SHA256 finalization), and `std::sort`'s comparator runs
O(n log n) times rather than O(n). This produces strictly more SHA256 work
than necessary, and the asymmetry grows with soroswap's per-ledger write
volume.

## Anti-Evidence

The MetaUtils functions exist for `normalizeMeta(TransactionMeta&)` and
`normalizeMeta(LedgerCloseMeta&)`, which are utility/test helpers.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

`normalizeMeta` is **not called from the production apply path**. A repo-wide
search (`grep -rn "normalizeMeta" src/`) finds only one caller:
`src/ledger/test/LedgerCloseMetaStreamTests.cpp:531`. `sortChanges` itself is
file-local (anonymous namespace inside MetaUtils.cpp) and has no other
callers. The `xdrSha256` work in the comparator therefore never runs during
`closeLedger` in production or in the `apply-load` benchmark — the meta
emitted by `LedgerManagerImpl` is not normalized through this helper.
Optimizing it has zero apply-time impact.

### Lesson Learned

Before writing a hypothesis against a "looks expensive" comparator or
helper in `src/util/`, verify it is actually invoked from a `closeLedger`
descendant. The `MetaUtils.cpp` `sortChanges`/`xdrSha256` pair is one such
helper that exists only for test-side meta canonicalization and is not part
of the production apply path. Add `MetaUtils::sortChanges` /
`MetaUtils::normalizeMeta` to the list of "utility code that looks like
apply-path crypto but is test-only" alongside the patterns from fail meta
#4.
