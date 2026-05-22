# H060: Eliminate `xdrBlake2(LedgerEntryKey)` in `visitBucketEntries` deduplication set

**Date**: 2026-05-22
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected as out-of-scope)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`visitBucketEntries` (`src/bucket/BucketManager.cpp:1684`) is a helper used to
walk a `BucketInputIterator` over a single bucket and deduplicate entries by
inserting `xdrBlake2(LedgerEntryKey(liveEntry))` (line 1738) or
`xdrBlake2(getDeadEntryKey(e))` (line 1762) into an `UnorderedSet<Hash>` named
`processedEntries`. For a workload that exercises this helper at scale, the
correct behavior is to deduplicate using a hash that costs at most a single
SipHash of the key bytes (consistent with `LedgerKey` hashing elsewhere) rather
than a 32-byte BLAKE2 digest of an XDR-serialized key, since the cryptographic
collision resistance of BLAKE2 is not required for in-memory deduplication.

## Mechanism

`xdrBlake2` on a `LedgerKey` allocates and streams the XDR encoding through a
full BLAKE2b initialization, update sequence, and finalization (libsodium
`crypto_generichash_init`/`update`/`final`). For an `UnorderedSet<Hash>` key,
SipHash over the same bytes (the existing `std::hash<LedgerKey>` machinery
via `shortHash::xdrComputeHash`) would yield equivalent dedup behaviour at a
fraction of the per-key cost. If `visitBucketEntries` were a `closeLedger`
descendant under soroswap, swapping the BLAKE2 hash for SipHash could meaningfully
reduce apply-time crypto load.

## Trigger

Run the soroswap benchmark and look for `visitBucketEntries` zones inside
`applyLedger`. The expected reduction would scale with the number of
`xdrBlake2` calls inside the apply window.

## Target Code

- `src/bucket/BucketManager.cpp:1684-1766` — `visitBucketEntries` template
- `src/bucket/BucketManager.cpp:1738,1762` — `processedEntries.insert(xdrBlake2(...))`
- `src/bucket/BucketManager.cpp:1660-1680` — `mergeBuckets` caller
- `src/crypto/BLAKE2.cpp:31-74` — `BLAKE2` init/add/finish path

## Evidence

The `xdrBlake2` callsite is real, performs cryptographic-strength hashing on
an in-memory dedup hot loop, and matches a pattern documented in
Meta-Pattern 6 (over-strong hashing for in-memory containers). The crypto/SHA
zone summary shows BLAKE2 self-time at 0.41% of total trace; if any of that
share fell inside `applyLedger`, this would be an actionable optimization.

## Anti-Evidence

Tracing the caller chain shows `visitBucketEntries` is reachable only from
`BucketManager::visitLedgerEntries`, which is called by:
- `LedgerCloseMetaStream` tooling
- `dump-ledger` / `dump-bucket` CLI commands
- Replay verification utilities

None of these are reachable from `closeLedger`. The soroswap benchmark does
not invoke any of them during the measured apply window. Tracy zone search
for `visitBucketEntries`/`visitLedgerEntries` shows zero events inside the
trace, confirming this helper does not run during apply.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

`visitBucketEntries` is bucket-replay/tooling code path, not a `closeLedger`
descendant. The hypothesis is structurally out-of-scope per the objective's
"closeLedger only" constraint. Confirms Meta-Pattern 11 (crypto callsites
must be verified as `applyLedger` descendants before sizing). Adds a new
specific instance: BucketManager helpers that look hot in process-wide
trace totals are dominated by tooling/replay callers, not apply.

### Lesson Learned

Before proposing any `xdrBlake2`/`xdrSha256` apply-path optimization in
bucket code, grep for the enclosing function's callers and confirm at
least one is a `closeLedger` descendant. `visitBucketEntries`,
`mergeBuckets`, `loadCompleteLedgerState`, and similar full-bucket scan
helpers are never invoked from apply.
