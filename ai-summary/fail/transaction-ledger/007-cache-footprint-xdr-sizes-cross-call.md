# H007: Cache footprint `LedgerKey` XDR sizes on `TransactionFrame` to skip per-key `xdr_size` walks in `addReads` and `recordStorageChanges`

**Date**: 2026-05-02
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Avoid recomputing `xdr::xdr_size(lk)` per footprint key per Soroban tx in workers
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban transaction, the size of every footprint `LedgerKey` (RO
and RW) is a deterministic function of the key XDR. The size should be
computed once when the `TransactionFrame` is constructed (or when the
soroban resources XDR is first parsed) and reused for the lifetime of the
frame. The apply-time helpers `InvokeHostFunctionApplyHelper::addReads`
(`InvokeHostFunctionOpFrame.cpp:398`) and `recordStorageChanges`
(`InvokeHostFunctionOpFrame.cpp:701`) should consume cached sizes instead of
calling `xdr::xdr_size(lk)` on every key on every invocation.

## Mechanism

`addReads` walks both the RO and RW footprints in worker threads and computes
`uint32_t keySize = xdr::xdr_size(lk);` for every key on line 398. The
result feeds `meterDiskReadResource(lk, keySize, entrySize)` for non-Soroban
keys (and is unused for Soroban keys on the v23+ path, but the sizing call
still happens unconditionally).

`recordStorageChanges` similarly computes `xdr::xdr_size(lk)` on line 701 for
every modified-entry key returned by the host. Both calls walk the XDR
structure of the key and accumulate per-field sizes — non-trivial work on a
hot per-tx loop in workers. The same per-tx footprint key is sized twice on
the RO path (once in `addReads`, once if it appears as a modified entry) and
RW keys are sized 1–3 times per tx across the apply lifecycle. Caching one
`uint32_t` per footprint key on `TransactionFrame` eliminates this redundant
serialization-bookkeeping.

## Trigger

Every Soroban transaction with a non-trivial footprint (soroswap has eight
footprint keys per tx). Aggregate work scales with `txs × footprint_size`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:398` —
  `uint32_t keySize = static_cast<uint32_t>(xdr::xdr_size(lk));` in
  `addReads`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:701` —
  `uint32_t keySize = static_cast<uint32_t>(xdr::xdr_size(lk));` in
  `recordStorageChanges`.
- `src/transactions/TransactionFrame.cpp` constructor — natural place to
  precompute the footprint key sizes vector.

## Evidence

- `addReads` aggregate self-time in soroswap trace: 149 ms / 10294 calls ≈
  14.5 µs per call, 2 calls per Soroban tx.
- `recordStorageChanges` aggregate self-time: 44 ms / 5093 calls ≈ 8.7 µs
  per call.
- `xdr_size(lk)` on a typical footprint `LedgerKey` (CONTRACT_DATA with
  `ScVal` key body) walks 5–10 nested XDR fields, dominating per-key work
  in addReads' inner loop on the v23+ Soroban path where
  `meterDiskReadResource` is gated off for soroban keys.

## Anti-Evidence

- Both `addReads` and `recordStorageChanges` include other per-key work
  (`isSorobanEntry`, `getTTLKey`, footprint linear scans, entry XDR
  decode/upsert) that dominates the per-tx self-time.
- Critical-path estimate: `addReads` is in workers, so 149 ms / 8 / 70 ≈
  0.27 ms/ledger. `recordStorageChanges` similarly: 44 ms / 8 / 70 ≈
  0.08 ms/ledger. Combined ~0.35 ms/ledger ≈ 0.13 % of the 278 ms soroswap
  median.
- This overlaps the existing fail `002-skip-xdr-size-on-soroban-path.md`,
  which gated the `addReads` `xdr_size` only on the non-Soroban path and
  was rejected at 0.6–1.3 % as below the Medium 3 % floor. Caching across
  both call sites instead of merely gating one site does not change the
  asymptotic ceiling — most of the `xdr_size` work is in `addReads`, which
  the prior fail already bounded.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS for the cross-cite-caching framing — the prior fail
`002-skip-xdr-size-on-soroban-path` proposed *gating* the `addReads`
`xdr_size` behind a version/type check. This hypothesis additionally targets
`recordStorageChanges:701` and proposes precomputing the sizes on the
TransactionFrame for reuse across all sites. The reframing is novel, but
the impact ceiling is the same.

### Why It Failed

Even the broader cross-site-caching variant cannot exceed the impact ceiling
of the prior `002-skip-xdr-size-on-soroban-path` fail. That fail measured
the `addReads` `xdr_size` cost at 0.6–1.3 % of soroswap apply, below the
3 % Medium floor. Adding the `recordStorageChanges` cache hit increases the
ceiling by at most another ~0.1 % (the `recordStorageChanges` self-time
share is one third of `addReads`, divided by 8 clusters). The combined
optimization remains below the Medium severity threshold required by the
optimize-soroswap objective.

### Lesson Learned

Cross-site caching of a per-key XDR size is an architecturally cleaner form
of the existing `xdr_size`-gating approach but cannot break the prior fail's
~1.5 % impact ceiling. Future hypotheses targeting per-key footprint
bookkeeping must either eliminate a much larger cost per key (e.g., the
full `xdr_from_opaque` ledger-entry decode in `recordStorageChanges`) or
combine with a broader redesign of the parallel-apply per-tx pre/post
processing to reach Medium.
