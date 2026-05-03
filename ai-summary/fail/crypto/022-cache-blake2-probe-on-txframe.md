# H022: Cache `verifySigCacheKey` BLAKE2 result on `TransactionFrame` to skip per-apply recompute

**Date**: 2026-05-03
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time BLAKE2 reduction on signature cache probe path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the same `(public_key, signature, message)` tuple is signature-verified
multiple times across a transaction's lifecycle (e.g., during validation,
fee processing, and apply), the BLAKE2 cache-probe key should be computed
only once and reused. Subsequent verifySig calls inside `applyLedger`
should look up the cached BLAKE2 hash on the `TransactionFrame` rather
than recomputing it from public key + signature + message bytes on every
call.

## Mechanism

`PubKeyUtils::verifySig` (`SecretKey.cpp:480`) calls
`verifySigCacheKey(key, signature, bin)` on every invocation, computing a
BLAKE2 hash over the public key (32 B), signature (64 B), and message
(typically the transaction signature payload, ~hundreds of bytes). This
work is identical across the validate-time and apply-time calls for the
same `(tx, signer)` pair. A hypothesis would propose attaching the cached
BLAKE2 cache-key to each `(SignatureChecker, signer-index)` slot on the
`TransactionFrame` so the apply-path probe skips the BLAKE2 hash entirely
and indexes directly into the sharded cache.

## Trigger

Run the soroswap apply-load benchmark and aggregate self-time for
`add,crypto/BLAKE2.cpp,50` and `verifySigCacheKey`-attributed BLAKE2 work
whose Tracy parent is a descendant of `applyLedger`.

## Target Code

- `src/crypto/SecretKey.cpp:73-84` — `verifySigCacheKey` BLAKE2 computation.
- `src/crypto/SecretKey.cpp:469-520` — `PubKeyUtils::verifySig` call site
  (BLAKE2 work is the first thing it does).
- `src/transactions/SignatureChecker.h` / `.cpp` — would need to gain a
  per-signer cache-key memo slot.
- `src/transactions/TransactionFrame.cpp:578` —
  `checkAllTransactionSignatures` apply-path entry into the verify path.
- `src/transactions/TransactionFrame.cpp:1588` — `processSignatures` apply
  entry.

## Evidence

`add,crypto/BLAKE2.cpp,50` shows 45 ms self-time across 1.08 M calls in
the soroswap diagnostic trace. A meaningful subset originates inside
`verifySigCacheKey` for cache-hit verifySig calls on the apply path, so
removing the BLAKE2 recompute would shave a portion of this work
specifically attributable to apply.

## Anti-Evidence

The dominant BLAKE2 callers are out-of-scope overlay paths
(`Floodgate::flood`, `Peer::recvMessage`, `Tracker::recv`, all in
`src/overlay/`) and out-of-scope `BucketManager::visitLedgerEntries`
(`BucketManager.cpp:1738, 1762`, called only from CLI commands). The
apply-path BLAKE2 share is bounded by the same ~46 ms ceiling that
Meta-Pattern 5 establishes for the entire apply-path verifySig surface,
because BLAKE2 is part of every verifySig call's prelude. BLAKE2 cannot
exceed verifySig in-apply share.

The realistic split: 360 K total `verifySig` calls in the trace, of which
the apply-path share is bounded by ~45-50 K calls (per Meta-Pattern 5's
46 ms / ~1 µs-per-call estimate). At a generous 200 ns per BLAKE2 cache
key, that is at most ~10 ms across the run — about 0.1% of apply time.
Three orders of magnitude below the 3% Medium floor.

Per Meta-Pattern 7 (Tracy ZoneScoped overhead inflates crypto primitive
costs), the headline 45 ms `BLAKE2::add` self-time also includes
substantial Tracy instrumentation overhead that does not exist in the
non-Tracy production benchmark. Sizing against the non-Tracy SHA/BLAKE2
budget ceiling (~0.67% combined per Meta-Pattern 1) puts apply-path
BLAKE2 work at the small remainder after SHA256 dominates that ceiling.

H009 (shorten cache key to skip message bytes) targeted the *content* of
the BLAKE2 hash; this hypothesis targets *eliminating* the BLAKE2 call on
re-verifies. Both are bounded by the same Meta-Pattern 5 ceiling.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H001 (contents-hash streaming), H005
(cached contents-hash apply accessors), H008 (sticky-flag verifySig
bypass), H009 (shorter cache key). H022 specifically proposes memoizing
the BLAKE2 cache-key on `TransactionFrame` so apply-time probes skip
BLAKE2 entirely.

### Why It Failed

The total apply-path verifySig surface is bounded by Meta-Pattern 5 at
~46 ms across the 65-ledger soroswap run (~0.2% of apply time). The
BLAKE2 cache-probe work is a strict subset of that surface — it cannot
exceed ~10 ms total even under generous assumptions. Eliminating it
entirely yields ~0.04% apply-time improvement, three orders of magnitude
below the 3% Medium severity threshold this objective accepts.

The BLAKE2 work that *does* matter (45 ms self-time) is dominated by
out-of-scope overlay flood/peer/tracker callsites and out-of-scope
`BucketManager::visitLedgerEntries` CLI paths. None of these are
reachable from `closeLedger` in the soroswap workload.

Plumbing per-signer cache-key memos through `SignatureChecker` and
`TransactionFrame` adds non-trivial complexity (memory ownership across
transaction-lifecycle phases, cache invalidation on signer rotation,
serialization across pre/post-apply parallelism) for a sub-noise win.

### Lesson Learned

Future BLAKE2 hypotheses must:

1. Verify the target callsite is reachable from `closeLedger` —
   `verifySigCacheKey` is the only apply-path BLAKE2 caller; all other
   BLAKE2 use lives in overlay (out of scope) or CLI tools (out of scope).
2. Size against Meta-Pattern 5's apply-path verifySig ceiling (~0.2%),
   since BLAKE2 work is bounded above by total verifySig work.
3. Per Meta-Pattern 7, treat headline `BLAKE2::add` self-time in Tracy
   traces as inflated by ZoneScoped overhead; the production-build
   non-Tracy share is significantly smaller.

Augment Meta-Pattern 5: "the apply-path verifySig surface (including its
BLAKE2 cache-probe prelude) is bounded at <0.2% of apply time". This
covers H008, H009, H021, and H022 collectively; future hypotheses that
target any micro-optimization inside `PubKeyUtils::verifySig` should be
rejected up-front against this ceiling.
