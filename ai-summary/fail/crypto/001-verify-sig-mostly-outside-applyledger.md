# H001: Optimize Signature Verification Cache for Soroswap Apply

**Date**: 2026-04-27
**Subsystem**: crypto, transactions
**Severity**: Medium
**Impact**: signature verification CPU reduction, but not in measured soroswap apply path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

An optimization to `PubKeyUtils::verifySig` should only count for this objective if it reduces time spent under `applyLedger` during `closeLedger`. Signature verification must continue to validate Ed25519 signatures exactly, preserve cache hit/miss semantics, and return the same `VerifySigResult` values for transaction authorization.

## Mechanism

The initial observation looked promising because `verifySig` is the largest self-time zone in the full soroswap Tracy trace. However, the full trace includes transaction validation and tx-set construction work outside the benchmark's measured apply window. Timestamp overlap against `applyLedger` shows that nearly all expensive signature verification, including Rust dalek verification, happens outside `applyLedger`, so optimizing it would not materially improve the objective metric.

## Trigger

Run the current soroswap apply-load benchmark with Tracy enabled and inspect full-trace self-time. `verifySig` appears at the top of the global self-time table, then disappears when filtered by overlap with `applyLedger`.

## Target Code

- `src/crypto/SecretKey.cpp:469-520` - `PubKeyUtils::verifySig` computes cache keys, checks the sharded cache, and verifies Ed25519 signatures on misses.
- `src/rust/src/ed25519_verify.rs:16-40` - Rust dalek verification path used by `verifySig` on cache misses.
- `src/transactions/SignatureChecker.cpp:33-143` - transaction signature checking calls into `SignatureUtils::verify` and `PubKeyUtils::verifySig`.

## Evidence

`csvexport-release -e` on `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy` reports `verifySig,crypto/SecretKey.cpp,473` at 6,304,457,990 ns self-time and `verify_ed25519_signature_dalek,src/rust/src/ed25519_verify.rs,23` at 2,848,199,145 ns self-time. This initially suggested a major crypto bottleneck.

## Anti-Evidence

Exporting individual events with `csvexport-release -u` and comparing event timestamps to the 65 `applyLedger` windows shows only 68,095,194 ns of `verifySig` total duration inside `applyLedger` out of 9,215,370,946 ns total, and zero `verify_ed25519_signature_dalek` events inside `applyLedger`. The expensive misses are therefore validation/tx-set work, while the in-apply calls are cheap cache-hit/check paths and below the objective's Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelty**: PASS - not previously investigated in the empty crypto record set

### Why It Failed

The apparent hotspot is mostly outside `applyLedger`, and this objective explicitly excludes tx-set construction and validation work that is not part of the measured `closeLedger` apply window.

### Lesson Learned

For crypto zones in apply-load traces, always timestamp-check overlap with `applyLedger`; global self-time is misleading because signature verification is heavily exercised before the benchmark's measured apply phase.
