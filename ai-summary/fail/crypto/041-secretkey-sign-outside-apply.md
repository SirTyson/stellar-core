# H041: SecretKey Signing Cost Is TX-Generation Work Outside Apply

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low (zero impact on apply path)
**Impact**: apply-time
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`SecretKey::sign(ByteSlice)` should only be considered for this objective if the
signing work occurs inside `closeLedger` / `applyLedger`. If a soroswap ledger is
already built and passed to apply, no new Ed25519 signatures should be generated
on the apply critical path; apply should only validate and execute transactions.

## Mechanism

The raw Tracy self-time for `SecretKey::sign` looks large enough to tempt an
optimization: the current soroswap diagnostic trace reports
`sign,crypto/SecretKey.cpp,159` at 641,699,326 ns across 34,072 calls, and
`sign,transactions/SignatureUtils.cpp,23` at 639,659,111 ns across 33,930
calls. However, this signing is benchmark transaction construction work, not
ledger apply work. Optimizing it would reduce TX-set/test setup time but would
not reduce the measured soroswap apply-time metric.

## Trigger

Run the current diagnostic trace from `ai-summary/CURRENT_STATE.md` and compare
unwrapped `sign` events against unwrapped `applyLedger` windows:

```sh
./lib/tracy/csvexport/build/unix/csvexport-release -u -f applyLedger \
  /mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy
./lib/tracy/csvexport/build/unix/csvexport-release -u -f sign \
  /mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy
```

The `SecretKey.cpp:159` and `SignatureUtils.cpp:23` signing events have
0 ns overlap with the 71 `applyLedger` windows.

## Target Code

- `src/crypto/SecretKey.cpp:156-169` — Ed25519 detached signing wrapper
- `src/transactions/SignatureUtils.cpp:20-28` — decorated transaction signature
  creation wrapper that calls `SecretKey::sign`

## Evidence

The source code is a straightforward Ed25519 signing path: `SignatureUtils::sign`
creates a `DecoratedSignature`, calls `secretKey.sign(hash)`, then attaches the
public-key hint. The current Tracy self-time profile reports substantial
aggregate signing time, but unwrap-mode containment shows `SecretKey::sign`:
34,072 events / 641,699,326 ns total / **0 ns inside `applyLedger`**, and
`SignatureUtils::sign`: 33,930 events / 639,659,111 ns total / **0 ns inside
`applyLedger`**.

## Anti-Evidence

This path is excluded by the objective because TX set creation is a testing
artifact, not part of `closeLedger`. The apply-contained signature-related work
in this trace is verification and signature-list processing, which is already
covered by the fail-summary ceiling for apply-path `verifySig` / BLAKE2 work
(well below 1% of apply).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — prior crypto failures covered signature verification and
transaction contents hashes, but not the separate `SecretKey::sign` TX-generation
hotspot.

### Why It Failed

The expensive `SecretKey::sign` and `SignatureUtils::sign` events are entirely
outside the `applyLedger` windows in the current soroswap Tracy trace. They are
part of benchmark transaction construction / signing, so optimizing them cannot
move the measured apply-time result.

### Lesson Learned

Crypto signing hotspots in apply-load traces must be unwrap-filtered before
promotion. Signing cost is usually TX construction; only apply-contained
verification or host crypto calls can affect this objective, and those existing
surfaces are already bounded below the Medium threshold.
