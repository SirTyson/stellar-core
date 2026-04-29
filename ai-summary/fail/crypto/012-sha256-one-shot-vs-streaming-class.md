# H012: Replace `SHA256` Class with One-Shot OpenSSL `::SHA256` for Single-Buffer Apply-Path Hashes (`getTTLKey`, `subSha256`, contents/full hashes)

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Low (proposed) → rejected
**Impact**: remove `SHA256_Init` + per-`add` Tracy zone + `SHA256_Final`
overhead from short-input apply-path SHA256 callsites by collapsing them
to a single OpenSSL `::SHA256(buf, len, out)` one-shot call
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Apply-path SHA256 callsites that hash a single contiguous XDR buffer (or
two trivially concatenable inputs) should use OpenSSL's one-shot
`::SHA256(data, len, out)` rather than constructing a `stellar::SHA256`,
calling `add()` (which itself enters a Tracy zone and updates an
`SHA256_CTX`), and then calling `finish()`. The streaming-class overhead
is justified for genuinely streaming uses (e.g., the hot
`finalizeSuccess` preimage hash that concatenates a result-value buffer
with a length prefix and per-event buffers), but for short callers like
`getTTLKey` and `subSha256` the one-shot path skips two extra context
operations and one Tracy ZoneScoped per call.

## Mechanism

`getTTLKey(LedgerKey)` is the dominant apply-window SHA256 caller (per
the crypto fail-summary's H003/H004 records establishing ~4.17 ms per
soroswap ledger of in-apply SHA256 budget, dominated by TTL-key
derivation). Each call XDR-encodes the `LedgerKey` and SHA256-hashes the
result via `xdrSha256<LedgerKey>` → `XDRSHA256` → multiple `add()` calls.
Replacing the class wrapper with a serialize-once-then-`::SHA256` shape
would (a) skip the per-`add` `ZoneScoped` Tracy entry/exit overhead, (b)
skip the redundant `SHA256_Init` / `SHA256_Final` pair when the input is
already buffered, and (c) let the OpenSSL one-shot select SHA-NI
intrinsics on a single call rather than across multiple `SHA256_Update`
invocations.

The `subSha256(seed, counter)` PRNG sub-seed path
(`src/crypto/SHA.cpp:42-48`) is similar: two trivially concatenable
inputs (32-byte seed + 8-byte counter) currently pay class-wrapper
overhead and an XDR opaque allocation for the counter.

## Trigger

Run the soroswap apply-load benchmark and inspect the `sha256` and
`add,crypto/SHA.cpp:65` zones inside `applyLedger` descendants. Replace
the `XDRSHA256`-based `getTTLKey` derivation with a serialize-once-then-
`::SHA256` form and re-measure.

## Target Code

- `src/crypto/SHA.cpp:30-38` — `sha256(ByteSlice)` one-shot wrapper
  (already uses `::SHA256`)
- `src/crypto/SHA.cpp:50-86` — `SHA256` class with per-`add` `ZoneScoped`
- `src/crypto/SHA.cpp:42-48` — `subSha256(seed, counter)` two-input
  streaming caller
- `src/ledger/LedgerHashUtils.h` — `getTTLKey()` callers (the dominant
  apply-window SHA256 driver per H003/H004)
- `src/ledger/InMemorySorobanState.cpp:127, 223, 248, 285, 311` —
  per-entry TTL-key derivations on the apply path

## Evidence

- Tracy trace `…-02-soroswap-tx-2000-t-8.tracy`:
  `sha256,crypto/SHA.cpp:33` is 499.8 ms self / 324 892 calls
  (~1.5 µs mean), and `add,crypto/SHA.cpp:65` is 244.7 ms self /
  1 278 995 calls (~191 ns mean). With Tracy enabled, a substantial
  fraction of the per-`add` mean is the `ZoneScoped` instrumentation
  overhead itself, which would not exist on the production
  (non-Tracy) build.
- One-shot `::SHA256` already exists and is used by the free
  `sha256()` function.
- `SHA256_CTX` setup is non-trivial (112 bytes of state, per the
  static_assert at `src/crypto/SHA.cpp:14`), and skipping its
  initialization for short-input callers is a legitimate micro-win.

## Anti-Evidence

- The crypto fail-summary's "SHA256 / Hashing Budget Ceiling"
  meta-pattern caps the entire in-apply SHA256 budget at ~4.17 ms per
  soroswap ledger out of a 595 ms median apply window — ~0.7 % of
  apply. Even fully eliminating SHA256 work cannot reach the 1 % Low
  floor, let alone the 3 % Medium floor.
- The per-`add` `ZoneScoped` overhead the trace highlights is a Tracy
  artefact: the production benchmark runs without Tracy, so removing
  it does not change the authoritative apply-time numbers.
- `getTTLKey` derivation is bounded by the H003/H004 review, which
  established that caching/eliminating it cannot reach Medium even
  in the optimistic limit.
- The streaming `SHA256` class is the right shape for the
  `finalizeSuccess` preimage hash, which is the single largest in-apply
  SHA256 caller by bytes (it concatenates the result-value XDR with a
  length-prefixed event array). One-shot conversion would force a
  redundant intermediate buffer there, paying a copy to save
  context-init cost — net regression for the dominant in-apply caller.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — switching short-input apply-path callers from the
`SHA256` streaming class to one-shot `::SHA256` (as distinct from the
H003/H004 caching strategies for `getTTLKey`) was not previously
investigated in crypto fail/hypothesis/reviewed/poc records.

### Why It Failed

The proposal lives entirely under the SHA256 budget ceiling
(H003/H004), which is structurally below the 1 % Low floor for this
objective. The headline per-call overhead in the Tracy trace is
`ZoneScoped` instrumentation that does not exist in the authoritative
non-Tracy benchmark, so the projected wall-clock saving is even
smaller than the SHA256 budget alone implies. The `finalizeSuccess`
preimage hash — the single largest in-apply SHA256 caller by bytes —
genuinely needs the streaming class shape, and forcing a one-shot
replacement there would add a copy.

### Lesson Learned

Tracy `ZoneScoped` overhead in fine-grained crypto primitives can
inflate apparent per-call costs in the diagnostic trace by 50 %+
relative to the production benchmark. Future hypotheses about
hashing-primitive overhead must be sized against the SHA256 / hashing
budget ceiling already established in the crypto fail-summary, and
must justify the saving in non-Tracy terms.
