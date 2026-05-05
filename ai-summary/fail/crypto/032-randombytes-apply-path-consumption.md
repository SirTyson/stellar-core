# H032: randomBytes / HashUtils::random Apply-Path Consumption

**Date**: 2026-05-05
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`randomBytes(size_t)` (`src/crypto/Random.cpp`) calls libsodium's
`randombytes_buf`, which in turn pulls entropy from the kernel via
`getrandom(2)` / `/dev/urandom`. A syscall-backed RNG draw is expensive
(~1–10 µs) compared to in-process work. The expected behavior is that
no descendant of `closeLedger` consumes `randomBytes` or
`HashUtils::random()` per-tx or per-entry, because deterministic ledger
apply must not depend on non-deterministic per-node randomness.

## Mechanism

If `randomBytes` were called on a per-tx or per-entry frequency from a
`closeLedger` descendant, the syscall overhead would compound across
soroswap's ~2000 tx/ledger × N entries/tx and could reach the 1% Low
floor or beyond. Soroban's `base_prng_seed` is the most likely candidate:
it is a per-tx 32-byte seed that crosses the FFI bridge into the host.
If the C++ side allocates the seed via `randomBytes(32)` per tx during
apply (rather than precomputing it deterministically from the tx hash
or LCL hash), the syscall cost would be on the soroswap apply critical
path. Self-rejected after a repo-wide grep showed all production
`randomBytes` callers are confined to non-apply-path infrastructure
(bucket file naming via `BucketBase.cpp:128`, key-pair generation via
`SecretKey.cpp`) and test/SDK utilities (`InvokeHostFunctionTests.cpp`,
`LedgerCloseMetaStreamTests.cpp`).

## Trigger

Apply soroswap ledgers (TX=2000, T=8) and check whether any
`closeLedger` descendant (tx apply, op apply, ParallelApplyUtils,
InvokeHostFunctionOpFrame, `commitChangesToLedgerTxn`) calls
`randomBytes` or `HashUtils::random`.

## Target Code

- `src/crypto/Random.cpp:14-25` — `randomBytes` libsodium call
- `src/crypto/SecretKey.cpp` — `HashUtils::random()` (`randombytes_buf`
  on a 32-byte buffer)
- `src/bucket/BucketBase.cpp:128` — `randomBytes(8)` for tmp-bucket
  filenames (per-bucket-file, not per-entry)
- `src/transactions/InvokeHostFunctionOpFrame.cpp` — Soroban
  `base_prng_seed` construction (the candidate apply-path caller)

## Evidence

- libsodium `randombytes_buf` is syscall-backed and individually
  expensive (~1–10 µs per call).
- Soroban host requires a per-tx PRNG seed; if drawn from kernel entropy
  per-tx, the cost would scale with tx count.
- `BucketBase.cpp:128` confirms `randomBytes` IS reachable from a
  `closeLedger` descendant (`addLiveBatch` -> bucket file write ->
  `randomFileName`), so per-bucket-file syscall cost is on the apply
  path.

## Anti-Evidence

- Repo-wide grep `randomBytes|HashUtils::random` in `src/transactions/`
  and `src/ledger/` returns ZERO production hits — only tests
  (`InvokeHostFunctionTests.cpp:3696,8050`,
  `LedgerCloseMetaStreamTests.cpp:48,297`).
- The Soroban `base_prng_seed` is constructed deterministically from
  the tx hash inside `InvokeHostFunctionOpFrame`, not via `randomBytes`,
  preserving deterministic apply across nodes (a `randomBytes`-derived
  seed would break consensus).
- The `BucketBase.cpp:128` `randomBytes(8)` call fires once per
  level-0 bucket file write per `addLiveBatch`, which is once per
  `closeLedger` — i.e., O(1) per ledger, not O(tx) or O(entry). At
  ~10 µs/call × 1 call/ledger = 0.0015% of the 272 ms soroswap apply
  median. Two orders of magnitude below the 1% Low floor.
- `HashUtils::random()` callers in `src/` are limited to test code and
  startup-time keypair generation, not apply.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — prior hypotheses covered hashing primitives
(SHA256, BLAKE2, SipHash), Curve25519/HKDF/HMAC, base64, and ed25519
verify, but none specifically audited the `randomBytes` /
`HashUtils::random` syscall-backed entropy primitive's apply-path
reachability.

### Why It Failed

Below objective severity threshold — and structurally so. The only
production `randomBytes` caller reachable from `closeLedger` is
`BucketBase::randomFileName` via `addLiveBatch`, which fires once per
ledger close (not per-tx, not per-entry). At ~10 µs/call × 1 call /
272 ms apply, the contribution is 0.0015% — three orders of magnitude
below the 1% Low floor. Soroban's per-tx PRNG seed must be deterministic
across nodes and is therefore derived from the tx hash, not from
`randomBytes`; replacing the existing deterministic derivation with
kernel entropy would break consensus and is non-viable for an entirely
separate reason.

### Lesson Learned

Before sizing a hypothesis around an expensive syscall-backed
cryptographic primitive (`randomBytes`, `HashUtils::random`,
`crypto_secretbox`, AEAD primitives), confirm via repo-wide grep that
the function is reachable from a `closeLedger` descendant AND that the
per-call frequency scales with apply work (per-tx or per-entry), not
just per-ledger. Per-ledger-O(1) syscall costs land four orders of
magnitude below the optimize-soroswap severity floor regardless of
absolute syscall expense. This complements H016's lesson for base64
and H030's lesson for Curve25519/HKDF: scope-discipline matters more
than primitive cost when sizing crypto hypotheses.
