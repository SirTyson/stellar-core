# H061: Eliminate `ByteSlice::operator[]` bounds check from crypto hot loops

**Date**: 2026-05-22
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — no callers use the checked path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ByteSlice::operator[]` (`src/crypto/ByteSlice.h`) performs a runtime
`releaseAssert(i < mSize)` on every access. For any tight loop that iterates
byte-by-byte over a `ByteSlice` payload during apply (signature verification,
streaming hash update, XDR archive serialization), the correct hot-path
behavior is to use the unchecked raw pointer (`data()` + `size()`) rather
than indexing through the bounds-checked subscript operator, so that each
byte access is a single load rather than a load + compare + branch.

## Mechanism

If any of the apply-path crypto primitives (libsodium, BLAKE2, SHA256,
SipHash, HMAC, or the `XDRHasher` buffer-copy path) reached into a
`ByteSlice` via `operator[]` inside a tight loop, the per-byte
`releaseAssert` would dominate the instruction stream. Removing the bounds
check (or switching to pointer arithmetic) would yield a measurable
reduction on the apply path proportional to total bytes hashed/verified.

## Trigger

Run soroswap; look for elevated self-time in `BLAKE2::add`, `SHA256::add`,
or `verifySig` proportional to total payload bytes hashed and check whether
any callees touch `ByteSlice::operator[]` in a loop.

## Target Code

- `src/crypto/ByteSlice.h` — `operator[]` definition with `releaseAssert`
- `src/crypto/SHA.cpp:65-80` — `SHA256::add`
- `src/crypto/BLAKE2.cpp:47-58` — `BLAKE2::add`
- `src/crypto/ShortHash.cpp` — `shortHash::computeHash`
- `src/crypto/SecretKey.cpp:73-84` — `verifySigCacheKey` (three `add` calls)
- `src/crypto/XDRHasher.h` — `XDRHasher::queueOrHash`, `hashBytes`

## Evidence

Tracy reports `SHA256::add` at 2.84% trace self-time and `BLAKE2::add` at
0.41% trace self-time. Inflated by Tracy `ZoneScoped` (Meta-Pattern 7) but
still non-trivial in non-Tracy builds. Bounds-check elimination in tight
byte loops is a standard micro-optimization with measurable impact when the
loop body is small enough that the branch is comparable to the load itself.

## Anti-Evidence

Audit of every `ByteSlice` consumer in `src/crypto/`:

- `SHA256::add`, `BLAKE2::add`, `shortHash::computeHash`, `hmacSha256`,
  `hkdfExtract`, `hkdfExpand`, `curve25519Encrypt`, `crypto_sign_detached`
  callers — all pass `bin.data()` and `bin.size()` straight to libsodium.
  Libsodium consumes the raw pointer; no per-byte `ByteSlice::operator[]`
  access occurs.
- `XDRHasher::queueOrHash` uses `std::memcpy(mBuf + mBufSize, bytes, size)`
  and pointer offsetting, never `operator[]`.
- `xdrSha256` / `xdrBlake2` / `xdrComputeHash` use the `XDRHasher` archiver,
  which uses `xdr::archive` and byte-wise `memcpy`, again no `operator[]`.

`grep -rn 'mSlice\[' src/crypto/ src/transactions/ src/ledger/ src/bucket/`
returns no matches; `ByteSlice::operator[]` has no production hot-path
consumer. It exists only for test code (e.g., `Hex` decode validation).
Bounds-check elimination cannot affect apply time because the checked
access pattern is not used.

This is also bounded by Meta-Patterns 1 (SHA256 < 0.67%), 5 (verifySig
< 0.2%), and 7 (Tracy `ZoneScoped` inflates per-`add` self-time): even
the maximally optimistic estimate (full elimination of all crypto-loop
overhead) cannot exceed the per-primitive ceilings, all of which are
sub-1% of apply.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

`ByteSlice::operator[]` is not invoked from any apply-path crypto primitive.
All hashers use `data() + size()` and hand the buffer to libsodium, which
uses raw pointers internally. No instructions are saved by removing the
unused bounds-check path. The hypothesis fails not on severity, but on
"the optimization target does not exist in the hot path."

### Lesson Learned

Before proposing a bounds-check / inlining / branch-prediction
micro-optimization on a `ByteSlice` accessor or any small inline helper,
grep all callers to confirm the optimized access pattern is actually used.
`ByteSlice` consumers in production code use the raw pointer interface;
`operator[]` is a test/validation convenience and contributes zero to
apply-time.
