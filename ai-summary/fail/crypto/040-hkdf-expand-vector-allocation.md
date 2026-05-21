# H040: Eliminate hkdfExpand Per-Call std::vector Allocation via Streaming HMAC

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low (zero impact on apply path)
**Impact**: apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`hkdfExpand(HmacSha256Key, ByteSlice)` (`src/crypto/SHA.cpp:124-134`)
implements single-step HKDF-Expand: `HMAC(key, bytes || 0x01)`. The
expected efficient implementation streams the input bytes plus the trailing
`0x01` byte into a single HMAC-SHA256 computation without copying the
entire input into a temporary heap buffer. For a small byte input (the
typical 32-byte ECDH shared-secret derivation case), the function should
allocate nothing on the heap.

## Mechanism

The actual implementation copies the entire `bin` ByteSlice into a
freshly-allocated `std::vector<uint8_t>`, appends a single `0x01` byte,
and passes the vector to `hmacSha256`. This forces a heap allocation
(plus a deallocation on return) per HKDF-expand call. A streaming-HMAC
implementation using libsodium's `crypto_auth_hmacsha256_init` /
`_update` / `_final` triplet would eliminate the vector entirely. The
deviation from expected behavior is that the implementation chooses a
copy-and-append shape over a streaming shape that libsodium directly
supports.

## Trigger

Any call to `hkdfExpand` allocates a vector with the size of the input
plus one byte. Audit `Curve25519::curve25519DeriveSharedKey` callers to
confirm the production call frequency.

## Target Code

- `src/crypto/SHA.cpp:124-134` — `hkdfExpand` body with vector allocation
- `src/crypto/Curve25519.cpp` — sole production caller via
  `curve25519DeriveSharedKey` (overlay PeerAuth)
- `src/overlay/PeerAuth.cpp` — establishes per-peer-session shared keys

## Evidence

The vector allocation is plainly visible at line 128. libsodium provides
the streaming HMAC interface (`crypto_auth_hmacsha256_state`,
`crypto_auth_hmacsha256_init`, `_update`, `_final`) that would eliminate
the allocation cleanly.

## Anti-Evidence

`hkdfExpand` is reachable **only from overlay peer-authentication code
paths**, not from `closeLedger` or any `applyLedger` descendant. H030
already established that `curve25519DeriveSharedKey` and HKDF helpers
belong exclusively to the overlay PeerAuth subsystem and are out of scope
for the optimize-soroswap objective. Per-peer-session HKDF is computed
once at peer-handshake time, not on the apply path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — H030 covered moving Curve25519 work off the apply
path generally; this hypothesis specifically targeted the vector
allocation shape inside `hkdfExpand`, which had not been individually
documented.

### Why It Failed

`hkdfExpand` is not on the `closeLedger` apply critical path. All its
production callers are in the overlay peer-authentication subsystem,
which is excluded by the OUT_OF_SCOPE list ("Anything outside
`closeLedger`: consensus, overlay, herder, SCP, history / catchup..."
). Even a perfect zero-allocation reimplementation has zero soroswap
apply-time impact.

### Lesson Learned

Before proposing any HMAC/HKDF/Curve25519 optimization, verify reachability
from `closeLedger`. The crypto subsystem exposes several primitives
(HMAC-SHA256, HKDF-Extract, HKDF-Expand, Curve25519 ECDH) whose production
callers all live in the overlay PeerAuth path. Per Meta-Pattern (H030), the
correct disposition for any such hypothesis is reject-at-hypothesis on
scope grounds, regardless of how clean the proposed change might be.
