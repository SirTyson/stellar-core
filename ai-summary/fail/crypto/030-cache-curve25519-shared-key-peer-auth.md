# H030: Move Curve25519 / HKDF Cost Off Apply Path

**Date**: 2026-05-04
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Curve25519` ECDH (`crypto_scalarmult`) and HKDF
(`hkdfExtract` → `hmacSha256`) are expensive cryptographic primitives
(~40 µs per Curve25519 multiplication). They appear in
`src/crypto/Curve25519.cpp` and are used to derive per-peer shared
session keys in the overlay subsystem. The expected behavior is that
these primitives never run inside `closeLedger` — they should be
exclusively used for peer-handshake key agreement and HMAC session
setup in the overlay layer, which is out of scope for the
optimize-soroswap apply-time objective.

## Mechanism

The hypothesis was that `curve25519DeriveSharedKey`, `hkdfExtract`, or
`hmacSha256` might be invoked from a `closeLedger` descendant — for
example in a ledger-close-triggered flood/relay path, or in a
`StellarMessage` HMAC computation tied to externalize processing —
where it would add measurable apply-time cost given the ~40 µs per
ECDH and ~1 µs per HMAC primitive cost. If a per-tx or per-ledger
flood-path HMAC sat inside `applyLedger`, it could in aggregate reach
the 3% Medium floor.

## Trigger

Run the soroswap apply-load benchmark and look for any of:
`curve25519DeriveSharedKey`, `hkdfExtract`, `hmacSha256`,
`hmacSha256Verify`, `crypto_scalarmult` in the apply zone subtree.

## Target Code

- `src/crypto/Curve25519.cpp:74` — `hkdfExtract` after
  `crypto_scalarmult`
- `src/crypto/SHA.cpp:90-117` — `hmacSha256`, `hmacSha256Verify`,
  `hkdfExtract` primitives
- `src/overlay/Hmac.cpp:53-77` — `hmacSha256Verify` /  `hmacSha256`
  callers (overlay only)
- `src/overlay/PeerAuth.cpp` — `curve25519DeriveSharedKey` callsite

## Evidence

- These primitives are individually expensive (Curve25519 scalarmult
  ~40 µs; ed25519-dalek verify ~50 µs) and would be material if on the
  apply path.

## Anti-Evidence

- Repo-wide grep
  (`grep -rn "hkdfExtract\|hmacSha256\|crypto_auth_hmac" src/`)
  shows ALL non-test, non-crypto-internal callers are inside
  `src/overlay/` (`Hmac.cpp`, `Floodgate.cpp`, `OverlayManager.h`,
  `Tracker.cpp`, `Peer.cpp`, `PeerAuth.cpp`).
- `curve25519DeriveSharedKey` is invoked only by `PeerAuth` during
  per-peer handshake — once per peer connection lifetime, not per
  ledger or per tx.
- The optimize-soroswap OUT_OF_SCOPE list explicitly excludes overlay,
  herder, SCP, and consensus.
- Meta-Pattern 5 already establishes that all apply-path
  signature/MAC verification is bounded under 0.2% of apply time; the
  overlay HMAC callers are in addition out of scope.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — H016 covered base64 (overlay/CLI) reachability;
H027 covered in-host ed25519; this entry covers Curve25519 ECDH and
HKDF/HMAC primitives, which were not the explicit subject of a prior
failure.

### Why It Failed

Out of scope. Every production caller of `curve25519DeriveSharedKey`,
`hkdfExtract`, `hmacSha256`, and `hmacSha256Verify` lives inside
`src/overlay/` (peer authentication and message HMAC). None are
reachable from a `closeLedger` descendant, and the overlay subsystem
is explicitly OUT_OF_SCOPE for the optimize-soroswap objective.

### Lesson Learned

Before sizing a hypothesis around an expensive crypto primitive
(Curve25519, HKDF, HMAC), confirm via repo-wide grep that the callers
are reachable from `closeLedger` rather than only from overlay /
peer-handshake paths. The optimize-soroswap scope rules out overlay
work even when its absolute cycle cost is high. This complements
H016's lesson for base64 and H027's lesson for in-host ed25519:
multiple Rust/C++ crypto primitives have zero soroswap apply-time
impact because their callers are exclusively outside `closeLedger`.
