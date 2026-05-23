# H064: Replace `sha256(xdr::xdr_to_opaque(...))` with streaming `xdrSha256` in `TransactionFrame::getContentsHash`

**Date**: 2026-05-23
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — no apply-path cost remains after cache hits)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::getContentsHash` (`src/transactions/TransactionFrame.cpp:133-159`)
computes the network-namespaced SHA256 over the transaction body. The current
implementation builds the contents preimage via two separate
`sha256(xdr::xdr_to_opaque(networkID, ENVELOPE_TYPE_TX, [0,] body))` calls
(lines 146 and 151), each of which materializes a fresh `std::vector<uint8_t>`
on the heap, runs one-shot SHA256 over it, then frees the vector. The
correct efficient form is to feed the same input tuple directly into the
streaming `XDRSHA256` archiver (analogue of `xdrSha256<T>`), so that the
serializer's small writes are batched through the 256-byte stack buffer
inside `XDRHasher` and no intermediate heap allocation occurs. The function
should produce a byte-identical SHA256 digest with zero heap-allocated
preimage buffer.

## Mechanism

For every transaction whose contents hash is requested, the current code
pays for one `std::vector` allocation, a memcpy of the serialized bytes
into that vector, the SHA256 over the vector, and the vector's destruction.
A streaming form (built by hand using `XDRSHA256` with explicit
`xdr::archive(sha, networkID)`, `xdr::archive(sha, env_type)`, optional
`xdr::archive(sha, 0u)`, and `xdr::archive(sha, body)` calls, then
`sha.finish()`) eliminates the heap allocation entirely. The codebase has
historically converted similar callers to the streaming form (e.g.,
`xdrSha256(mEnvelope)` at line 127 is already in streaming form). The
remaining `getContentsHash` callsite is a pattern outlier.

## Trigger

Run soroswap; observe `TransactionFrame::getContentsHash` calls during
apply-path validation. Any saved allocation per call accrues across 2000
soroban txs × 65 ledgers in the diagnostic trace.

## Target Code

- `src/transactions/TransactionFrame.cpp:133-159` — `getContentsHash`
- `src/transactions/TransactionFrame.cpp:146` — V0 path
  (`sha256(xdr::xdr_to_opaque(mNetworkID, ENVELOPE_TYPE_TX, 0, mEnvelope.v0().tx))`)
- `src/transactions/TransactionFrame.cpp:151` — V1 path
  (`sha256(xdr::xdr_to_opaque(mNetworkID, ENVELOPE_TYPE_TX, mEnvelope.v1().tx))`)
- `src/crypto/SHA.h` — `XDRSHA256` streaming archiver
- `src/crypto/XDRHasher.h` — `XDRHasher` 256-byte buffered archiver

## Evidence

The `sha256(xdr::xdr_to_opaque(...))` pattern is a known anti-pattern in
this codebase: the `xdrSha256<T>` template was introduced precisely to
avoid the intermediate allocation, and many historical callsites have
already been migrated. The `getContentsHash` implementation calls
`xdr::xdr_to_opaque` with a heterogeneous tuple (networkID + envelope type
+ optional zero + tx body), which is why a single-template helper does
not exist for it, but a hand-rolled streaming form is straightforward.
The replacement is mechanical and byte-equivalent (XDR serialization of
the tuple is identical whether materialised into a vector then hashed or
streamed directly into SHA256 state).

## Anti-Evidence

`mContentsHash` is cached on the `TransactionFrame` (line 142 checks
`isZero(mContentsHash)`). Per existing fail H005
(`005-cached-contents-hash-apply-accessors.md`), all apply-path
`getContentsHash()` calls in the soroswap workload are cache hits — the
cold computation runs once during tx-set construction, outside the
measured `applyLedger` window. The actual `sha256(xdr_to_opaque(...))`
work this hypothesis targets is therefore not on the apply critical path
for soroswap.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — distinct callsite (TransactionFrame::getContentsHash V0/V1 branches) from prior `xdr_to_opaque` migration hypotheses (H062 targeted `getTTLKey`; H018 targeted general `XDRHasher` redesign)

### Why It Failed

The optimization is real (anti-pattern is genuine), but the apply-path
impact is zero for soroswap. `getContentsHash` returns a cached value on
every apply-path invocation; the underlying `sha256(xdr_to_opaque(...))`
work executes during tx-set assembly, which is explicitly out-of-scope
per the objective (TX set construction is a testing artifact, not part
of `closeLedger`). This is the same structural finding as H005:
`getContentsHash` accessor cost reduces to a single load + branch on
apply, regardless of how the cold path is implemented. Meta-Pattern 5
additionally bounds the entire apply-path verifySig/contents-hash
surface to <0.2% even in the worst case.

### Lesson Learned

For SHA256-anti-pattern hypotheses (`sha256(xdr::xdr_to_opaque(x))` →
`xdrSha256(x)`), the streaming form is always a clean micro-improvement,
but only matters when the call actually executes on the apply critical
path. For `TransactionFrame::getContentsHash`, the cold computation is
amortised by `mContentsHash` caching across tx-set construction +
overlay + ledger close, so apply-path savings are exactly zero on
soroswap. Confirm every such candidate against the cached-vs-cold
distinction (per H005) before sizing savings.
