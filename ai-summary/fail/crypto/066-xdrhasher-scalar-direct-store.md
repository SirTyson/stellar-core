# H066: Inline u32/u64 scalar stores in `XDRHasher::queueOrHash` to eliminate per-field `memcpy`

**Date**: 2026-05-23
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — bounded by Meta-Pattern 1 SHA256/BLAKE2 budget)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`XDRHasher::queueOrHash` (`src/crypto/XDRHasher.h:26-49`) is the per-byte
batching hot path through which every XDR-serialized field of every hashed
XDR object flows. The u32 and u64 `operator()` overloads
(`XDRHasher.h:62-75`) endian-swap their argument into a local 4- or 8-byte
variable on the stack, then call `queueOrHash` with a pointer to that local
and `sizeof(u32)` / `sizeof(u64)`. `queueOrHash` then performs a `memcpy`
into `mBuf + mLen`. For each scalar XDR field hashed, this means: one
endian-swap, one `memcpy(dst, &local, 4 or 8)`, and one `mLen += sz`. For a
hot path that processes structurally-rich XDR with many small fixed-size
scalars (e.g., `LedgerKey::contractData` field walks, `LedgerHeader`
serialization, `TransactionEnvelope` decoding for the verifySig BLAKE2
prelude), the expected efficient form is to inline a direct 4-byte/8-byte
store via `*reinterpret_cast<uint32_t*>(mBuf+mLen) = u; mLen += 4;` (or use
`__builtin_memcpy` which the compiler reliably lowers to a single store
when the size is a compile-time constant). The bounds-vs-`available` check
should also collapse for fixed-size scalars: with a 256-byte buffer, a 4-
or 8-byte scalar can only ever fail the `sz > available()` test when the
buffer is within 8 bytes of full — a rare branch worth a separate slow
path.

## Mechanism

In a non-Tracy build, `queueOrHash` is reduced to: branch on `sz >
available`, then `memcpy(mBuf + mLen, u, sz); mLen += sz`. For fixed-size
scalars, the compiler should fold the `memcpy` to a single store
instruction — but only if the call gets inlined through both the scalar
`operator()` overload and the type-erased `queueOrHash`. In practice,
`queueOrHash` takes `unsigned char const* u, size_t sz` (runtime-sized) and
calls `memcpy(mBuf + mLen, u, sz)`. Without LTO or aggressive call-site
specialization, the compiler emits a real `memcpy` call with a runtime
size argument. Even with full inlining, the runtime-sized memcpy is a
small-loop / rep-movsb sequence rather than a single 4- or 8-byte store.
Hoisting a typed scalar fast path into a separate `queueOrHashScalar<T>`
template would let the compiler emit the optimal store for the common
case (4 or 8 bytes, buffer not full).

## Trigger

Run soroswap; any XDR object hashed via `xdrSha256`, `xdrBlake2`, or
`xdrComputeHash` exercises this path. Every `LedgerKey` SipHash probe
(every `unordered_map<LedgerKey>` lookup in `LedgerTxn::EntryMap`,
`InMemoryBucketState::scan`, etc.) walks the XDR-hasher scalar path
several times per probe.

## Target Code

- `src/crypto/XDRHasher.h:26-49` — `queueOrHash` byte-batching path
- `src/crypto/XDRHasher.h:59-75` — u32/u64 scalar `operator()` overloads
- `src/crypto/XDRHasher.h:77-95` — bytes/opaque overload
- `src/crypto/SHA.cpp` — `XDRSHA256` derived hasher
- `src/crypto/BLAKE2.cpp` — `XDRBLAKE2` derived hasher
- `src/crypto/ShortHash.cpp:74-85` — `XDRShortHasher` derived hasher

## Evidence

`SHA256::add` shows 2.84% trace self-time (Tracy-inflated per
Meta-Pattern 7) and `BLAKE2::add` shows 0.41%. The XDR archive walk is
upstream of these `add` calls and feeds them via `hashBytes`. For a
hashed `LedgerKey::contractData` (~40 bytes after XDR encoding), the
archive emits ~10 scalar writes (key type tag, address discriminant,
contract-id length, contract-id bytes, key sub-discriminant, length,
bytes), each going through `queueOrHash` with a runtime-sized memcpy.
Direct-store specialization would compile each scalar to one MOV.

## Anti-Evidence

Apply-path crypto budget is structurally capped: in-apply SHA256 ~0.67%,
in-apply BLAKE2 ~0.41% (and verifySig BLAKE2 is bounded at <0.2% per
Meta-Pattern 5). SipHash apply-path cost is dominated by `unordered_*`
bucket traversal + XDR equality compare, not by hash computation
(Meta-Pattern 6); shaving scalar memcpy from XDR archive walk does not
move the bucket-walk cost. Modern compilers with `-O2` and visible-body
inlining already emit a single store for compile-time-sized `memcpy` of
4 or 8 bytes; the runtime-sized `queueOrHash` signature defeats this
only if the call is not inlined, and at `-O2` with the header
implementation visible, both `queueOrHash` and the scalar overloads do
inline. The actual SHA256/BLAKE2 compute work (libsodium/OpenSSL
SHA-NI) dominates per-byte even with optimal archive feeding.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H018 (which proposed one-shot vs streaming
for entire short XDR objects). This hypothesis keeps the streaming archive
but specializes the scalar inner loop.

### Why It Failed

Three independently sufficient reasons:

1. **Meta-Pattern 1 ceiling (SHA256 budget <0.67%)**: The total in-apply
   SHA256 budget for soroswap is structurally below the 1% Low floor.
   Improving scalar memcpy efficiency within `XDRHasher` is a fraction
   of the per-byte compute cost; even halving the archive walk overhead
   cannot move the headline metric.

2. **Meta-Pattern 5 ceiling (verifySig BLAKE2 <0.2%)**: BLAKE2 archive
   walks on the apply path are dominated by `verifySigCacheKey` (cache
   probe prelude), already bounded at <0.2% of apply.

3. **Meta-Pattern 6 ceiling (SipHash bucket-traversal dominance)**:
   `XDRShortHasher` archive walks for `LedgerKey` SipHash probes are
   dwarfed by `unordered_set` bucket traversal and XDR `operator==`
   cost; reducing SipHash compute saves a fraction of a fraction.

Compiler-visible inlining at `-O2` likely already folds compile-time-sized
4/8-byte memcpy into single MOV instructions for the common path,
leaving little to recover even before the meta-pattern ceilings apply.

### Lesson Learned

`XDRHasher` archive scalar walks are upstream of three downstream meta-
patterns (1, 5, 6) that all independently cap any savings below the Low
floor. Future hypotheses targeting per-scalar XDR archive efficiency on
the apply path must demonstrate a callsite NOT bounded by these three
ceilings (e.g., a hot path that hashes many MB of XDR per ledger
outside the SipHash/SHA256/BLAKE2 envelopes) before proceeding.
