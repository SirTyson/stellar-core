# H046: Hoist `gUseRustDalekVerify` Atomic Load Out of verifySig Miss Path

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low (sub-1%)
**Impact**: apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`PubKeyUtils::verifySig` (`src/crypto/SecretKey.cpp:469-520`) selects between
libsodium and Rust ed25519-dalek verifiers based on the global
`gUseRustDalekVerify` flag, set once at startup via `enableRustDalekVerify()`
and never cleared. The expected efficient implementation reads the flag once
(at protocol-version transition or at startup) and dispatches without
re-reading on every signature verification. A flag that is one-way and
toggled at process boot is structurally a constant for the duration of any
ledger apply.

## Mechanism

The actual implementation re-reads the atomic flag on every cache miss:

```cpp
bool shouldUseRustDalekVerify =
    gUseRustDalekVerify.load(std::memory_order_relaxed);
```

While a `memory_order_relaxed` load on x86 compiles to a plain `mov` (no
LOCK prefix and no fence), the load still occupies an instruction slot,
prevents the compiler from CSE-ing the dispatch decision across calls, and
forces the verify branch to be data-dependent on the flag rather than
constant-folded. A startup-fixed dispatch table (one libsodium-verify
function pointer or one dalek-verify function pointer set during
`enableRustDalekVerify`) would let the compiler inline the selected verifier
and remove the per-call flag check entirely.

## Trigger

Every cache-miss verifySig invocation reads the global atomic. The soroswap
benchmark drives ~1 verifySig call per transaction × 2000 tx × 65 ledgers
across 8 parallel workers; with non-zero cache miss ratio, the load fires
in the tens of thousands per benchmark run.

## Target Code

- `src/crypto/SecretKey.cpp:496-497` — `gUseRustDalekVerify.load` in the
  miss path
- `src/crypto/SecretKey.cpp:71` — `gUseRustDalekVerify` declaration as
  `std::atomic<bool>`
- `src/crypto/SecretKey.cpp:enableRustDalekVerify` — one-way setter called
  at protocol-24 transition

## Evidence

- `gUseRustDalekVerify` is a one-way flag — it is set to `true` once and
  never cleared.
- The relaxed atomic load pattern is appropriate for correctness but adds
  no benefit when the value is known to be constant after startup.
- A function-pointer dispatch table or `[[likely]]`-annotated branch could
  let the compiler eliminate the data dependency.

## Anti-Evidence

This proposal sits inside Meta-Pattern 5: the entire apply-path verifySig
budget is <0.2% of apply time. A single relaxed-atomic load on x86 is one
instruction (~1-2 cycles uncontended) and will not measurably perturb
verifySig latency: even at 130k apply-path calls × 2 ns/call = 0.26 ms
across the full 65-ledger soroswap run, structurally five orders of
magnitude below the 3% Medium floor (~580ms over 19s of total apply
across runs).

The per-call cost is also bounded by Meta-Pattern 7 (Tracy `ZoneScoped`
overhead in `verifySig` already dwarfs any sub-cycle micro-cost from the
atomic load), so even if a Tracy trace appears to attribute time to the
load, that attribution is profiler artifact rather than production cost.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; prior verifySig hypotheses
(H008, H009, H021, H034, H043, H044, H045) targeted cache-bypass,
key-shortening, per-thread cache, batch verify, shard-index hash,
atomic-counter increments, and double mutex acquisition, but no prior
record addresses the dalek-flag dispatch pattern.

### Why It Failed

Meta-Pattern 5 caps the apply-path verifySig surface at <0.2% of apply time.
A single x86 relaxed-atomic load is ~1-2 cycles per call, contributing
sub-microsecond cost per ledger. Optimizing it cannot reach the 1% Low floor,
let alone the 3% Medium floor required by this objective. The `std::atomic`
load on x86 is already as cheap as a plain memory read and provides
correctness guarantees (publication of the protocol-24 transition) that a
function-pointer redesign would have to preserve at equal cost.

### Lesson Learned

`memory_order_relaxed` atomic loads on x86 compile to plain `mov`
instructions; targeting them as performance hot spots is almost always a
trap. Combined with Meta-Pattern 5 (verifySig <0.2%) and Meta-Pattern 7
(Tracy overhead inflates per-call self-times), per-call atomic-flag reads
in apply-path crypto wrappers are structurally never Medium-tier
optimization candidates for this objective.
