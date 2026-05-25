# H209: Avoid Heap-Allocated PRNG Seed CxxBuf Per Soroban Invocation

**Date**: 2026-05-25
**Subsystem**: soroban / Rust bridge
**Severity**: Low
**Impact**: per-invocation bridge allocation and 32-byte sub-seed copy overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The parallel apply thread already derives the deterministic 32-byte
transaction PRNG sub-seed before invoking the Soroban host. The C++/Rust bridge
should not need a heap-allocated `std::vector<u8>` wrapper just to pass those
32 bytes to Rust; an inline fixed-size bridge value or borrowed byte-slice API
should be enough as long as Rust receives exactly the same sub-seed bytes.

## Mechanism

`LedgerManagerImpl::applyThread` computes `txSubSeed` for each bundle, and
`InvokeHostFunctionParallelApplyHelper` stores it as `mSorobanBasePrngSeed`.
`InvokeHostFunctionApplyHelper::invokeHostFunction` then constructs
`basePrngSeedBuf`, allocates a new vector, and copies those 32 bytes before
calling `rust_bridge::invoke_host_function`. A narrower bridge representation
for fixed-size hashes would remove one small allocation and copy per Soroban
transaction without changing PRNG derivation.

## Trigger

Run the current soroswap apply-load benchmark. Every successful Soroban
transaction reaches `InvokeHostFunctionOpFrame::doParallelApply`, enters
`InvokeHostFunctionApplyHelper::invokeHostFunction`, and builds a fresh
`basePrngSeedBuf` before crossing the Rust bridge.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` —
  `invokeHostFunction` allocates and fills `basePrngSeedBuf` per invocation.
- `src/ledger/LedgerManagerImpl.cpp:2490-2506` — `applyThread` derives the
  transaction sub-seed and then calls `parallelApply` for each bundle.
- `src/rust/src/soroban_proto_any.rs:391-448` — bridge-side invocation receives
  the seed buffer and passes it to the protocol-specific host.

## Evidence

The allocation/copy is structurally present at
`InvokeHostFunctionOpFrame.cpp:570-583`. The containing C++ bridge zone is an
`applyLedger` descendant: unwrap containment for the current soroswap trace
shows `invokeHostFunction` at `InvokeHostFunctionOpFrame.cpp:559` has
12,050,240,000 ns total duration over 8,687 events inside apply windows, so the
path is in scope.

## Anti-Evidence

The relevant removable work is only a tiny part of the C++ bridge wrapper.
`csvexport-release -e` reports 43,783,597 ns self-time for
`invokeHostFunction` across all 8,705 invocations in the current soroswap trace.
After 8-way parallel-apply normalization and 71 apply windows, that is about
0.077 ms per ledger, roughly 0.04% of the 207.590 ms soroswap baseline. A
single 32-byte vector allocation/copy is just a subset of that C++ wrapper
self-time and is also covered by the broader distributed XDR/bridge-cost ceiling
in the fail summary.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — no existing fail record targets the base-PRNG seed buffer
allocation specifically, although the broader C++/Rust bridge-cost ceiling
applies.

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage). Even
removing the entire self-time of the containing C++ `invokeHostFunction` wrapper
would be far below 1% of apply time after parallelism normalization. The
base-seed buffer allocation/copy is smaller still, so it cannot plausibly reach
the 3% Medium threshold.

### Lesson Learned

Small bridge allocation cleanups must be bounded against the bridge wrapper's
own self-time, not its total duration including Rust host execution. A per-tx
32-byte fixed-size bridge value is structurally safe but far below the
performance floor for optimize-soroswap.
