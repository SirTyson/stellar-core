# H077: `i128_*` Rust-FFI Arithmetic in EventsAreConsistentWithEntryDiffs Is Not Enabled During Benchmark Apply

**Date**: 2026-05-24
**Subsystem**: crypto / rust
**Severity**: Low
**Impact**: invariant-only Rust-FFI i128 arithmetic outside benchmark execution
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

If `i128_add`, `i128_sub`, `i128_add_will_overflow`, `i128_sub_will_underflow`, `i128_from_i64`, `i128_is_negative`, and `i128_i64_eq` were called on the soroswap apply path, each per-call FFI roundtrip (Rust function dispatch + `cxx` thunk) would add tens of nanoseconds to event-balance accounting. Replacing the bridge calls with native C++ `__int128` arithmetic (which all supported Linux x86_64 / aarch64 toolchains provide) should preserve every numerical result while eliminating the per-call FFI overhead. The expectation is that this cost would only matter if the benchmark actually invokes the consuming code path.

## Mechanism

`EventsAreConsistentWithEntryDiffs` is a Stellar Core invariant that, when enabled, intercepts every operation's emitted contract events and ledger-entry diffs, summing 128-bit balance deltas per (address, asset) pair to verify they match (`src/invariant/EventsAreConsistentWithEntryDiffs.cpp:46,51,62,67,211,253,273,302-303,361,383,478,505,527`). Each balance update calls into Rust through `rust_bridge::i128_add` / `i128_sub` / overflow-check helpers (`src/rust/src/i128.rs`), with `i128_i64_eq` and `i128_is_negative` also crossing FFI per comparison.

For a Soroban-heavy workload, this would mean *every* contract event with a 128-bit amount triggers an FFI hop through cxx into Rust just to do a `checked_add` on a native `i128`. C++ already supports native `__int128` arithmetic; the FFI roundtrip is pure overhead. The candidate optimization would either short-circuit the FFI by implementing the same checked arithmetic in C++ inline, or skip the invariant entirely when it is not registered.

## Trigger

Run the protocol-27 soroswap apply-load benchmark in its standard configuration. Each `applyOperation` would emit contract events through `EventsAreConsistentWithEntryDiffs::checkOnOperationApply` if and only if the invariant is registered via the `INVARIANT_CHECKS` config setting. If registered, soroswap's per-swap contract events trigger several `i128_add`/`i128_sub`/`i128_is_negative` calls per operation, with N transactions × M operations × ~5 i128 ops each yielding tens of thousands of FFI roundtrips per ledger.

## Target Code

- `src/invariant/EventsAreConsistentWithEntryDiffs.cpp:46-67` — `addAmount`/`subAmount` helper functions cross FFI to `rust_bridge::i128_add_will_overflow` and `rust_bridge::i128_add`.
- `src/invariant/EventsAreConsistentWithEntryDiffs.cpp:478,505,527` — per-event `rust_bridge::i128_is_negative` checks.
- `src/invariant/EventsAreConsistentWithEntryDiffs.cpp:211,253,273,302-303` — per-diff `rust_bridge::i128_from_i64` and `==` comparisons against `Int128Parts`.
- `src/rust/src/i128.rs:1-75` — thin Rust wrappers around native `i128` arithmetic.
- `src/main/ApplicationImpl.cpp:319` — invariant registration call: `EventsAreConsistentWithEntryDiffs::registerInvariant(*this)`.
- `src/main/ApplicationImpl.cpp:1613,1628` — config-driven enablement check in `InvariantManager`.

## Evidence

The bridge calls genuinely cross FFI for trivial 128-bit arithmetic that C++ can do natively. If the invariant were live during apply-load, the per-event FFI cost could plausibly be reduced by an order of magnitude through inline C++ implementation, since the function bodies in `src/rust/src/i128.rs` are just `lhs.checked_add(rhs)` / `lhs.checked_sub(rhs)` / sign-test calls — nothing requires Rust-specific machinery.

## Anti-Evidence

`EventsAreConsistentWithEntryDiffs::registerInvariant` (`src/invariant/EventsAreConsistentWithEntryDiffs.cpp:569-575`) only attaches the invariant to the manager; the manager itself enables registered invariants only when listed in the `INVARIANT_CHECKS` config field. `InvariantManagerImpl::resolveAndRegisterInvariants` (`src/invariant/InvariantManagerImpl.cpp:152`) explicitly singles out `EventsAreConsistentWithEntryDiffs` for a stricter enablement check — it is not registered by default and is explicitly opt-in.

The apply-load benchmark configuration does not enable `EventsAreConsistentWithEntryDiffs`. The current accepted baseline (`/mnt/nvme2/apply-load/8dd3f525748f-20260524-114704/...soroswap...tracy`) shows no `i128_add` / `i128_sub` / `i128_is_negative` Tracy zones under any `applyLedger` window — these zones simply do not appear in the trace, confirming the invariant is disabled.

If the benchmark were to enable this invariant, the resulting apply time would be dominated by event-processing overhead generally (event collection, address/asset map probes, comparison work) rather than the i128 FFI hops alone. Even an order-of-magnitude reduction in i128 FFI cost would be only a fraction of the invariant's own overhead, and the invariant is not part of the production apply path or the benchmark configuration.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — Rust-FFI i128 arithmetic in the events invariant was not previously investigated. Prior records cover base64 (H016), HostModule dispatch (H070), CxxFeeConfiguration (H071), but not `i128_*` callers.

### Why It Failed

`EventsAreConsistentWithEntryDiffs` is an opt-in invariant that is not registered in the soroswap apply-load benchmark configuration. The current baseline trace shows zero `i128_*` Tracy zones inside any `applyLedger` window, confirming the entire surface is dead code for the benchmark. Optimizing the FFI roundtrip would have no measurable effect on the soroswap apply metric, regardless of how cheaply the arithmetic could be inlined in C++.

### Lesson Learned

Invariant-internal Rust-bridge callsites must be checked for default enablement before being considered apply-path work. `EventsAreConsistentWithEntryDiffs` follows the same pattern as `BucketListIsConsistentWithDatabase`: registered with the InvariantManager at app construction, but enabled only via explicit `INVARIANT_CHECKS` config. Any future hypothesis targeting `i128_*` FFI calls must demonstrate a non-invariant caller reachable from `closeLedger` (none currently exists in the codebase: `P23HotArchiveBug.cpp` and `SorobanTxTestUtils.cpp` are also off-path).
