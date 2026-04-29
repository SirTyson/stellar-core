# H013: Optimize Soroban host `compute_hash_sha256` syscall dispatch overhead

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a Soroban contract calls the host `compute_hash_sha256` syscall, the host
should hash the input bytes object and return a new `BytesObject` handle
referencing the digest, with overhead dominated by the actual SHA256 work and
the unavoidable host-object table insertion.

## Mechanism

The actual hashing work for a single contract-invoked SHA256 call is small
(libsodium SHA256 over <100 bytes), but each call also pays for: dispatch
through the wasmi VmCaller, `sha256_hash_from_bytesobj_input` (object visit +
slice extraction), `scbytes_from_vec` allocation, and `add_host_object`
budget metering + table insert. If a hot contract performs many such calls
per invocation, dispatch overhead could dominate the actual hash cost.

## Trigger

Run the soroswap apply-load benchmark with Tracy. The
`compute_hash_sha256` zone in
`src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` is invoked
~10,004 times across 69 ledger applies in the diagnostic trace.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3095-3102` —
  `compute_hash_sha256` host implementation
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` — Tracy zone
  dispatch
- `src/rust/soroban/p26/soroban-env-host/src/crypto/mod.rs:414` — internal
  `sha256` helper

## Evidence

Tracy measurements of the soroswap diagnostic trace (within applyLedger
windows only):

- `compute_hash_sha256` (vm dispatch): 54.0 ms total, 10,004 calls
- `sha256` (soroban-env-host crypto/mod.rs): 11.8 ms total, 20,110 calls
- C++-side `sha256` (crypto/SHA.cpp): 208.4 ms total, 205,093 calls

`compute_hash_sha256` is invoked from soroswap's swap path (the AMM uses
hash-derived storage keys). Per-call cost is ~5.4 µs of which the actual
SHA256 work is microseconds.

## Anti-Evidence

Total Soroban-side SHA256 work inside applyLedger windows (host syscall +
internal mod.rs helper) is 54 ms + 11.8 ms = 65.8 ms across 5774 ms of
applyLedger time = **1.14% of apply**. Even fully eliminating both zones
would not reach the Medium severity floor (3%). Realistic savings from
dispatch-overhead reduction are a fraction of that 1.14% because the
actual SHA256 work and the `add_host_object` budget charge are required by
soroban-env semantics and cannot be removed without breaking metering
determinism. The work is also bounded per-contract-call and only scales
with how many `compute_hash_sha256` calls soroswap makes per swap; the
soroswap workload generates ~3 such calls per ledger invocation on average.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (prior fail entries 001-012
address C++-side SHA256 / verifySig, not Soroban host syscall dispatch)

### Why It Failed

In-apply Soroban SHA256 work totals ~1.14% of applyLedger time even before
considering that the actual hash work and metering charges cannot be
removed. The realistic optimization surface (dispatch zone + scbytes_from_vec
allocation) is a fraction of that 1.14% and is well below the 3% Medium
severity floor required by this objective. Additionally, the Soroban host
APIs are part of the metered deterministic interface — restructuring
host-syscall dispatch risks changing budget consumption across the
protocol-version boundary, which is unacceptable.

### Lesson Learned

Soroban host-syscall dispatch overhead for cryptographic primitives is
bounded by the per-call invocation count from the contract workload.
Soroswap's per-swap SHA256 syscall count is too low to make this surface
reach Medium severity. Any future host-syscall hypothesis must first verify
the contract workload makes the syscall in tight inner loops (hundreds of
calls per invocation), not the few-per-invocation pattern soroswap uses.
