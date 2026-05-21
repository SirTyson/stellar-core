# H048: Skip or Cache `unbias_prng_seed` HMAC for Soroswap Host PRNG Seeds

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban host PRNG setup should not spend meaningful apply time on cryptographic
seed normalization when the workload does not use contract PRNG syscalls. For
soroswap, the base PRNG seed should be initialized deterministically and cheaply
for each host invocation, while preserving the protocol-defined randomness
stream observed by contracts.

## Mechanism

`Prng::new_from_seed` always calls `unbias_prng_seed`, which performs an
HMAC-SHA256 extraction with a fixed public-network salt before constructing
`ChaCha20Rng`. This fires during `Host::set_base_prng_seed` for each invocation
even when the contract never calls `prng_bytes_new`, `prng_u64_in_inclusive_range`,
`prng_vec_shuffle`, or `prng_reseed`. Skipping or caching the HMAC for
embedder-derived seeds would change the PRNG stream and therefore contract-
observable behavior, and the measured HMAC surface is far too small to justify a
protocol-gated redesign.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` and
filter `unbias_prng_seed`:

```sh
./lib/tracy/csvexport/build/unix/csvexport-release -e -f unbias_prng_seed \
  /mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy
```

The trace reports `unbias_prng_seed,soroban-env-host/src/crypto/mod.rs,460` at
5,104,366 ns self-time across 6,823 calls. Unwrap-mode containment confirms all
6,823 events are inside `applyLedger`, totaling 5,956,326 ns.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/crypto/mod.rs:456-486` —
  `unbias_prng_seed` charges two SHA256 operations and runs HMAC-SHA256 with a
  fixed salt.
- `src/rust/soroban/p26/soroban-env-host/src/host/prng.rs:98-101` —
  `Prng::new_from_seed` unconditionally unbiases every supplied seed.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:535-542` —
  `set_base_prng_seed` constructs the base PRNG for a host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3793-3804` —
  `prng_reseed` constructs a new PRNG from contract-supplied bytes.

## Evidence

The code path is confirmed to be apply-contained and cryptographic. The current
soroswap trace has no `chacha20` zone events, so the workload initializes host
PRNG state but does not call the metered PRNG byte-draw path. This makes the
HMAC seed-unbias step look like removable setup work at first glance.

## Anti-Evidence

The complete apply-contained `unbias_prng_seed` event time is only 5.96 ms over
a 5.230 s `applyLedger` trace, or about 0.11% if eliminated entirely. The step
is also protocol-visible: changing or skipping the HMAC changes every derived
`ChaCha20Rng` stream for contracts that do use PRNG syscalls, so even a
protocol-gated redesign would need semantic review for a sub-noise benefit on
soroswap.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — prior crypto failures covered C++ `randomBytes` seed
construction and Curve25519/HKDF overlay paths, but not the Rust Soroban host
PRNG seed-unbias HMAC.

### Why It Failed

The entire apply-contained HMAC seed-unbias surface is two orders of magnitude
below the 3% Medium severity floor, and eliminating it would change
contract-observable PRNG output. The objective does not accept Low hypotheses at
this stage, and this is below even the Low threshold.

### Lesson Learned

Host PRNG setup can appear as crypto work inside `applyLedger`, but for
soroswap it is tiny fixed setup cost per invocation and must not be optimized by
changing deterministic PRNG semantics. Future PRNG hypotheses need evidence of
large `chacha20`/PRNG syscall usage in the target workload before promotion.
