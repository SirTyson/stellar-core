# H073: Advanced Soroban Crypto Host Syscalls Are Not Exercised By Soroswap

**Date**: 2026-05-24
**Subsystem**: crypto / rust
**Severity**: Low
**Impact**: out-of-workload Soroban host crypto syscall optimization
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

If advanced Soroban crypto syscalls were a Medium-tier soroswap apply bottleneck, the measured `applyLedger` windows would contain repeated calls to host functions such as `verify_sig_ed25519`, `recover_key_ecdsa_secp256k1`, `verify_sig_ecdsa_secp256r1`, BLS12-381 group operations, Keccak, Poseidon, or ChaCha20 PRNG draws. Optimizing those implementations should then reduce apply time while preserving syscall results, metering, error behavior, and deterministic host-object outputs.

## Mechanism

The p26 host exposes many expensive crypto primitives through VM imports, and several perform byte-object visits, validation, curve operations, hashing, or host-object allocation. However, soroswap's hot contracts are router/pair/SAC swap logic; after the accepted native pool optimizations, the benchmark still exercises storage, event, and cross-contract-call paths rather than contract-level advanced crypto syscalls. Optimizing these syscall implementations would therefore improve other contracts but not the soroswap apply objective.

## Trigger

Run the current protocol-27 soroswap apply-load benchmark and inspect the apply-contained VM import/syscall profile. The trigger needed for viability would be nonzero, repeated apply-window events for advanced crypto syscall zones under the soroswap router/pair/SAC execution path; source review shows the swap path does not call them.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3119-3136` — SHA256 and Keccak host imports.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3139-3151` — Ed25519 verification host import.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3154-3179` — secp256k1 recovery and secp256r1 verification host imports.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3182-3225` — BLS12-381 host-function entry points.
- `src/rust/soroban/p26/soroban-env-host/src/crypto/mod.rs:263-319` — SHA256/Keccak byte-object helpers and hashing implementation.

## Evidence

The host source has clear crypto syscall entry points and several are individually expensive enough to matter for contracts that call them frequently. But the crypto failure summary already records soroswap-specific checks for host Ed25519 (`verify_sig_ed25519_internal`) and SHA256 syscalls: source-account credentials bypass in-host Ed25519 entirely, and Soroban SHA256 syscall dispatch is only about 1.14% of apply before subtracting mandatory hashing and metering. No prior success or current-state note identifies BLS, ECDSA, Keccak, Poseidon, or ChaCha20 as an apply-contained soroswap zone; they are absent from the accepted native pool/pair/SAC paths.

## Anti-Evidence

This is workload-mismatched. The Soroswap contracts under apply-load perform swaps, SAC transfers/balance reads, storage updates, and event emission; they do not repeatedly invoke advanced crypto host syscalls. The only crypto primitive with known soroswap reachability is SHA256, and existing records cap all SHA-only optimizations below the objective threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — broad advanced-crypto host syscalls beyond Ed25519/SHA256 were not separately recorded in the crypto fail summary

### Why It Failed

The advanced crypto syscall implementations are not on the soroswap apply hot path. Optimizing BLS, ECDSA, Keccak, Poseidon, or ChaCha20 host functions would benefit different contract workloads, while the soroswap objective is bounded to the existing storage/event/VM-call path and the already-sub-threshold SHA256 surface.

### Lesson Learned

Do not generalize from expensive crypto host functions to soroswap performance. A Soroban syscall must appear as an `applyLedger` descendant in the current workload before it can be considered for this objective.
