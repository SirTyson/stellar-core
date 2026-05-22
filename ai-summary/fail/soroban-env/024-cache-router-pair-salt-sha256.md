# H024: Cache router pair-salt SHA256 derivation for the fixed two-token route

**Date**: 2026-05-22
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Potentially lower CPU in router/pair-address derivation, but below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated Soroswap swaps over the same two-token route should avoid recomputing the pair-address salt hash if the host can prove the token pair and factory are unchanged, while still deriving exactly the same `ScVal::Address(token_0) || ScVal::Address(token_1)` byte stream and deterministic pair contract id as the Wasm router.

## Mechanism

The current trace contains apply-contained SHA256 work from router/pair derivation and other Soroban calls. A per-ledger or per-host cache keyed by `(factory, token_0, token_1)` could return the previously derived pair id on later swaps, removing repeated `serialize_to_bytes`/`compute_hash_sha256`/contract-id hashing work for the benchmark's single pair.

## Trigger

Run the current accepted soroswap benchmark with the fixed generated route. The same token pair is used across all measured swaps, so pair-address derivation repeats.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1073-1301` at accepted p26 commit `03d78248` — native pair path consumes the pair id after router derivation.
- `src/rust/src/soroban_proto_any.rs:472-552` — per-invocation host setup where any per-host cache would need to be installed.
- `soroban-env-host/src/vm/dispatch.rs:304` — generated `compute_hash_sha256` dispatch zone observed in the trace.

## Evidence

Unwrap containment against the current soroswap Tracy trace shows SHA-related work inside `applyLedger`: `compute_hash_sha256` has 22,321 apply-contained events totaling 78.151309ms, `sha256` in `soroban-env-host/src/crypto/mod.rs:414` has 44,744 events totaling 23.726104ms, and C++ `sha256` has 331,541 events totaling 318.242234ms. The fixed benchmark route gives a high cache-hit opportunity for the router pair salt specifically.

## Anti-Evidence

The trace does not attribute the full SHA aggregate to router pair-id derivation; the C++ `sha256` total includes transaction hashes and other apply work, while `compute_hash_sha256`'s entire apply-contained total is only 78ms across the trace. Even removing all `compute_hash_sha256` time would be roughly 1.7% of the 4.565s apply envelope before subtracting mandatory hashing outside the pair-salt subset and before benchmark-noise normalization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously recorded as a standalone pair-salt cache investigation in `fail/soroban-env`.

### Why It Failed

This is below the optimize-soroswap severity threshold. The whole relevant host SHA dispatch upper bound is already below the 3% Medium floor, and the pair-salt subset is smaller than that because the zone includes all contract `compute_hash_sha256` calls. The prior router-native failure also found that pair-id hashing was not the dominant residual cost relative to SAC transfer, pair swap, event construction, and balance reads.

### Lesson Learned

For Soroswap router-address derivation, fixed-route repetition is real but not enough by itself. Pair-id caching should only be part of a broader fused router/pair redesign; as a standalone hypothesis it is a Low-impact micro-optimization and should not be promoted for this objective.
