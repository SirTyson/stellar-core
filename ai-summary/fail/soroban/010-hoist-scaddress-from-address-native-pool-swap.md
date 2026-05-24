# H010: Hoist `scaddress_from_address` Token Extraction in Native Pool Swap

**Date**: 2026-05-25
**Subsystem**: soroban-env (native soroswap pool fast path)
**Severity**: Low
**Impact**: Per-swap CPU (native pool path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `call_native_soroswap_pool_swap`, each token's `ScAddress` should be
extracted from its `AddressObject` host handle **at most once per swap**, and
the resulting `ScAddress` (or `ContractId`) reused for all subsequent
helper calls (`soroswap_pool_invoke_sac_transfer`,
`soroswap_pool_invoke_sac_balance`) that need to identify the SAC contract.
Extracting it repeatedly via `scaddress_from_address` (which performs a
metered `visit_obj` + `metered_clone`) wastes CPU and budget on identical
extractions.

## Mechanism

`soroswap_pool_invoke_sac_transfer` and `soroswap_pool_invoke_sac_balance`
each call `scaddress_from_address(token)` (or an equivalent
`contract_id_from_address`) to convert the `AddressObject` argument back to
an `ScAddress` before invoking the SAC. Per swap this happens for both
tokens across both helper paths — yielding 3–4 redundant `visit_obj` +
`metered_clone(ScAddress)` round-trips for two distinct tokens. Hoisting the
extraction once at the top of `call_native_soroswap_pool_swap` would let
each helper take an already-extracted `ContractId`/`ScAddress` by reference.

## Trigger

Every soroswap pool swap. ~28 swaps/ledger × 70 ledgers = 1960 swaps,
each doing 3–4 redundant extractions × 2 tokens.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1300` —
  `call_native_soroswap_pool_swap` body, where token handles are passed to
  helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1520` —
  `soroswap_pool_invoke_sac_transfer` and `soroswap_pool_invoke_sac_balance`
  each re-extract the token address.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256` —
  `scaddress_from_address` performs `visit_obj` + `metered_clone`.

## Evidence

Code reading shows both helpers take an `AddressObject` for the token and
both re-extract it. The pattern is the same per call regardless of swap
direction. The extraction is structurally redundant within the scope of a
single swap.

## Anti-Evidence

1. **Sub-threshold absolute cost.** `visit_obj` is a hashmap-free indexed
   vector lookup plus a budget charge; `metered_clone(ScAddress::Contract(Hash))`
   is a fixed 32-byte copy. Estimated <50ns per extraction. With ~6
   extractions/swap × 28 swaps/ledger / 8 clusters ≈ 1µs/ledger of
   *critical-path* savings — three orders of magnitude below the 1% noise
   floor on a 211ms apply.

2. **Metering visibility.** Each `visit_obj` and `metered_clone` issues
   `BudgetType::VisitObject` and `BudgetType::HostMemAlloc` charges. Skipping
   them would change observed budget consumption and refund amounts, which
   are protocol-visible (per fail meta-pattern #16: "Budget charge
   coalescing exhausted post-VisitObject/ValSer success"). Any change would
   require either a protocol gate or a careful re-issuance of equivalent
   charges, eroding the already-tiny saving.

3. **Native-pool fast path scope.** The same native swap function already
   bypasses far heavier work (full frame construction, auth tree, storage
   snapshots) via accepted successes; the remaining helper-level extractions
   are residual noise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not duplicated by fail #001 family
(native-pool-sac-transfer-return-balance) which targeted entire helper
elimination; this is the strictly weaker "share extracted ScAddress" variant.

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage).
Projected savings ≪0.01% of apply time, well below benchmark noise.
Additionally, the extractions emit metered budget charges that are
protocol-observable, so any caching would require a protocol gate — a
disproportionately large blast radius for a sub-µs/ledger saving.

### Lesson Learned

Within the native soroswap pool fast path, residual per-swap work that is
already metered (visit_obj, metered_clone, charge_budget) is doubly
constrained: (a) absolute cost is in the nanoseconds, and (b) elimination
mutates the metering schedule. Future investigations of the native pool path
should target unmetered or already-bypassed work, not micro-optimization of
metered helpers. Per fail meta-pattern #15, all native bypass variants of
this kind share the same metering/spec blockers.
