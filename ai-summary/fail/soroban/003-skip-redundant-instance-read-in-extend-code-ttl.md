# H003: Skip Redundant Instance Storage Read in `extend_contract_code_ttl_from_contract_id`

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Soroswap apply-time reduction by removing one redundant `Storage::get` probe per SAC transfer's TTL extend
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`extend_current_contract_instance_and_code_ttl` (called once per SAC `transfer`) extends both the contract-instance and the contract-code TTL for the currently-running contract. For a SAC contract, the code TTL extension is a no-op because the executable is `ContractExecutable::StellarAsset`. The expected behavior is to perform the mandatory instance-TTL extend and the (no-op) StellarAsset check using only the storage probes that are actually required.

## Mechanism

The flow in `extend_current_contract_instance_and_code_ttl` (host.rs:2320) is:

1. `extend_contract_instance_ttl_from_contract_id` → `Storage::extend_ttl(instance_key)` (TTL probe + write)
2. `extend_contract_code_ttl_from_contract_id` (data_helper.rs:247) → first calls `retrieve_contract_instance_from_storage(instance_key)` (a full `Storage::get` on the instance entry), then matches on `executable`. For `StellarAsset`, the function returns Ok(()) — the instance read was only used to discover that no code-TTL work was needed.

For SAC transfers, the executable type is invariant for a given contract id within an invocation and across the whole apply window. The instance read inside `extend_contract_code_ttl_from_contract_id` is therefore a redundant storage probe (~5µs each including budget charges for `Storage::get`, host-side `Compare<HostObject>` for the storage-map binary search, and the metered footprint lookup).

ACTUAL deviation from expected: the host performs an extra `Storage::get` for the instance entry every single time a SAC `transfer` calls `extend_current_contract_instance_and_code_ttl`, only to discover the executable is `StellarAsset` and return.

## Trigger

Run the soroswap apply-load benchmark. Every SAC `transfer` (input transfer router→pair, output transfer pair→user, native-pair fast-path SAC transfers) invokes `extend_current_contract_instance_and_code_ttl`, paying one extra `Storage::get` probe on the SAC instance entry just to confirm the executable is `StellarAsset`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2335` — `extend_current_contract_instance_and_code_ttl` calls both helpers back to back.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-265` — `extend_contract_code_ttl_from_contract_id` does `retrieve_contract_instance_from_storage` purely to read `executable`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` — SAC `transfer` entry that triggers the TTL extend.

## Evidence

Tracy zone `extend_current_contract_instance_and_code_ttl` (vmcaller_env.rs:270) shows 15,770 calls totalling 212ms aggregate self-time on the current soroswap diagnostic trace. This matches roughly 2 SAC transfers per accepted swap tx × 7,891 txs in the benchmark. Each call currently performs at least two storage probes (instance TTL + instance entry read) plus a third (instance TTL write) — the proposed change would eliminate the middle probe for SAC contracts.

A specialized fast path in `extend_contract_code_ttl_from_contract_id` could check whether the current frame already knows the contract's executable type (it does — the frame's `ScContractInstance` is held while executing SAC) and skip `retrieve_contract_instance_from_storage` when the executable is known to be `StellarAsset`. Alternatively, a host-side per-invocation cache keyed on `contract_id → ContractExecutable` (set on first frame entry) would amortize this across all calls in the same tx.

## Anti-Evidence

- `Storage::get` charges metered cost (`MemCpy`, `VisitObject`, comparison work) that contributes to budget consumption visible to fees and consensus. Removing the call removes those charges — a protocol-visible metering change.
- The metering-preserving variant would have to replay the same `BudgetImpl::charge` calls in the same order with the same amounts, which leaves only the physical `Vec` lookup and `Rc::clone` time as recoverable (sub-µs per call).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (distinct from fail/005-extend-instance-and-code-ttl-redundant-per-call, which targeted redundancy *across* `extend_current_contract_instance_and_code_ttl` calls; this hypothesis targets a redundant probe *within* a single call).

### Why It Failed

**Sub-Low even at most optimistic upper bound.** The redundant probe being targeted is approximately a `Storage::get(instance_key)` returning an in-map entry. Realistic per-call cost is ~5µs including budget charges. Aggregate worker-CPU saving:

- 15,770 calls/run × 5µs/call ≈ 79 ms aggregate worker CPU
- After 8-way cluster parallelism normalization: ~10 ms wall-clock total per run
- Spread over 70 ledgers: ~0.14 ms/ledger ≈ **0.06% of the 218 ms soroswap baseline**

This is two orders of magnitude below the 3% Medium floor and an order of magnitude below the 1% Low floor.

Worse, any actual implementation must preserve the existing `Storage::get` metering charge sequence (Meta-Pattern #9: metering changes are protocol-visible). After replaying the budget charges, the remaining physical savings (one `Vec` lookup + one `Rc::clone`) are sub-µs per call, making the realistic saving effectively zero.

### Lesson Learned

Inside `extend_current_contract_instance_and_code_ttl`, the apparent redundant instance read in `extend_contract_code_ttl_from_contract_id` is structurally needed for the wasm-hash discovery path, and a SAC-specific fast path is bounded by `(call_count × storage_get_µs) / NUM_CLUSTERS / N_ledgers` — for soroswap's ~15,800 calls/run this is firmly in sub-Low territory. Pair with Meta-Pattern #14: sub-millisecond per-ledger serial paths inside the apply window are exhausted; the same upper-bound formula applies to per-call host-function probe-counts within the Soroban host.
