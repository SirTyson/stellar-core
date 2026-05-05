# H017: Coalesce SAC instance/code TTL extension calls

**Date**: 2026-05-05
**Subsystem**: ledger / Soroban SAC apply path
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated SAC calls in one host invocation should extend the current contract instance and code TTL when needed, preserve the same final live-until ledger values, and still fail on invalid TTL operations. If the same current contract has already had its instance/code TTL extended to the target in the same invocation, later identical extension calls should not repeat storage lookup and map-update work.

## Mechanism

The tempting mechanism is that every hot SAC entry point calls `extend_current_contract_instance_and_code_ttl`, including `transfer`, and soroswap invokes SAC transfers heavily. A per-host "already extended current contract to this threshold/extend pair" cache could skip repeated extension preparation for the same current contract and reduce storage/TTL map work.

## Trigger

Run the current soroswap apply-load workload (`soroswap, TX=2000, T=8`) and inspect SAC transfer calls that repeatedly enter `StellarAssetContract::transfer` for the same token contracts.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - `transfer` calls `extend_current_contract_instance_and_code_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2338` - host helper extends current contract instance and code TTL.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:532-575` - storage-level TTL extension preparation and update.

## Evidence

The current soroswap trace shows `extend_current_contract_instance_and_code_ttl` fully inside `applyLedger`: total 960,691,858 ns across 47,428 events, with self-time 543,047,205 ns across the two dispatch/vmcaller spans. The child `extend key` zone reports total 252,582,503 ns and self-time 50,401,223 ns across 94,908 calls.

## Anti-Evidence

These are aggregate worker-thread times. With the soroswap workload configured for `NUM_CLUSTERS=8`, even eliminating the full 960,691,858 ns aggregate extension total projects to roughly 120 ms over a 5,230 ms `applyLedger` trace, about 2.3%. The true removable portion is lower because some first extension per contract is required and storage/key conversion work is shared with other host paths.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS - not previously investigated

### Why It Failed

The optimization is plausible but below this objective's Medium severity threshold. The maximum optimistic savings after normalizing aggregate worker time by the 8 configured clusters is under 3% of apply time, and realistic savings would only remove repeated extensions, not the first required extension or unrelated storage work.

### Lesson Learned

For Soroban worker-thread zones, normalize aggregate Tracy time by configured cluster parallelism before assigning severity. SAC TTL extension coalescing may be a clean Low-tier cleanup, but this objective only promotes Medium and High hypotheses.
