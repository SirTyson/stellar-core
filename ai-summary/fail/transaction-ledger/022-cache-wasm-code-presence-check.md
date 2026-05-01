# H022: Cache Wasm contract-code presence checks in `instantiate_vm`

**Date**: 2026-05-01
**Subsystem**: transaction-ledger / Soroban VM instantiation
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When `Host::instantiate_vm` uses the inter-ledger module cache, it should still fail if the corresponding contract-code ledger entry is missing from the transaction footprint/storage view. A cache of "this contract-code key exists in the enforcing storage map for this invocation" should preserve the same storage-access enforcement and missing-value error behavior while avoiding repeated `Storage::has` map lookups for the same Wasm hash.

## Mechanism

`instantiate_vm` checks `self.try_borrow_storage_mut()?.has(&wasm_key, self, None)?` before consulting `cache.get_module(wasm_hash)`. In soroswap, every Wasm router/pair call has live contract-code entries and a module-cache hit, so the `storage.has` check looks redundant after the first call to the same code key within an invocation or worker. If this check were hot, caching the positive presence result alongside the decoded contract executable/module lookup could remove a storage-map lookup before each wasmi instantiation.

## Trigger

Run the current soroswap Tracy trace and inspect `storage has` and `Vm::instantiate_wasmi - instantiate` under `applyLedger`. Each Wasm contract call reaches `instantiate_vm` before invoking router/pair code.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — `instantiate_vm` constructs the contract-code key, calls `Storage::has`, then fetches the parsed module from the module cache.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:421-429` — `Storage::has` calls `try_get_full`, enforcing footprint membership and performing a storage-map lookup.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — wasmi instantiation remains the larger visible VM setup cost even if the presence check is skipped.

## Evidence

The source does perform the defensive presence check on the cached-module path. In the current trace, `Vm::instantiate_wasmi - instantiate` is visible inside apply windows, and `instantiate_vm` reaches storage before cache lookup for every Wasm contract call.

## Anti-Evidence

The direct measured cost is tiny. `csvexport-release -e -f "storage has"` on the current soroswap trace reports only `5,116,798 ns` self-time over `20,594` calls for the whole trace, far below the 3% Medium floor even before dividing aggregate worker time by the eight parallel clusters. The larger `Vm::instantiate_wasmi - instantiate` zone has already been investigated as below threshold and constrained by wasmi store ownership.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Failed At**: hypothesis
**Novelty**: PASS — adjacent to VM-instantiation reuse failures but targets the specific pre-cache `Storage::has` guard

### Why It Failed

The code path is real but not performance-significant. The `storage.has` guard consumes about five milliseconds of aggregate self-time across the entire current soroswap trace, so removing it would be orders of magnitude below the objective's accepted Medium threshold.

### Lesson Learned

Before proposing VM-instantiation shortcuts, isolate the exact sub-step. Defensive storage-presence checks in `instantiate_vm` are much smaller than the visible wasmi instantiation cost and should not be re-proposed as standalone optimizations.
