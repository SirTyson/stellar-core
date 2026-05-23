# H004: Static-Wasm-Hash Fast Path to Skip ScContractInstance Retrieve in Native Pool Code-TTL Extension

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: <1% soroswap apply-time reduction; sub-Medium and rejected under objective threshold
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the next-protocol native Soroswap pool swap path extends the pool contract's *code* TTL via
`extend_contract_code_ttl_from_contract_id(instance_key, threshold, extend_to)`, the host should
extend the TTL of the contract-code ledger entry keyed by the pool's wasm hash. The wasm hash is
already known statically as `SOROSWAP_POOL_WASM_HASH` and has been validated upstream in
`try_call_native_soroswap_pool_swap` before the frame was pushed. The TTL extension itself
(`Storage::extend_ttl`) is the only mandatory side effect.

## Mechanism

The current implementation of `extend_contract_code_ttl_from_contract_id`
(`src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-305`) reloads the full
`ScContractInstance` from storage just to learn the executable's wasm hash:

```rust
match self.retrieve_contract_instance_from_storage(&instance_key)?.executable {
    ContractExecutable::Wasm(wasm_hash) => {
        let key = self.contract_code_ledger_key(&wasm_hash)?;
        self.try_borrow_storage_mut()?.extend_ttl(self, key, threshold, extend_to, None)?;
    }
    ContractExecutable::StellarAsset => {}
}
```

`retrieve_contract_instance_from_storage` performs a metered `Storage::get(instance_key)` plus a
`ScContractInstance::metered_clone` of the full instance (including its instance-storage `ScMap`
with ~5–6 entries: token_0, token_1, reserve_0, reserve_1, factory, optionally k_last). For the
native pool swap path, the wasm hash is already a `const` (`SOROSWAP_POOL_WASM_HASH`) and was just
matched in `try_call_native_soroswap_pool_swap`. A specialized helper could build the code key
directly from the known hash and call `Storage::extend_ttl` without the redundant instance load.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on the next-protocol soroswap
workload (`soroswap, TX=2000, T=8`). Every native pool swap entry currently incurs one redundant
`retrieve_contract_instance_from_storage` inside the code-TTL extension call at
`call_native_soroswap_pool_swap` line 1089–1093.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1084-1093` — native pool swap calls
  both `extend_contract_instance_ttl_from_contract_id` and
  `extend_contract_code_ttl_from_contract_id`; the code-TTL call redundantly retrieves the
  instance even though the wasm hash is known.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-305` —
  `extend_contract_code_ttl_from_contract_id` body that performs the redundant retrieve+clone.

## Evidence

- Tracy `extend_current_contract_instance_and_code_ttl` zone (related path) self-time is 212 ms
  across 15,770 calls (apply-contained, ~2.07% of soroswap apply). The native pool path uses the
  newer `_from_contract_id` variants which have similar per-call overhead.
- The accepted baseline already establishes that next-protocol native paths can intentionally
  deviate from p26 metering (CURRENT_STATE: "protocol-gated host metering coalescing").
- The pool wasm hash is static (`SOROSWAP_POOL_WASM_HASH`) and validated before entering the
  native frame, so the retrieve is provably redundant for this specific call site.

## Anti-Evidence

- The `retrieve_contract_instance_from_storage` call carries protocol-visible metering charges
  (`Storage::get` charge plus `ScContractInstance::metered_clone`). Skipping it without replay
  changes the budget envelope for the native path; this is permitted under the next-protocol gate
  but must be confirmed to not flip any `try_call`-observable `BudgetExceeded` transition.
- Per-call removable physical work is ~one `Storage::get` (binary search + metered access) plus
  one `metered_clone` of a ~5–6-entry `ScMap` — roughly 5–10 µs per swap.
- Pair swap count is ~7,900 over the soroswap benchmark. Total removable wall: ~40–80 ms aggregate
  trace time / 8-way parallelism / ~71 measured `applyLedger` windows ≈ 0.07–0.14 ms per ledger
  wall, or **~0.1–0.2% of soroswap median apply time**.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — the specific "static-wasm-hash code-TTL extend" angle is not in any prior
hypothesis, reviewed, poc, or fail entry; adjacent failures (fail/023, fail/003) cover
deduplication and shortcut variants of the **`extend_current_contract_instance_and_code_ttl`**
host function on the **legacy** path, not the native-pool _from_contract_id variant with a
statically known wasm hash.

### Why It Failed

Projected impact is Low (~0.1–0.2% wall after 8-way parallelism and per-ledger normalization),
which falls below this objective's Medium acceptance floor of 3% and even below the 1%
benchmark-noise floor. The removable work is a single `Storage::get` + single
`ScContractInstance::metered_clone` per swap; while the wasm hash is provably redundant to fetch,
the per-call savings are sub-10 µs and the call count (~7,900 swaps) is too small for this single
shortcut to clear Medium. This is the same dynamic that defeated fail/023 (within-call instance
lookup deduplication) and fail/002-frame-instance-shortcut-extend-ttl (frame-instance shortcut).

### Lesson Learned

For next-protocol native Soroswap pool fast paths, redundant `retrieve_contract_instance_from_storage`
calls in the TTL-extension helpers are a real but Low-impact inefficiency. Combining multiple
adjacent Low optimizations (e.g., this + instance metered_clone reduction + obj_cmp dispatch
elimination) into a single coordinated next-protocol native-pool refactor might clear Medium, but
each component on its own is below the noise floor. Future native-pool hypotheses should aggregate
removable per-swap physical work across all redundant storage accesses, metered clones, and host
dispatches in `call_native_soroswap_pool_swap` and pre-quantify total wall savings before promoting.
