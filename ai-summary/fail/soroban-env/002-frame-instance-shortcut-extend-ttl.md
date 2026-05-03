# H002: Use current frame's ScContractInstance to bypass redundant retrieve in extend_current_contract_instance_and_code_ttl

**Date**: 2026-05-03
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3–4% soroswap apply-time reduction projected (one redundant Storage::get + ScContractInstance metered_clone removed per SAC entrypoint)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`extend_current_contract_instance_and_code_ttl` should not re-read the
running contract's `ScContractInstance` from `Storage` when the current
frame already holds that exact value. The frame variants
`Frame::ContractVM { instance, .. }` and
`Frame::StellarAssetContract(_, _, _, instance)` (defined at
`host/frame.rs:138–166`) carry the contract instance by value, populated
when the frame was pushed. The TTL-extension implementation only needs the
`ScContractInstance.executable` discriminant to decide whether to extend
the contract code TTL (only for `ContractExecutable::Wasm(hash)`). Reading
that discriminant from the frame is O(1) and incurs no storage borrow,
binary-search, or `metered_clone` of the entire instance.

The protocol-visible budget on each call must remain byte-identical to the
current implementation: the optimization replays the budget charges that
`Storage::get` and `extract_contract_instance_from_ledger_entry` would have
performed (footprint `MapAccess`, storage map binary-search, `MemCpy` for
the `metered_clone` of the `ScContractInstance` payload), via direct
`Budget::charge` calls, while skipping the actual physical storage
traversal and clone allocation.

## Mechanism

`extend_current_contract_instance_and_code_ttl`
(`host.rs:2320–2335`) calls `extend_contract_code_ttl_from_contract_id`
(`host/data_helper.rs:247–265`), which always invokes
`retrieve_contract_instance_from_storage(&instance_key)`
(`host/data_helper.rs:114–120`). That helper does
`self.try_borrow_storage_mut()?.get(key, self, None)?` — a footprint check
plus a `LedgerKey`-keyed binary search over the storage map — followed by
`extract_contract_instance_from_ledger_entry`, which `metered_clone`s the
`ScContractInstance` (potentially including its instance storage `ScMap`)
just to read the executable discriminant.

For the SAC path that dominates soroswap, the executable is
`ContractExecutable::StellarAsset` and the
`extend_contract_code_ttl_from_contract_id` call therefore *does no work*
after the discriminant check (the `match` arm is `{}`). Every per-event
`extend_current_contract_instance_and_code_ttl` call thus pays a full
storage lookup and instance clone solely to learn that the SAC
executable is `StellarAsset`. The current frame already holds the
authoritative `ScContractInstance`; reading
`frame.instance.executable` directly avoids the storage round-trip.

The deviation between expected and actual behavior is the redundant
storage borrow + `Rc<LedgerEntry>` traversal + `ScContractInstance`
clone on every SAC entrypoint. On soroswap each `transfer`, `balance`,
`approve`, `mint`, `burn`, etc. SAC entrypoint goes through this path
exactly once, contributing to the aggregate
`extend_current_contract_instance_and_code_ttl` Tracy cost.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the soroswap scenario. Every
SAC entrypoint reached during a swap (transfer, transfer-from, balance,
approve, etc.) calls `extend_current_contract_instance_and_code_ttl`
exactly once, which in turn invokes the redundant
`retrieve_contract_instance_from_storage` discussed above.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320–2335` —
  `extend_current_contract_instance_and_code_ttl`. Refactor so the
  executable discriminant is read from the current frame, and only the
  TTL `Storage::extend_ttl` calls are issued (no
  `retrieve_contract_instance_from_storage`).
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247–265`
  — `extend_contract_code_ttl_from_contract_id`. Add a sibling helper
  that takes a borrowed `ContractExecutable` instead of an `instance_key`,
  and skips the `retrieve_contract_instance_from_storage` call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:138–166`
  — frame variants already expose `instance: ScContractInstance`; this
  is the source of truth used by the optimization.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` (currently
  has accessor `Frame::instance() -> Option<&ScContractInstance>`
  around line 164/166) — extend or reuse to surface the executable
  discriminant to the caller without exposing the full
  `ScContractInstance`.

## Evidence

- Tracy soroswap trace:
  `extend_current_contract_instance_and_code_ttl` (vmcaller wrapper)
  self-time 364 ms / 27,047 calls (3.54% of trace self-time, 13.5 µs/call)
  + dispatch wrapper 178 ms / 20,381 calls (1.73%) — combined ≈ 5.4% of
  trace self-time, all of it on the SAC entrypoint path that this
  optimization targets.
- The current implementation calls
  `retrieve_contract_instance_from_storage` once per SAC entrypoint —
  a `Storage::get` (footprint check + binary-search of the storage
  `MeteredOrdMap`) plus an `extract_contract_instance_from_ledger_entry`
  whose only work is a `metered_clone` of the `ScContractInstance`
  followed by a discriminant check.
- The frame already owns the authoritative `ScContractInstance`
  (`Frame::ContractVM { instance, .. }` for Wasm contracts and
  `Frame::StellarAssetContract(_, _, _, instance)` for SAC), so the
  redundancy is unambiguous and removable.
- For SAC frames the entire extension path is a no-op after the
  discriminant check (`ContractExecutable::StellarAsset =>` `{}` in
  `extend_contract_code_ttl_from_contract_id`); the storage lookup
  exists only to read that discriminant.

## Anti-Evidence

- Fail #003 (`003.md` in `ai-summary/fail/soroban-env/summary.md`)
  rejected a related angle: "Memoize repeated SAC instance/code TTL
  extensions within one host invocation". That rejection's reasoning
  was that the **safely removable subset** (after exact budget
  preservation) was below 3% across the trace as it stood at the time
  of the previous baseline. The current baseline (post-protocol-gated
  metering coalescing) shifted some other costs out of the trace and
  the combined `extend_current_contract_instance_and_code_ttl`
  self-time is now 5.4%, so the safely removable subset may now clear
  Medium — but verification requires PoC measurement.
- Exact-budget preservation: the current path charges (a) a footprint
  `MapAccess` for the instance key, (b) a `MeteredOrdMap`
  binary-search over the storage map, (c) a `MemCpy` for the `Rc`
  bump on the storage entry, and (d) a `MemCpy` for the
  `ScContractInstance::metered_clone`. To preserve exact `cpu_insns`
  and `mem_bytes`, the frame-shortcut path must replay all four
  charges via direct `Budget::charge` calls. Once those are replayed,
  the residual savings are the actual binary-search comparator work
  and the `metered_clone` allocation/copy. If the SAC instance storage
  is small (typical: just the metadata entry + admin), the
  `metered_clone` payload is small and the absolute savings per call
  are modest.
- The instance value that the frame holds is the *snapshot at frame
  creation*; if the contract has mutated its instance storage during
  the current frame, the `executable` field is unchanged (it cannot
  be mutated mid-call by SDK APIs), so reading the executable from
  the frame snapshot is always correct. The TTL extension itself
  does not depend on instance storage contents.
- The `extend_ttl` calls themselves still touch the storage map and
  the TTL map; this hypothesis only removes the redundant
  `retrieve_contract_instance_from_storage`, not the TTL writes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to fail-summary #003, but this exact frame-snapshot mechanism was not previously recorded
**Failed At**: reviewer

### Trace Summary

`call_contract_fn` loads the contract instance from storage and stores a snapshot of it in either `Frame::ContractVM` or `Frame::StellarAssetContract`. SAC entrypoints then call `extend_current_contract_instance_and_code_ttl`, which extends the instance TTL and calls `extend_contract_code_ttl_from_contract_id`; that helper reloads the instance from `Storage` and matches on its executable. The reload is physically redundant for ordinary SAC calls, but the proposed generalized frame shortcut is not correctness-preserving because Wasm contracts can call `update_current_contract_wasm` during the same frame, which rewrites the current contract instance executable in storage while the frame snapshot remains stale. A SAC-only refinement would avoid that stale-Wasm case, but after exact budget preservation and the accepted storage-map indexed fast path, the remaining removable work is below this objective's Medium floor.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` retrieves the instance from storage and pushes a frame containing that snapshot before invoking either Wasm or SAC code.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:148-203,206-225,229-249,252-368,403-411` — SAC `allowance`, `approve`, `balance`, `authorized`, `transfer`, `transfer_from`, `burn`, `burn_from`, `clawback`, `set_authorized`, `mint`, `set_admin`, and `trust` call `extend_current_contract_instance_and_code_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2344-2358` — `extend_current_contract_instance_and_code_ttl` builds the current contract instance key, extends the instance TTL, then calls `extend_contract_code_ttl_from_contract_id`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-265` — `extend_contract_code_ttl_from_contract_id` reloads the instance and extends code TTL only for `ContractExecutable::Wasm`; `ContractExecutable::StellarAsset` is a no-op after the discriminant read.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:90-120` — `retrieve_contract_instance_from_storage` performs `Storage::get` and `extract_contract_instance_from_ledger_entry`, whose `ScContractInstance::metered_clone` charges and physically clones instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-377` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-339` — the current accepted baseline already uses an enforcing-mode side index and `get_at_known_position` for storage-map lookups, so the old binary-search comparator work cited by the hypothesis is no longer the dominant removable cost.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2565-2585` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:173-217` — `update_current_contract_wasm` verifies the new code and calls `store_contract_instance(Some(new_executable), ...)`, mutating the current contract instance executable in storage.
- `src/rust/soroban/p26/soroban-env-common/env.json:1487-1498,1523-1537` — both `update_current_contract_wasm` and `extend_current_contract_instance_and_code_ttl` are host functions available to contracts; the update is explicitly safe to call in the middle of a function.

### Why It Failed

The hypothesis's core correctness assumption is false for `Frame::ContractVM`: the executable field can be changed mid-frame by `update_current_contract_wasm`. The current storage reload observes the updated executable; a shortcut through `frame.instance.executable` would instead use the stale executable captured when the frame was pushed, and could extend the old Wasm code TTL or skip the new one. Restricting the shortcut to `Frame::StellarAssetContract` would avoid that stale-Wasm bug, but then the finding collapses to the SAC no-op code-TTL-reload subset already called out in fail-summary #003. In the current source that subset is even smaller because storage and footprint lookups use the accepted indexed fast path, and exact budget preservation still requires replaying the metered lookup and clone charges; the remaining physical hash/position lookup and small instance clone cannot justify the projected 3-4% soroswap apply-time reduction.

### Lesson Learned

Frame-held contract instances are snapshots, not an always-current view of the instance ledger entry. TTL-extension optimizations that read `executable` must account for `update_current_contract_wasm`, and SAC-only variants need a focused measurement of the physical no-op code-TTL reload after subtracting mandatory metering and existing storage-map fast paths before being promoted.
