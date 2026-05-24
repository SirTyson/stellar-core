# H001: Single-Pass Native Pool Instance Fields

**Date**: 2026-05-24
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction in native Soroswap pool swap storage handling
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-gated native Soroswap pool `swap` calls, apply should validate the pool instance layout, read `token_0`, `token_1`, `reserve_0`, and `reserve_1`, perform the same outbound SAC transfer(s), compute the same input amounts and K-invariant, update reserve instance-storage keys 2 and 3, emit the same swap event, and produce identical ledger entries and metering to the current native pool path. Non-matching pool instances, older protocols, unexpected storage layouts, or malformed arguments should continue to fall back to the existing Wasm/native path unchanged.

## Mechanism

`try_call_native_soroswap_pool_swap` already scans the raw `ScContractInstance.storage` map to prove the native pool layout is present, but `call_native_soroswap_pool_swap` then re-enters instance storage and repeatedly looks up/converts the same token and reserve fields before writing reserves back with two independent map inserts. A single parsed `NativePoolFields` bundle produced during the layout check could carry the typed token addresses, reserves, and raw storage positions into the native swap body, then update the reserve positions directly in one instance-storage mutation. This targets the apply-descendant storage-map family rather than a per-tx C++ micro-cost, and it preserves determinism because it does not change cluster scheduling or add workers.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load scenario with protocol 27 enabled, using the native Soroswap pool `swap` path where the pool instance storage has the canonical integer-keyed map layout: token addresses at keys 0 and 1, reserves at keys 2 and 3, and optional `k_last` at key 5. The optimized path should trigger only when the same shape checks that currently admit native pool swap all pass.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — native pool swap gate validates argument and instance-storage shape, then enters `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — native swap re-reads token and reserve values through instance-storage helpers after the shape check.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1257-1265` — reserve updates perform two ordered-map inserts into instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-352,480-489` — `storage get`/`storage put` descend into indexed map lookups and map replacement.

## Evidence

The current Tracy trace from `ai-summary/CURRENT_STATE.md` has 72 `applyLedger` windows totaling 4,802,199,603 ns. Timestamp filtering confirms all events for the relevant storage-map zones overlap those windows: `storage get` totals 707,240,794 ns, `map lookup indexed` totals 612,594,844 ns, `new map` totals 449,333,084 ns, and `storage put` totals 145,311,950 ns. These are worker aggregates, so T=8 division is required, but the combined storage-map family still provides a Medium-sized upper bound, and the code shows native pool swap doing avoidable duplicate instance-field reads and reserve map rewrites on every swap.

## Anti-Evidence

The broad `storage get`, `map lookup indexed`, and `new map` zones include more than native pool instance storage, so the PoC must instrument or benchmark the exact native pool subset before claiming the full bound. The reserve update still needs to produce the same metered storage effects, budget charges, and ordered `ScMap` representation, so a direct-position update is only viable if it preserves the same observable storage and metering semantics under the next-protocol gate.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of accepted baseline `ai-summary/CURRENT_STATE.md` (`001-native-pool-raw-instance-storage`)
**Failed At**: reviewer

### Trace Summary

The stale target code path enters `Host::call_contract_fn`, retrieves the pool contract instance from durable storage, checks the raw `ScContractInstance.storage` layout in `try_call_native_soroswap_pool_swap`, then pushes a `Frame::NativeContract` and re-reads instance fields through `soroswap_pool_instance_storage_get`. On success, `call_native_soroswap_pool_swap` performs SAC transfers/balance reads, computes input amounts and the K-invariant, mutates reserve keys 2 and 3 with two `MeteredOrdMap::insert` calls, and persists modified instance storage when the frame exits. However `ai-summary/CURRENT_STATE.md` records the accepted current baseline as `001-native-pool-raw-instance-storage`, which already reads fixed raw `ScMap` fields, keeps reserve values as `i128`, rebuilds the raw storage map directly for reserve updates, and avoids the extra full-instance clone when entering the native pool frame.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — `call_contract_fn` retrieves the contract instance and dispatches Wasm contracts through native Soroswap pool getter/swap gates before VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:913-929` — raw `ScMap` shape checks only test that fixed keys contain address/i128 values; they do not carry typed values into the stale swap body.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1003` — stale helper path uses `with_instance_storage` and `MeteredOrdMap::get` for every token/reserve field access.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — stale native swap gate validates protocol, Wasm hash, symbol, argument shape, and raw pool layout, then clones the full instance into `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1266` — stale native swap re-reads token/reserve fields and rewrites reserves via two ordered-map inserts.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1882` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:213-257` — instance storage is lazily converted to `InstanceStorageMap`, converted back to `ScMap`, and persisted through `store_contract_instance` only if marked modified.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-352,418-489` — durable `Storage::get`/`put` paths perform footprint checks and storage-map lookup/replacement, but the duplicate pool field reads themselves are in-memory instance-storage map lookups rather than additional durable storage gets.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-242,325-384` — ordinary `get`/`insert` do binary-search lookup and full map rebuild; known-position helpers already exist for storage maps but the accepted raw-instance baseline supersedes this stale path.
- `ai-summary/CURRENT_STATE.md:1-36,80-95,126-134` — accepted baseline records the native pool raw instance-storage optimization and protocol-27 gating.

### Why It Failed

This hypothesis is a rediscovery of work already accepted into the current optimization baseline. The exact proposed direction — pass raw native pool instance fields through the layout check, avoid repeated instance-storage representation work, and update reserves by rebuilding the raw storage map directly — is recorded in `ai-summary/CURRENT_STATE.md` as the accepted `001-native-pool-raw-instance-storage` state. Additionally, the stale mechanism over-attributes broad `storage get`/`storage put` Tracy totals to duplicate pool field reads: those field reads are `InstanceStorageMap` lookups, while durable storage get/put still occur for instance retrieval, TTL handling, and final persistence.

### Lesson Learned

Future native Soroswap pool storage hypotheses must be rebased against the accepted `bf6625f8` p26 baseline in `CURRENT_STATE.md`; older `fbbea0d9`-style source lines still show the pre-raw-instance path and will produce duplicate hypotheses.
