# H001: Extend native Soroswap pool code TTL from the already-known Wasm hash

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / Soroban host native Soroswap path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing redundant pool contract-instance reads from native getter/swap code-TTL extension
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the protocol-gated native Soroswap pool getter/swap path matches `SOROSWAP_POOL_WASM_HASH`, it should extend the same pool instance TTL and pool Wasm-code TTL as the generic Wasm execution path. The code TTL extension should use the `wasm_hash` that was already loaded and validated by `call_contract_fn`, rather than re-loading and re-cloning the pool contract instance only to recover the same executable hash.

## Mechanism

`call_contract_fn` loads the pool contract instance, matches `ContractExecutable::Wasm(wasm_hash)`, checks the pool hash, and then enters `try_call_native_soroswap_pool_getter` or `try_call_native_soroswap_pool_swap`. Inside the native bodies, `call_native_soroswap_pool_getter` and `call_native_soroswap_pool_swap` call `extend_contract_code_ttl_from_contract_id(instance_key, ...)`, whose first step is `retrieve_contract_instance_from_storage(&instance_key)?.executable`, re-entering storage and cloning the same `ScContractInstance` that dispatch already inspected. A native-pool-only helper such as `extend_contract_code_ttl_for_known_wasm_hash(instance_key, wasm_hash, threshold, extend_to)` can construct the `ContractCode` key directly and call `Storage::extend_ttl`, preserving deterministic ledger writes while removing one pool-instance storage lookup and clone for every native getter/swap call.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) on the `04c9035453c68519e19c52006255f4ca0f40ca42` baseline. Each router-driven swap reaches native pool getter and native pool swap hooks; each hook has already matched the pool Wasm hash at dispatch and then redundantly re-reads the same pool instance when extending the code TTL.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-828` — `call_contract_fn` loads the contract instance, matches `ContractExecutable::Wasm(wasm_hash)`, and dispatches to native Soroswap hooks before VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-870` — native pool getter gate receives `wasm_hash` but drops it before `call_native_soroswap_pool_getter`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — native pool swap gate receives `wasm_hash` but drops it before `call_native_soroswap_pool_swap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:931-946` — getter body extends instance TTL, then calls the re-reading code-TTL helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1093` — swap body repeats the same instance/code TTL extension pattern.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-305` — `extend_contract_code_ttl_from_contract_id` re-loads the instance solely to recover the executable hash.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:646-687` — `Storage::extend_ttl` performs the actual deterministic TTL update once given a concrete key.

## Evidence

The current soroswap Tracy trace confirms the targeted zones are inside the measured apply window: `call` at `soroban-env-host/src/vm/dispatch.rs:304` contributes **5,134.323 ms total** across **23,569** start-in-`applyLedger` events; `storage get` contributes **672.075 ms total** across **321,796** start-in-`applyLedger` events; `extend_current_contract_instance_and_code_ttl` contributes **340.374 ms total** across **15,684** start-in-`applyLedger` events. The native hooks are current-source code, and the redundant pool-instance read is structural: dispatch already has `wasm_hash`, while `extend_contract_code_ttl_from_contract_id` loads the instance again to derive it.

This is not a parallelism change and does not alter ordering. The code-TTL key for a matched pool contract is a pure function of the already-validated `wasm_hash`; extending that key through the existing `Storage::extend_ttl` path should produce the same ledger write or no-op as the current helper.

## Anti-Evidence

The broad Tracy zones include mandatory storage and dispatch work unrelated to pool code-TTL extension. A PoC needs a narrow counter or span around `extend_contract_code_ttl_from_contract_id` calls made from native pool getter/swap bodies to prove the redundant instance load clears the Medium threshold after `NUM_CLUSTERS=8` normalization. The helper must remain protocol-gated with the native hook because using the known hash changes the exact metered work relative to released p26 replay.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `001-frame-cached-contract-instance-ttl.md`
**Failed At**: reviewer

### Trace Summary

`call_contract_fn` loads the pool contract instance at dispatch, matches `ContractExecutable::Wasm(wasm_hash)`, passes that hash into both native Soroswap gates, and only runs the native bodies after the pool Wasm hash and instance layout match. The native getter and swap bodies then extend the pool instance TTL and call `extend_contract_code_ttl_from_contract_id`, which re-enters storage and clones the same contract instance solely to recover the Wasm hash before constructing the `ContractCode` key. `Storage::extend_ttl` is the deterministic TTL update once the code key is known, so the claimed redundant lookup exists, but it is the same frame/current-contract code-TTL executable reuse class already investigated.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-828` — dispatch loads the current contract instance, matches `ContractExecutable::Wasm(wasm_hash)`, tries native Soroswap getter/swap hooks, and falls back to VM execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-870` — native getter gate receives `wasm_hash`, verifies `SOROSWAP_POOL_WASM_HASH`, validates getter shape/layout, then pushes a native contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:931-946` — native getter extends the instance TTL and then calls `extend_contract_code_ttl_from_contract_id(instance_key, ...)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1074` — native swap gate receives the same already-matched `wasm_hash`, validates function/arguments/layout, then pushes a native contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1093` — native swap repeats the instance TTL extension followed by the same code-TTL helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:90-120,162-170,287-305` — `retrieve_contract_instance_from_storage` performs a storage `get` and `metered_clone`; `contract_code_ledger_key` builds the code key from a hash; `extend_contract_code_ttl_from_contract_id` reloads the instance only to branch on `executable`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:646-687` — `extend_ttl` applies the actual thresholded TTL update for a concrete ledger key.
- `ai-summary/fail/transaction-ledger/summary.md` — prior entries `001-frame-cached-contract-instance-ttl.md`, `020-skip-sac-code-ttl-instance-retrieval.md`, and `006-coalesce-current-contract-instance-ttl-extend.md` record the same one-storage-lookup/code-TTL optimization family as below the objective threshold after cluster normalization.

### Why It Failed

This is not novel. The prior transaction-ledger fail summary already records `001-frame-cached-contract-instance-ttl.md`, "Reuse current frame contract instance when extending current contract code TTL", with the same core mechanism: avoid reloading the current contract instance when the executable/hash is already available from the active frame/dispatch context. This hypothesis narrows that idea to the native Soroswap pool hooks and uses the passed `wasm_hash` instead of a frame-cached instance, but the removable operation is still one current-contract instance storage lookup/clone before a mandatory code-TTL `extend_ttl`.

Even if treated as a refinement rather than a duplicate, it falls below the objective's Medium floor. The cited `extend_current_contract_instance_and_code_ttl` and `storage get` totals are broad aggregate worker-time zones; prior TTL reviews found one skipped code-TTL instance retrieval is at noise-floor/sub-1% scale once divided across `NUM_CLUSTERS=8`, while the actual TTL extension lookup/update remains required. A native-pool-only variant executes on getter/swap hooks but still removes only the executable rediscovery step, not the pool instance TTL extension, code-key TTL lookup, threshold logic, ledger write/no-op decision, or any swap/getter work.

### Lesson Learned

Known-hash native hooks can safely identify redundant executable rediscovery, but one current-contract code-TTL storage lookup is too narrow for the optimize-soroswap Medium threshold and has already been rejected in the frame-cached/code-TTL family. Future TTL hypotheses need either a materially broader coalescing mechanism with narrow measurements or a demonstrated synchronous critical-path saving above 3%, not attribution from broad storage/TTL Tracy totals.
