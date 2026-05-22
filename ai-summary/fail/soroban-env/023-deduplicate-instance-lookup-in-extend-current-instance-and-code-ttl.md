# H023: Skip the second `retrieve_contract_instance_from_storage` in `extend_current_contract_instance_and_code_ttl` by threading the instance entry across the two TTL extensions

**Date**: 2026-05-22
**Subsystem**: soroban-env (p26 host)
**Severity**: Low
**Impact**: Apply-time reduction on Soroban host TTL extension hot path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A single host invocation of `extend_current_contract_instance_and_code_ttl`
on a Wasm-backed contract should read the contract instance ledger entry
exactly once: the same entry is needed (a) to extend the instance TTL and
(b) to extract the `ContractExecutable::Wasm(wasm_hash)` for the
companion code-TTL extension. For SAC contracts the second read is
strictly redundant because the executable variant is known to be
`StellarAsset`, which is a no-op for the code-TTL branch.

## Mechanism

`Host::extend_current_contract_instance_and_code_ttl`
(`src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2335`) calls
`extend_contract_instance_ttl_from_contract_id` then
`extend_contract_code_ttl_from_contract_id`. The first call's
`prepare_extend_ttl` (`storage.rs:433-498`) loads the instance entry via
`get_with_live_until_ledger`. The second call
(`data_helper.rs:247-265`) immediately re-invokes
`retrieve_contract_instance_from_storage`
(`data_helper.rs:114-120`), which performs the same `storage.get(...)` and
then `extract_contract_instance_from_ledger_entry` (with a metered
`ScContractInstance::metered_clone`). Threading the instance entry from
the first pass into the second pass would eliminate one full storage-map
lookup plus the `ScContractInstance` metered clone per call.

## Trigger

Every Wasm contract that calls `extend_current_contract_instance_and_code_ttl`
during apply triggers the redundant work. In the soroswap apply trace this
host function is invoked 27,942 times (essentially once or twice per
contract frame on a workload that performs ~14,040 Wasm contract
invocations + SAC built-in invocations).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2335` — host fn body.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-281` —
  `extend_contract_code_ttl_from_contract_id` and
  `extend_contract_instance_ttl_from_contract_id`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:90-120` —
  `extract_contract_instance_from_ledger_entry` and
  `retrieve_contract_instance_from_storage`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:433-516` —
  `prepare_extend_ttl` / `apply_ttl_extension`.

## Evidence

- Tracy zone `extend_current_contract_instance_and_code_ttl`
  (`vmcaller_env.rs:270`): 390.3 ms aggregate self over 27,942 calls,
  ~14 µs/call on the accepted soroswap baseline (~3.79% of apply envelope).
- The instance entry is loaded twice on the Wasm path and three times on
  some SAC paths (once by `prepare_extend_ttl`, once by
  `retrieve_contract_instance_from_storage` in the code branch). The
  second load adds `Storage::get` (footprint guard + MeteredOrdMap probe +
  `extract_contract_instance_from_ledger_entry` + `metered_clone` of the
  `ScContractInstance`).
- Removing one `storage.get` + one `ScContractInstance::metered_clone` per
  call is a physically real saving for both the Wasm path (~14,000 calls)
  and the SAC path (~14,000 calls).

## Anti-Evidence

- The `ScContractInstance::metered_clone` and `Storage::get` calls in the
  redundant path are not free of protocol-visible metering: they charge
  `MemAlloc`, `MemCpy`, `MapVisit`, and `ValDeser` budget entries that are
  part of the network-observable `cpu_insns` / `mem_bytes`. A budget-
  preserving refactor must replay each of those `charge()` calls anyway,
  leaving only the physical hash/binary-search/copy work removable.
- Fail entry 003 already covers TTL-extension memoization broadly and
  states: "Aggregate `extend_current_contract_instance_and_code_ttl`
  zones are ~3–4% of apply envelope, and the safely removable subset
  (SAC no-op code-TTL reload) is well below 3% after accounting for
  metered budget charges and first-extension overhead." The within-a-
  single-call deduplication targeted here is bounded by the same wall:
  even an unrealistically perfect removal of the second `storage.get` +
  `metered_clone` per call yields, optimistically, perhaps 50–80 ms
  aggregate trace time. After 8-cluster parallelism and 72 ledgers that
  is ≈ 0.1 ms per ledger, ~0.04% of the 250 ms apply baseline.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — fail/003 targets TTL-extension memoization across calls
and fail/002-frame-instance-shortcut-extend-ttl targets reading the
executable from the frame snapshot; neither investigated this
specific "deduplicate the second `retrieve_contract_instance_from_storage`
within a single host fn call by threading the entry through" angle.

### Why It Failed

Same wall as fail/003: the second storage lookup is wrapped in mandatory
protocol-visible metering (`Storage::get` charges, `ScContractInstance::
metered_clone` charges). A budget-preserving refactor must replay all of
those charges, leaving only the bare hash/binary-search/copy/heap-alloc
work removable. The remaining physical savings, even taken generously,
fall under 0.1 ms per ledger after 8-way cluster parallelism — well below
the 1% benchmark noise floor and three orders of magnitude below the
3% Medium severity floor required by this objective.

### Lesson Learned

Within-a-call deduplication of storage lookups in p26 has the same
budget-preservation problem as cross-call memoization: every removed
`Storage::get` / `metered_clone` requires its `charge()` calls to be
replayed if cpu_insns / mem_bytes are to remain protocol-stable. Future
TTL-extension hypotheses should isolate the *unmetered* sub-fraction of
`extend_current_contract_instance_and_code_ttl` (RefCell borrows, hash
probes, struct field copies that aren't covered by `MeteredClone`) and
demonstrate that subset clears the Medium floor before promotion.
