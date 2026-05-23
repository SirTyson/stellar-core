# H011: Reuse Native Pair Frame Instance to Skip Redundant Storage Read in `extend_contract_code_ttl_from_contract_id`

**Date**: 2026-05-23
**Subsystem**: soroban-env, soroban
**Severity**: Low (sub-threshold)
**Impact**: Reduce per-native-pair-swap storage probe count by reusing the in-frame `ScContractInstance.executable` instead of re-reading it from storage
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the native Soroswap pair `swap` entry runs, the host already owns a
fully-resolved `ScContractInstance` for the pair contract — it was passed
into `try_call_native_soroswap_pool_swap` (frame.rs around the inserted
native dispatch block) and metered-cloned into the `Frame::NativeContract`
variant. The native swap immediately calls:

1. `extend_contract_instance_ttl_from_contract_id(instance_key, …)` — pure
   TTL bump on the instance ledger entry.
2. `extend_contract_code_ttl_from_contract_id(instance_key, …)` — which
   internally invokes
   `retrieve_contract_instance_from_storage(&instance_key)` purely to read
   `instance.executable` and decide whether to extend the contract-code
   TTL.

Step 2's storage probe is logically redundant because the executable is
already known to the caller (it's `ContractExecutable::Wasm(pool_hash)`
for every native pair swap, since we only dispatch the native path when
the wasm hash matches `SOROSWAP_POOL_WASM_HASH`). A correct
implementation could pass the already-resolved `executable` (or the
`wasm_hash` itself) into a variant of
`extend_contract_code_ttl_from_contract_id`, avoiding the extra
`Storage::get` and its associated metered comparisons.

## Mechanism

`extend_contract_code_ttl_from_contract_id`
(`soroban-env-host/src/host/data_helper.rs:288-303`) calls
`retrieve_contract_instance_from_storage(&instance_key)` which performs a
`Storage::get` on the instance entry, runs `Footprint::enforce_access`,
binary-searches the enforcing `StorageMap`, validates the returned
entry, and then matches on `executable`. For native pair swaps, the
caller in `call_native_soroswap_pool_swap` already has the
`ScContractInstance` available on the current `Frame::NativeContract`
(via `get_current_frame()` → `Frame::NativeContract(_, _, _,
instance)`). A `_with_executable` variant that takes a precomputed
`&ContractExecutable` (or `wasm_hash: &Hash`) would skip the storage
probe entirely while preserving the TTL extension and its metering.

The ACTUAL deviation from expected: every native pair swap pays one
extra `Storage::get` (footprint lookup + storage-map binary search +
budget charges) just to learn what the calling code already knows.

## Trigger

Run the soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`.
Each accepted swap (≈140k across the 70-ledger run) executes the native
pair `swap` body, which calls
`extend_contract_instance_ttl_from_contract_id` followed by
`extend_contract_code_ttl_from_contract_id` at the top of the function.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` (around the
  `call_native_soroswap_pool_swap` body added by accepted commit
  `03d78248`): the two helper calls at the top of the function.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-303`
  — `extend_contract_code_ttl_from_contract_id` performs the redundant
  instance read.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` —
  `Frame::NativeContract` variant already carries the
  `ScContractInstance`.

## Evidence

Tracy on the current accepted soroswap trace
(`62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`) shows
`storage get` totalling 224ms self-time / 323,533 calls (~693ns/call
self) inside the Soroban worker fan-out. The two
`_from_contract_id` extend helpers contribute roughly two probes per
native pair swap (≈280k extra `Storage::get`-equivalent operations
across the run) on top of the work charged by the dispatched
`extend_current_contract_instance_and_code_ttl` host function (which is
its own 212ms-self-time / 15,770-count Tracy zone for Wasm-dispatched
calls). The native-pair direct calls are *not* counted in that
dispatched zone — they show up inside the broader `SAC transfer` /
`storage get` parent zones.

Optimistic per-call savings: one fewer `Storage::get` per native pair
swap ≈ 3-5 µs (footprint enforcement + storage-map binary search +
metered comparisons + budget charges that survive into a "no metering
change" variant only as the bare physical lookup).

## Anti-Evidence

- The retained budget charges in `Storage::get`
  (`Footprint::enforce_access`, `MeteredOrdMap::find`,
  `Compare<HostObject>`, `Rc::clone`, value-shape validation) are
  protocol-visible metering work. A metering-preserving variant has to
  replay those charges, so the recoverable saving is only the bare
  physical lookup + `Rc::clone` time (sub-µs per call).
- A non-metering-preserving variant requires a protocol-27 gate, but
  Meta-Pattern #16 already classifies sub-Medium charge-coalescing as
  exhausted.
- Fail 003 (`003-skip-redundant-instance-read-in-extend-code-ttl.md`)
  already ruled this redundant probe sub-Low for the SAC-transfer call
  site; the native-pair call site has even fewer per-ledger calls
  (~140k vs. ~15.7k dispatched `extend_current...` calls per cluster
  worker total) and the same per-call ceiling, so the verdict generalizes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — distinct call site (native-pair direct helpers vs.
fail 003's SAC-transfer dispatched-host-function path), but the per-call
removable surface is identical, and the call-site call count and
per-call cost ceiling are bounded by the same arithmetic.

### Why It Failed

The redundant work being targeted is the same per-call structure as fail
003: one `Storage::get` on the instance entry whose only product is the
`executable` field. The metering-preserving recoverable saving is
sub-µs/call.

- 140,000 native pair swaps × ≤5 µs/call removable ≈ 700 ms aggregate
  worker CPU across the whole 70-ledger benchmark.
- After 8-way cluster parallelism normalization: ≈ 87.5 ms wall-clock
  total saved over the benchmark.
- Spread over 70 ledgers: ≈ 1.25 ms/ledger.
- Against the 218 ms soroswap baseline: ≈ 0.57%.

This is below the 1% Low floor and far below the 3% Medium severity
threshold required by the optimize-soroswap objective. The
metering-preserving variant cuts this further (to the bare physical
lookup, sub-µs per call), pushing the saving toward 0.1%. The
metering-changing variant requires a protocol-27 gate, but is bounded by
Meta-Pattern #16 (post-VisitObject/ValSer coalescing, residual
`BudgetImpl::charge` self-time is sub-2% and structurally cannot clear
3% by per-call elimination alone).

### Lesson Learned

The redundant `retrieve_contract_instance_from_storage` inside
`extend_contract_code_ttl_from_contract_id` recurs at multiple call sites
(SAC transfer host function via dispatch, native pair swap via direct
helper). Each call-site contributes a bounded sub-Low slice; even
aggregated across the SAC-transfer call site (fail 003) and the
native-pair call site (this fail), total removable wall-time per ledger
is well under the 1% Low floor after 8-way parallelism normalization. Do
not re-propose new variants of "skip the executable-read probe" — the
arithmetic is bounded by `N_calls × probe_µs / NUM_CLUSTERS / N_ledgers`
and no call-site count gets large enough to clear Medium for the
soroswap workload.
