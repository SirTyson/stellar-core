# H006: Coalesce repeated `extend_current_contract_instance_and_code_ttl` calls per tx and skip the SAC code-extend storage lookup

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host TTL extension on the SAC apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing redundant per-call storage lookups in the SAC TTL bookkeeping path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The SAC built-in calls
`Host::extend_current_contract_instance_and_code_ttl` on every
`transfer`, `transfer_from`, `mint`, `burn`, `approve`, `set_authorized`,
`clawback`, etc. (call sites
`builtin_contracts/stellar_asset_contract/contract.rs` lines 150, 169, 188,
198, 217, 240, 261, 285, 306, 326). Within a single Soroban tx the second
and subsequent calls for the same contract id are functionally idempotent
-- `Storage::extend_ttl` (`storage.rs:570-572`) only calls
`apply_ttl_extension` when `current_ttl <= threshold`, and after the first
call's `apply_ttl_extension` the entry's live-until is already at the same
target. The expected efficient implementation should:

1. Track per-tx which `(contract_id, instance|code)` TTL extensions have
   already been performed at the current `(threshold, extend_to)` pair, and
   short-circuit subsequent calls without re-entering `prepare_extend_ttl`
   (which does a storage.get + decode of the Option) for the same key.
2. When the *current* contract is the built-in `StellarAsset` (the SAC
   itself), skip the code-TTL branch entirely. The SAC has no Wasm code,
   so `extend_contract_code_ttl_from_contract_id` (`data_helper.rs:247`)
   always pays a wasted `retrieve_contract_instance_from_storage` (storage
   get + `extract_contract_instance_from_ledger_entry` decode) only to hit
   the `ContractExecutable::StellarAsset => {}` arm and return.

The visible budget charge totals must remain identical to the current
implementation, so each short-circuited call must apply a budget-equivalent
charge accumulator (the same pattern as H001 batch metered ValSer).

## Mechanism

Today `extend_current_contract_instance_and_code_ttl` (`host.rs:2320-2335`)
unconditionally calls `extend_contract_instance_ttl_from_contract_id` and
`extend_contract_code_ttl_from_contract_id` on every invocation. Each
call walks
`Storage::extend_ttl -> prepare_extend_ttl -> get_with_live_until_ledger`
which performs a `MeteredOrdMap::find` (binary search with charge), a `get`
(charge_access + map deref), and decodes the `Option<(LedgerEntry, Option<u32>)>`
to extract `old_live_until`. For the soroswap workload the same
`(contract_id, threshold, extend_to)` triple repeats many times per tx
(every SAC method called on the same token), and for SAC-typed contracts
the code-TTL branch is *always* a no-op after the storage lookup. From the
soroswap trace this zone family is `extend_current_contract_instance_and_code_ttl`
@ `vmcaller_env.rs:270` totalling 175.5 ms across 6 164 calls (~28.5 us per
call), with a worker self-time tail of 83.1 ms; the underlying `extend key`
zone (`storage.rs:540`) is 120.7 ms across 21 749 calls. A per-tx
`(contract_id, threshold, extend_to) -> already_extended` cache on the
`Host`/frame plus a static SAC short-circuit removes most of the redundant
storage-map work on the soroswap critical path.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, `soroswap, TX=4000, T=8`) and inspect
the longest `applyLedger` window in the existing baseline trace
(`/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`).
Each soroswap swap tx invokes the Wasm pool which calls SAC `transfer` on
two token contracts; each SAC method call hits
`extend_current_contract_instance_and_code_ttl` once. Within a single tx
the second SAC transfer (the credit side) and any allowance/transfer_from
flow re-enter the same function for keys whose live-until is already at
the target value -- the trace shows 6 164 calls vs ~3 000 SAC transfers,
i.e. >1 redundant extend per transfer on average.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2335` --
  `extend_current_contract_instance_and_code_ttl`: add the per-tx
  dedup cache lookup before invoking the inner instance/code helpers,
  and skip the code-TTL helper when the current contract is the
  `StellarAsset` built-in.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-281` --
  `extend_contract_code_ttl_from_contract_id` /
  `extend_contract_instance_ttl_from_contract_id`: accept an optional
  "already extended this tx" hint or expose a fast-path that bypasses
  `retrieve_contract_instance_from_storage` when the executable type is
  statically known (SAC built-in).
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:518-574` --
  `Storage::extend_ttl`: cooperating change, optionally accept a
  precomputed `TtlExtensionInfo` so a coalesced caller can avoid a
  repeat `prepare_extend_ttl` while still applying the equivalent budget
  charge.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs` (Host state) -- add
  a per-tx (cleared at end of `invoke_host_function`) hashmap keyed on
  `(contract_id_hash, threshold, extend_to, kind)`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:217-219`
  (and the eight other `extend_current_contract_instance_and_code_ttl`
  call sites in this file) -- exercise the new fast path; no source
  changes required if the host-side dedup is transparent.

## Evidence

Tracy soroswap baseline (longest `applyLedger` window):

- `extend_current_contract_instance_and_code_ttl,vmcaller_env.rs:270`:
  175.5 ms total / 6 164 calls (the dispatch-side wrapper).
- `extend_current_contract_instance_and_code_ttl,vm/dispatch.rs:304`:
  115.5 ms total / 4 687 calls.
- `extend_current_contract_instance_and_code_ttl,vmcaller_env.rs:270`
  worker self-time: 83.1 ms / 6 164 calls.
- `extend key,storage.rs:540`: 120.7 ms / 21 749 calls (covers all
  `Storage::extend_ttl` invocations including `extend_contract_data_ttl`).
- `storage get,storage.rs:258`: 86.7 ms / 82 208 calls -- the
  `retrieve_contract_instance_from_storage` step routes through this
  zone for every extend_current call, including SAC contracts where the
  result is discarded.
- `SAC transfer,contract.rs:212`: 3 082 invocations (soroswap-trace
  longest applyLedger window per H001 evidence). Each transfer calls
  `extend_current_contract_instance_and_code_ttl` exactly once
  (`contract.rs:217`). 6 164 / 3 082 ~= 2.0 calls per transfer
  on average across the whole trace, so SAC built-ins are the dominant
  caller and most calls do redundant work for the code-TTL branch.

Combining the per-tx dedup (eliminates ~50% of `prepare_extend_ttl`
storage-map lookups on the SAC path) and the SAC short-circuit
(eliminates the code-side `retrieve_contract_instance_from_storage`
on every SAC call) plausibly removes 90-130 ms of worker time on the
soroswap apply window (~=3-4 % of the 4.59 s total `applyLedger` window
captured in the baseline).

## Anti-Evidence

- **Determinism / metering**: the host's budget trail is observable --
  every short-circuited call must charge the same budget dimensions
  (`ChargeBudget`, ValSer, map-access) it would have charged. The fix
  must be implemented as a charge-equivalent fast path, identical in
  spirit to H001's batch ValSer metering. Any deviation in cumulative
  CPU/memory budget will desync nodes.
- **Per-tx state lifetime**: the dedup cache must be reset at the
  *outer* tx boundary (`invoke_host_function` entry/exit), not at each
  `with_frame` boundary, otherwise nested cross-contract calls could
  re-trigger redundant extends when control returns to a higher frame
  that already extended its instance TTL.
- **State observability**: skipping `prepare_extend_ttl` must not
  bypass the
  `if old_live_until < ledger_seq -> "accessing no-longer-live entry"`
  check on the *first* call -- that check is what guards correctness.
  After the first successful extend the entry is provably live, so the
  short-circuit on subsequent identical calls within the same tx is
  safe.
- **SAC short-circuit safety**: the SAC built-in is statically known
  to be `ContractExecutable::StellarAsset`; there is no possibility
  of a SAC contract's instance entry mutating to a Wasm executable
  mid-tx. The check `running_contract_is_sac` can be derived from the
  current frame's contract id type (`ContractIdPreimage::Asset(_)`)
  without any storage access.
- **Future protocol changes**: if a future protocol introduces new
  SAC method side-effects on the contract-code entry, the SAC
  short-circuit would need to be re-validated. The dedup cache is
  protocol-neutral.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS -- this exact TTL coalescing/SAC code-branch hypothesis was not previously investigated; related fail entry `002-lazy-frame-rollback-snapshots.md` records the same parallel-worker-time normalization pitfall for a different mechanism
**Failed At**: reviewer

### Trace Summary

The local inefficiency exists: SAC functions call `extend_current_contract_instance_and_code_ttl`, which unconditionally extends the current instance and then re-reads the contract instance to discover that the SAC has no Wasm code. `Storage::extend_ttl` always enters `prepare_extend_ttl` and `get_with_live_until_ledger`, so repeated same-contract calls within one transaction can pay redundant map lookup and live-until extraction work. However, the trace evidence is aggregate worker-thread time in an 8-cluster parallel soroswap phase, not wall-clock apply critical-path time, so the claimed 3-4% apply-time reduction is overstated. After normalizing by the benchmark's parallelism, even removing the entire cited `extend_current_contract_instance_and_code_ttl` aggregate is below the objective's Medium threshold, and realistic savings are smaller because equivalent budget charges and non-TTL call overhead remain.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:417-425` -- the `T=8` scenario writes `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS = 8`, so the benchmark is explicitly configured for 8 dependent clusters.
- `src/simulation/ApplyLoad.cpp:2653-2682` -- soroswap setup creates exactly one pair per dependent cluster/bin to achieve maximum parallelism.
- `src/simulation/ApplyLoad.cpp:3382-3505` -- swap transactions are generated round-robin across pairs, making the SAC work distributed across the configured clusters rather than concentrated on one worker.
- `src/simulation/ApplyLoad.cpp:2323-2334` -- the benchmark asserts one Soroban apply stage and `max-clusters == APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`, confirming that the measured scenario has the requested parallelism.
- `src/ledger/LedgerManagerImpl.cpp:2484-2520` and `2531-2574` -- each cluster is applied by an async worker and the apply path waits on those futures; worker zone totals must be converted to critical-path wall time.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1000` and `557-585` -- the Soroban operation apply path enters `rust_bridge::invoke_host_function` for each transaction before recording returned storage changes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` -- each host invocation builds a fresh `Host` with enforcing footprint/storage, invokes the host function, and finishes the host at the transaction boundary.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` -- contract calls retrieve the instance from storage once and enter either a Wasm frame or `Frame::StellarAssetContract`; the SAC frame already carries the `ScContractInstance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:148-153`, `169-172`, `188-201`, `217-220`, `240-243`, `261-264`, `285-288`, `306-309`, and `326-329` -- SAC methods call `extend_current_contract_instance_and_code_ttl` with the same threshold/extend amount constants.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2335` -- `extend_current_contract_instance_and_code_ttl` unconditionally calls the instance TTL helper and then the code TTL helper for the current contract.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-264` -- the code TTL helper re-retrieves the contract instance from storage, then does nothing for `ContractExecutable::StellarAsset`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:267-280` -- the instance TTL helper clones the instance key and calls `Storage::extend_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-329`, `433-498`, and `532-573` -- TTL extension performs storage lookup, live-until validation, max-live computation, and conditional update even when a repeated call will not extend anything.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-241` -- storage lookup performs a charged binary search and charged access through `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` and `522-562` -- frame rollback snapshots restore storage on error, which any persistent per-transaction TTL-dedup cache would need to respect.

### Why It Failed

This fails the optimize-soroswap objective's Medium severity floor. The cited 175.5 ms `extend_current_contract_instance_and_code_ttl` time is aggregate worker time across the `T=8` parallel scenario; with the benchmark distributing swaps round-robin across 8 cluster-specific pairs, the critical-path share is roughly 175.5 / 8 = 21.9 ms in the impossible best case that the whole wrapper disappeared. Against the hypothesis's 4.59 s apply window, that is about 0.5%, far below the 3% Medium threshold, and the more relevant removable subset is smaller because the implementation must preserve deterministic budget charges and still perform first-touch live-entry validation.

There is also a correctness constraint missing from the proposed per-tx cache. `with_frame` rolls back storage on failed frames, so a host-level "already extended" entry recorded inside a failed subcall would become stale if the storage extension is reverted but the cache is not reverted with the frame. A future version of this idea would need either a rollback-aware cache snapshot in `RollbackPoint` or a design that only publishes cache entries after successful frame exits, but even a correct version does not have enough projected top-line impact for this objective.

### Lesson Learned

For parallel Soroban apply hypotheses, Tracy worker-thread totals cannot be compared directly with `applyLedger` wall-clock time; normalize by the active cluster count and avoid treating aggregate per-worker savings as critical-path savings. Host-side caches that summarize storage mutations also have to be frame-rollback-aware, because failed contract frames restore storage while the outer transaction may continue.
