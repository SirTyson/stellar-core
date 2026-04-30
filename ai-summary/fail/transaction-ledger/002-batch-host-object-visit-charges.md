# H002: Batch host-object visit charges during recursive Val/ScVal conversions

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host object conversion
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing per-object metering and object-table borrow overhead in hot contracttype conversions
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Recursive conversions between host `Val` objects and typed Rust / XDR values should charge the same deterministic `ContractCostType::VisitObject` budget totals they charge today, but they should not re-enter `Host::visit_obj_untyped`, borrow the host object table, update the budget tracker, and emit a Tracy `visit host object` span for every nested object leaf when the whole conversion is already walking a known immutable object graph. For soroswap, generated contracttype conversions and generic storage/event conversions should produce identical values, errors, and budget totals with fewer repeated metering calls.

## Mechanism

`Host::visit_obj_untyped` (`src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-489`) charges `VisitObject`, borrows the host object table, decodes the object handle, and invokes a closure on every object visit. Recursive conversion code such as `Host::from_host_obj` (`src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-485`) calls this for maps, vectors, and nested objects, while generated `#[contracttype]` implementations build and unpack maps/vectors through `map_new_from_slices`, `map_unpack_to_slice`, and `Vec::try_from_val` (`src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:48-80,171-203`). This creates a high-frequency fixed overhead independent of the useful conversion work.

A conversion-local visitor can first charge the exact number of `VisitObject` events it will perform, or accumulate a counter and flush exact repeated-single charges at conversion boundaries, then walk the object graph while holding a single immutable object-table borrow and using unchecked/internal object access for handles it has already validated. This is analogous to the reviewed `ValSer` batching hypothesis but targets `VisitObject` and object-table lookup overhead rather than XDR write chunks. It should complement, not duplicate, the SAC-specific typed balance helpers already under review: those remove one source of object visits, while this reduces the overhead of remaining generic conversions in router, pool, event, storage, and contracttype paths.

## Trigger

Run the current soroswap apply-load trace from `ai-summary/CURRENT_STATE.md`. In the longest `applyLedger` window, `visit host object` (`soroban-env-host/src/host_object.rs:468`) occurs **1,226,322** times for **1,074.468 ms** of worker time. Grouped by worker, the critical worker thread 4132 alone spends **212.653 ms** over 249,762 visits, while other workers spend ~119-126 ms. The trigger is any soroswap swap that converts generated contracttype values or storage/event payloads through host objects during `Host::invoke_function` and SAC/router/pool subcalls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-489` - `visit_obj_untyped` charges and borrows per object visit.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443` - `to_host_val` enters recursive `ScVal` -> `Val` conversion.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-485` - `from_host_obj` recursively visits host vectors/maps and converts nested values back to `ScVal`.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:48-80` - generated struct contracttype conversions unpack/pack host maps.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:171-203` - generated enum contracttype conversions unpack/pack host vectors.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-97` - SAC balance helpers are one hot caller family that currently routes through generated host-object conversions.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2242,2292-2318` - generic contract-data reads/writes reconstruct keys and values through host-object conversion paths.

## Evidence

- Tracy scope check: the cited `visit host object` events occur inside the longest `applyLedger` window and share the same worker threads as `InvokeHostFunctionOpFrame doParallelApply`, `Host::invoke_function`, and `SAC transfer`, so they are descendants of the measured parallel apply path rather than TX-set construction.
- `visit_obj_untyped` performs budget charging and object-table borrowing per visit; the comment at `host_object.rs:469-474` explicitly says each visit is small but ubiquitous, matching the trace's high call count.
- Generated contracttype code repeatedly converts maps/vectors for SAC balance keys/values and other Soroswap contract arguments. This path remains hot even after SAC-specific duplicate-read or typed-balance hypotheses, because user Wasm router/pool calls and event/storage materialization still use generic host-object conversions.
- The critical worker's `visit host object` time is ~213 ms. A batched visitor that removes even 20% of per-visit fixed overhead on that worker would save ~40 ms of apply critical-path time, enough for Medium severity on the 596 ms soroswap median.
- Determinism does not require one budget-tracker update per object handle. It requires the same total budget consumption, same object validation, same conversion result, and same error behavior. Exact repeated-single charging or chunked charging before each bounded traversal can preserve those properties.

## Anti-Evidence

- Some `visit host object` time is useful work in conversion closures, not just budget/object-table overhead. The PoC needs narrower spans or counters to isolate the removable fixed overhead.
- Budget errors are observable. A fully deferred charge could change the point at which an out-of-budget error is raised relative to a conversion error; the safer design is chunked exact charging before each bounded traversal segment or an internal visitor that preserves current error precedence.
- Holding the object table borrow across recursive conversion must not conflict with conversions that allocate new host objects or otherwise require mutable object access. The first safe target is read-only `Val` -> typed / `Val` -> `ScVal` traversal, not object-producing conversions.
- The reviewed SAC typed-balance and duplicate-read hypotheses may remove part of the same trace family. This hypothesis must show additional wins after those narrower changes or focus on non-SAC generic conversions under router/pool/event paths.
- Tracy instrumentation inflates every per-visit span in Tracy-enabled builds. Repeated non-Tracy benchmark runs must show that reducing budget bookkeeping and borrow overhead moves top-line apply time, not just profiler self-time.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated

### Trace Summary

The soroswap apply path reaches this code through `InvokeHostFunctionOpFrame::doParallelApply`, which constructs the Rust host invocation and calls `Host::invoke_function` from `e2e_invoke`. `Host::invoke_function` converts invocation arguments to host `Val`s before VM/SAC execution and converts the returned `Val` back to `ScVal`; storage host functions also reconstruct contract-data ledger keys via `storage_key_from_val`, which routes through `from_host_val_for_storage`. Those `Val` -> `ScVal` and generated contracttype conversions repeatedly call `visit_obj_untyped`, so the claimed per-object budget charge, object-table borrow, and Tracy span are on the measured closeLedger/parallel-apply path.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1358-1377` - parallel apply invokes `rust_bridge::invoke_host_function` inside `InvokeHostFunctionOpFrame doParallelApply`, so the Rust host work is part of the apply critical path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-481` - constructs `Host` with enforcing storage and budget, decodes inputs, then calls `Host::invoke_function` under the `Host::invoke_function` span.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` - `InvokeContract` converts XDR args through `scvals_to_val_vec`, calls the contract, then externalizes the return value with `from_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-166,407-443,463-540` - storage-key and return-value conversion enter `ScVal::try_from_val`; each object reaches `from_host_obj`, which immediately calls `visit_obj_untyped` and recurses through vectors/maps.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:266-288` - host maps are converted by iterating keys/values and recursively converting each `Val`, causing nested object visits for map entries.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-505` - every object visit opens a Tracy span, charges `VisitObject`, borrows the object table, validates the absolute handle, and then calls the closure.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,1295-1325` - single charges update tracker state and check CPU/memory limits each time; `bulk_charge` already exists and preserves total iterations/cost for identical constant-cost visits.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:48-80,171-203` - generated `#[contracttype]` conversions unpack maps/vectors and then convert each field, so SAC and contract storage values route through this object-visit machinery.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-97,121-125,175-180` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/storage_types.rs:23-35` - SAC balance reads/writes convert `DataKey::Balance` and `BalanceValue` via generated contracttype implementations.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1018-1083,1096-1113,2211-2242,2292-2318` - slice-based map/vector unpack helpers and contract-data host functions use `visit_obj` and `storage_key_from_val`, confirming generic storage and contracttype paths are affected.

### Findings

The inefficiency exists. `visit_obj_untyped` performs a full budget charge and object-table `RefCell` borrow for every object node, and recursive conversion paths immediately re-enter it for every nested vector, map, address, symbol, bytes, and large integer object. The budget layer has `Budget::bulk_charge`, which evaluates identical constant-cost charges in one call while preserving the `CostTracker.iterations`, CPU, and memory totals; therefore the metered totals can be kept deterministic.

The path is hot for the objective. The traced entry is inside parallel Soroban `closeLedger`, not transaction-set construction, and SAC balance/storage helpers plus generated contracttype conversions are exercised by soroswap swaps. The aggregate `visit host object` count is large enough that even a partial reduction in budget-call and object-table-borrow overhead can plausibly clear the 3% Medium floor, provided the PoC focuses on the conversion-heavy subset and measures non-Tracy apply time.

The safe implementation scope is narrower than "change all visits globally". Object-producing `ScVal` -> `Val` conversion (`to_host_val` / `to_host_obj`) allocates host objects and should not hold a long immutable object-table borrow. The first viable target is read-only `Val` -> `ScVal` / `Val` -> typed conversion, including storage-key conversion, map/vector externalization, and generated contracttype unpacking. A global change to `visit_obj_untyped` would be risky because many host map/vector/bytes functions mutate or allocate after visiting.

Budget-error ordering is the main correctness constraint. A PoC must not simply precharge an entire unvalidated object graph if that can report budget exhaustion before an error that currently appears earlier, or vice versa. It should either batch only bounded sequences whose handles and traversal order have already been validated, or implement an internal visitor that preserves the existing charge-before-lookup semantics while reducing repeated object-table borrow/span overhead and using `bulk_charge` where the current traversal would perform a contiguous run of identical `VisitObject` charges.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs` (`from_host_val`, `from_host_val_for_storage`, `from_host_obj`, `host_map_to_scmap`, `instance_storage_map_to_scmap`) and supporting helpers in `src/rust/soroban/p26/soroban-env-host/src/host_object.rs` / `budget.rs` if needed. Consider `host.rs:map_unpack_to_slice` and `vec_unpack_to_slice` only after the read-only conversion visitor is correct.
- **Change description**: Add a private read-only conversion visitor that borrows the object table once for a conversion traversal, performs direct absolute-handle lookup for nested objects, and batches `ContractCostType::VisitObject` with `Budget::bulk_charge` only where doing so preserves current validation and error ordering. Do not change object-producing `to_host_obj` first.
- **Correctness check**: Existing conversion, storage, SAC, and budget-metering tests should continue to see identical `VisitObject` tracker iterations and identical CPU/memory budget totals. Add or run focused tests for invalid handles, wrong object tags, muxed-address storage-key rejection, and budget-exceeded precedence if the PoC changes charge timing.
- **Benchmark focus**: Measure `scripts/run_apply_load_matrix.py` soroswap apply time in non-Tracy builds before/after, with additional counters or narrow spans for `from_host_val` / storage-key conversion visit counts. The expected signal is reduced wall time in `Host::invoke_function`/parallel apply and a top-line apply-time improvement in the 3-10% range; if only Tracy span time improves, the finding should not advance.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-29
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:3-5` imports direct object-handle helpers for internal read-only conversion traversal.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:269-311` keeps public map conversion entry points intact while adding private variants that reuse a caller-provided immutable host-object slice for map key/value recursion, including storage-key conversion mode.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-465` changes `from_host_val` and `from_host_val_for_storage` object paths to borrow the object table once for the conversion traversal instead of reacquiring it at every nested object visit.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:499-631` adds private read-only helpers that perform direct absolute-handle lookup against the borrowed object slice and recurse through vectors/maps without nested `visit_obj_untyped` calls. The helper still charges `ContractCostType::VisitObject` before each handle lookup to preserve current budget totals and charge-before-validation ordering.

### Demonstration

The PoC implements the safe subset of the reviewed optimization: read-only `Val` -> `ScVal` conversion now carries one immutable object-table borrow through recursive vector/map traversal. This removes repeated `RefCell` object-table borrows and nested `visit_obj_untyped` closures/Tracy spans from conversion-heavy return, event, storage, and generated contracttype externalization paths while preserving per-object `VisitObject` iterations and error ordering.

### Test Results

Configured and built with Tracy support via `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j $(nproc)`. The full suite passed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make MAKE="make -o ../.git/modules/src/rust/soroban/p21/HEAD -o ../.git/modules/src/rust/soroban/p21/index -o ../.git/modules/src/rust/soroban/p22/HEAD -o ../.git/modules/src/rust/soroban/p22/index -o ../.git/modules/src/rust/soroban/p23/HEAD -o ../.git/modules/src/rust/soroban/p23/index -o ../.git/modules/src/rust/soroban/p24/HEAD -o ../.git/modules/src/rust/soroban/p24/index -o ../.git/modules/src/rust/soroban/p25/HEAD -o ../.git/modules/src/rust/soroban/p25/index -o ../.git/modules/src/rust/soroban/p26/HEAD -o ../.git/modules/src/rust/soroban/p26/index" -j $(nproc) check`; the `-o` options were required only because this git worktree stores submodule gitdirs under the common worktree gitdir rather than `.git/modules/...`, while the make recipe still generated each `target/git-state.txt` from `git` state.

---

## Final Review — Needs Revision

**Date**: 2026-04-30
**Final review by**: gpt-5.5, high

### What Needs Fixing

The final-review handoff is not reproducible. The outer PoC marker exists on `soroswap-perf` as `1edfb4b4d` and records the p26 gitlink at `e6728024aed9bb39cac3c2f247579bfac5b8bc79`, but the actual PoC source change is still an uncommitted submodule diff in `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs` on top of detached p26 `e6728024`. There is no local p26 `poc/002-batch-host-object-visit-charges` branch or committed submodule SHA containing this conversion change, so a fresh checkout of the recorded outer branch would not contain the optimization.

The committed `ai-summary/CURRENT_STATE.md` on `soroswap-perf` also still describes the previous baseline as p26 working-tree edits on upstream `b351f88a`, rather than the committed p26 baseline SHA `e6728024` and fork branch required by the final-review handoff model. This violates the supplement's pre-measurement requirements, so I did not run the full build/test/benchmark workflow.

### Revision Instructions

Commit the `src/rust/soroban/p26` change on a p26 submodule branch named `poc/002-batch-host-object-visit-charges` in the `SirTyson/rs-soroban-env` fork, push that branch, and update the outer PoC branch to point its `src/rust/soroban/p26` gitlink at the new committed SHA. The outer branch should also contain the PoC file move/update and should leave both the outer worktree and p26 submodule worktree clean after `git submodule update --init --recursive src/rust/soroban/p26`.

Update `ai-summary/CURRENT_STATE.md` before resubmission so the accepted baseline is reproducible: record the full p26 baseline SHA (`e6728024aed9bb39cac3c2f247579bfac5b8bc79` if that remains the prior accepted state), the p26 fork branch URL that contains it, the outer baseline commit, and the existing three baseline artifact paths. Then rerun the PoC verification from a clean checkout and append the resulting test/benchmark notes.

### Checks Passed So Far

- Hypothesis and PoC file were read from `ai-summary/poc/transaction-ledger/002-batch-host-object-visit-charges.md`.
- The source diff was traced to the intended p26 conversion path (`host/conversion.rs`) and appears directionally aligned with the reviewed safe subset.
- Handoff validation found a blocking reproducibility failure before build/test/benchmark: uncommitted p26 source changes and stale baseline metadata.

---

## PoC Attempt (revision)

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: claude-opus-4.7, high

### Revision Summary

The prior PoC iteration left the source change as an uncommitted submodule
diff in `src/rust/soroban/p26`, so the recorded outer gitlink did not
contain the optimization and a fresh checkout would not reproduce the PoC.
This revision commits the source change as a real submodule commit and
updates `ai-summary/CURRENT_STATE.md` to record the now-committed baseline,
addressing the Final Review — Needs Revision items.

### Changes Made

- `src/rust/soroban/p26` submodule: committed the conversion-traversal
  visitor change as `3af0b5a5fce5cf3d314a4c65c9db0d085ed782c1` ("viable poc
  002-batch-host-object-visit-charges") on the SirTyson/rs-soroban-env fork
  branch
  [`poc/002-batch-host-object-visit-charges`](https://github.com/SirTyson/rs-soroban-env/tree/poc/002-batch-host-object-visit-charges).
  Code change is identical to the prior iteration and is contained entirely
  within `soroban-env-host/src/host/conversion.rs`.
- Outer worktree branch `poc/002-batch-host-object-visit-charges`: bumped
  the `src/rust/soroban/p26` gitlink from `e6728024` to `3af0b5a5` so the
  outer commit reproducibly references the committed PoC source.
- `ai-summary/CURRENT_STATE.md`: rewrote the `## Commit` section to record
  the accepted baseline as committed p26 SHA `e6728024` plus its fork
  branch URL, and to give the exact commands to reproduce the baseline
  from a clean checkout, replacing the prior "uncommitted working-tree
  edits" description that the supplement flags as a workflow bug.

### Demonstration

After this revision, `git submodule update --init --recursive
src/rust/soroban/p26` against the outer PoC commit checks out
`3af0b5a5`, which contains the read-only `Val` -> `ScVal` conversion
visitor that borrows the host-object table once per traversal and routes
nested vector/map handles through direct absolute-handle lookups while
still charging `ContractCostType::VisitObject` before each lookup. Both
the outer worktree (modulo the orchestrator's `ai-summary/` shared symlink)
and the p26 submodule worktree are clean after the recursive submodule
update.

### Test Results

Built with `./configure --enable-ccache --enable-sdfprefs --enable-tracy
--enable-tracy-capture --disable-postgres` and `make -j $(nproc)`, then
ran the full unit-test suite via `env NUM_PARTITIONS=30
STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots'
make check` from a clean build of the now-committed gitlink. The suite
ran to completion with zero failing tests, matching the prior iteration's
green run on the same source diff (now that diff is reachable via the
recorded gitlink rather than via a working-tree edit).

---

## Final Review

**Verdict**: REJECTED
**Date**: 2026-04-30
**Final review by**: gpt-5.5, high
**Failed At**: final-review

### Adversarial Analysis

1. **Does the change actually address the claimed inefficiency?** YES. The p26 commit `3af0b5a5fce5cf3d314a4c65c9db0d085ed782c1` changes only `soroban-env-host/src/host/conversion.rs` and carries one immutable host-object slice through recursive read-only `Val` -> `ScVal` conversion, replacing nested `visit_obj_untyped` object-table borrows in the targeted path while preserving per-object `VisitObject` charging.
2. **Are the preconditions realistic?** YES. The modified conversion path is exercised by Soroban storage/key/value externalization and contract return/event conversion during `InvokeHostFunctionOpFrame::doParallelApply`, which is inside the measured closeLedger apply path for soroswap.
3. **Is the original code inefficient or working as designed?** INEFFICIENCY. The per-nested-object borrow/closure overhead is removable in read-only conversion without changing deterministic budget totals. The final review did not find evidence that the repeated borrow itself was required for correctness.
4. **Does the benchmark improvement match the claimed severity?** NO. Independent non-Tracy apply-load runs showed no eligible improvement. Accepted baseline soroswap medians were `290.766289 / 286.738946 / 288.663084 ms` (average `288.722773 ms`); optimized medians were `304.220270 / 288.316975 / 287.212452 ms` (average `293.249899 ms`), a `+1.568%` regression. Max-sac medians regressed from baseline `333.099159 / 314.378531 / 316.290692 ms` (average `321.256127 ms`) to optimized `364.823694 / 344.357855 / 315.108117 ms` (average `341.429889 ms`), a `+6.280%` regression.
5. **Is the optimization in scope?** YES. The source change is in Soroban host conversion code reached from parallel Soroban apply, not transaction-set construction, consensus, overlay, or background bucket merge work.
6. **Is the benchmark methodology correct?** YES. Final review used the required optimized build and ran `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` exactly three times without `--tracy`, comparing against `ai-summary/CURRENT_STATE.md`. The full suite also passed before benchmarking with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`.
7. **Can the improvement be explained without the optimization?** YES. The only favorable soroswap data points are sub-1% and within normal run-to-run variation, while the three-run average regressed and the first run was substantially slower. There is no reproducible positive signal to attribute to the code change.
8. **Is this optimization novel?** NOVEL. No duplicate prior accepted finding was identified during final review.

### Rejection Reason

The optimization is reproducible and tests pass, but the required independent non-Tracy benchmark runs do not demonstrate a soroswap apply-time improvement. Soroswap regressed on average by `1.568%`, and max-sac regressed by `6.280%`, which fails the objective's CONFIRMED criteria and exceeds the allowed tradeoff envelope.

### Failed Checks

- Performance final-review verdict criteria: soroswap apply time did not improve consistently across the three non-Tracy runs.
- Soroswap-vs-max-sac tradeoff: max-sac regressed by `6.280%`, outside the allowed under-5% envelope, while soroswap did not provide an offsetting win.
- Adversarial check 4: benchmark improvement did not match any accepted severity tier.
- Adversarial check 7: any isolated favorable datapoint is explainable as benchmark noise rather than a reproducible optimization effect.
