# H002: Success-biased call-frame and argument pipeline for hot Soroswap contract calls

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban VM call frames
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing eager rollback snapshots and repeated argument-vector movement on successful cross-contract calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Successful Soroban cross-contract calls should push frames, enforce reentry/auth rules, pass arguments to Wasm or SAC code, persist instance storage, pop frames, and return values with the same observable ledger effects, auth tree, events, diagnostics, budget accounting, and errors as today. If a frame fails at any point, all storage, event, auth, and context-stack changes made after frame entry must still roll back exactly as they do today. Worker scheduling must not affect rollback behavior or output order.

## Mechanism

The current `with_frame` path eagerly prepares rollback state and copies arguments before knowing whether the frame will fail. `push_context` always calls `AuthorizationManager::push_frame`, snapshots auth, and clones the storage map into a `RollbackPoint`; `call_contract_fn` copies call arguments into an owned `args_vec` for the frame; then `Vm::invoke_function_raw` walks the same argument slice again to allocate/marshal a separate `Vec<wasmi::Value>`. In the soroswap benchmark, the hot path is overwhelmingly successful router/pair/SAC calls, so a success-biased frame pipeline can lazily materialize rollback state only when a fallible mutation first occurs, and can carry one owned/borrowed `CallArgs` object through frame construction and VM marshalling instead of repeatedly cloning small vectors.

This is broader than the previously rejected standalone lazy-snapshot and auth-snapshot micro-hypotheses. Those individual slices were below threshold; this hypothesis combines the frame rollback point, auth snapshot, call-stack frame setup, argument cloning, relative-object translation, and VM argument marshalling into one call-frame redesign.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark from `ai-summary/CURRENT_STATE.md`. The trigger is a successful router swap transaction that enters `InvokeHostFunctionOpFrame::doParallelApply`, calls the router Wasm, performs repeated pair/token/SAC cross-contract calls, and exits frames successfully.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-205` — `push_context` eagerly pushes auth frame state, snapshots authorization, clones the storage map, records event length, and pushes the `Context`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` always builds a rollback point before running the frame, then rolls back only on error.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1190` — `AuthorizationManager::snapshot` clones account tracker state for rollback.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `AuthorizationManager::push_frame` constructs a contract invocation frame, pushes tracker state, and snapshots auth for every contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` charges and copies `args` into `args_vec` before dispatching to Wasm or SAC.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` allocates/marshals a second `Vec<wasmi::Value>` from the same call arguments.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:412-440` — `absolute_to_relative` pushes objects into the frame-local relative-object table during VM argument marshalling.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2567-2601` — the generated `call` host function copies a `VecObject` to `Vec<Val>` through `call_args_from_obj` before entering `call_n_internal`.

## Evidence

- Tracy self-time in the current soroswap trace shows several small-to-medium frame/call setup zones that are individually borderline but additive: `call,soroban-env-host/src/vm/dispatch.rs:304` at **632,325,205 ns self-time**, `Vm::invoke_function_raw,soroban-env-host/src/vm.rs:400` at **517,251,229 ns self-time**, `snapshot auth,soroban-env-host/src/auth.rs:1170` at **119,848,449 ns self-time**, `push auth frame,soroban-env-host/src/auth.rs:1345` at **82,108,514 ns self-time**, and `push context,soroban-env-host/src/host/frame.rs:191` at **73,349,688 ns self-time**.
- Timestamp filtering confirms these zones are in the measured close-ledger subtree: `call` has **30,432** events inside `applyLedger` (out of 30,534 total), `Vm::invoke_function_raw` has **15,229** events inside `applyLedger`, `push auth frame` and `snapshot auth` each have **40,716** events inside `applyLedger`, and `SAC transfer` has **10,140** events inside `applyLedger`.
- The source has repeated work across each call boundary: `call` converts a `HostVec` to `Vec<Val>`, `call_contract_fn` copies `args` again into `args_vec`, and `Vm::invoke_function_raw` allocates/marshals yet another vector. Separately, `push_context` constructs rollback material even though `with_frame` discards it on the common successful path.
- Combined aggregate self-time across the named setup/call-frame zones is over **1.4 s** in the current trace. Normalized by eight clusters, that is roughly **175 ms** over the trace's apply windows, enough to plausibly exceed the Medium threshold if a redesign removes a meaningful fraction rather than only one micro-slice.

## Anti-Evidence

- Rollback correctness is consensus-critical. Lazy rollback must still handle errors after partial storage writes, event emission, auth tracker mutations, instance-storage persistence, lifecycle hooks, and return-value validation. A delta-log design may be safer than simply postponing snapshots.
- Some argument copying is protocol-visible through memory-copy charges. A PoC must preserve equivalent charges or protocol-gate the new cheaper path with budget expectation updates.
- The `call` and `Vm::invoke_function_raw` self-time zones include mandatory VM/host boundary work that cannot all be removed. Narrow counters are needed to isolate argument-vector copying, `absolute_to_relative` table pushes, and rollback snapshot construction from required dispatch, fuel, and error-handling work.
- This must not alter `try_call`, reentrant `SelfAllowed` behavior, top-level `HostFunction` frames, test-only native frames, diagnostic lifecycle hooks, or auth recording/testutils behavior. The initial implementation should target production enforcing-mode successful contract frames only, with an explicit fallback to the current eager path for uncommon or hard-to-prove cases.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as one combined frame/argument-pipeline redesign; prior fail summary records only the standalone lazy rollback snapshot and inline VM/frame argument buffer slices
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban path is real: `InvokeHostFunctionOpFrame::doParallelApply` invokes the p26 host, `HostFunction::InvokeContract` reaches `call_n_internal`, `call_contract_fn` builds a contract frame, and Wasm calls go through `Vm::invoke_function_raw`. The source confirms eager rollback setup in `push_context`/`with_frame`, eager auth snapshotting in `AuthorizationManager::push_frame`, and repeated argument materialization from guest `VecObject` to `Vec<Val>`, then to frame-owned `Vec<Val>`, then to `Vec<wasmi::Value>`. However, the projected Medium impact is not supported after applying the same critical-path normalization used by the objective: the named 1.4 s aggregate self-time is spread across the trace's apply windows and eight parallel clusters, and the actual removable subset is smaller than those broad zones.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — top-level `HostFunction::InvokeContract` runs under `with_frame`, converts invoke arguments to host `Val`s, calls `call_n_internal`, and converts the result back to `ScVal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-984` — `call_n_internal` performs reserved-name and reentry checks before the dispatch path; immediate `SelfAllowed` reentry may persist instance storage before the nested call, which lazy rollback must still handle.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-205` — `push_context` pushes auth frame state, builds a `RollbackPoint` by cloning the storage map, records event length, and pushes the `Context`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` calls `push_context`, runs lifecycle hooks and the frame closure, persists/reloads instance storage on success, calls pop lifecycle hooks, and rolls back only when the result is an error.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:210-229` — `pop_context` restores the storage map, rolls back events, and passes the auth snapshot to `AuthorizationManager::pop_frame` only on error.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1219` — `AuthorizationManager::snapshot` clones enforcing account tracker snapshots and invoker-contract tracker root snapshots.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `push_frame` clones the contract ID for VM/SAC frames, pushes an `AuthStackFrame::Contract`, pushes tracker frames, and returns an auth snapshot.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1376-1425` — `pop_frame` must perform rollback before popping the auth call-stack frame so invoker-contract tracker snapshots remain meaningful.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` — `call_args_from_obj` copies a guest `HostVec` to `Vec<Val>` for generated host `call` and `try_call`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2567-2601` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:2610-2645` — generated `call`/`try_call` both convert the argument object to a `Vec<Val>` before calling `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` charges and copies `args` into the frame-owned `args_vec` before dispatching Wasm or SAC.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` charges allocation, translates each `Val` with `absolute_to_relative`, marshals to `wasmi::Value`, and calls `metered_func_call`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:412-440` — `absolute_to_relative` pushes object references into the current frame's relative-object table; this is required ABI translation for object arguments, not just allocation overhead.
- `ai-summary/fail/transaction-ledger/summary.md:24-26` — prior reviewed slices found in-place storage-map updates, inline VM/frame argument buffers, and lazy frame rollback snapshots below the objective's 3% Medium threshold after cluster-normalized critical-path estimation.
- `ai-summary/CURRENT_STATE.md:39-52` and `ai-summary/CURRENT_STATE.md:60-78` — the current authoritative soroswap baseline averages about 278.74 ms, so Medium requires roughly 8.4 ms per ledger in non-Tracy runs; diagnostic Tracy attribution is useful only for locating work, not for accepting aggregate totals directly.

### Why It Failed

The inefficiencies exist, but the combined impact estimate overstates recoverable apply-time savings. The cited self-time adds broad scopes (`call` dispatch and `Vm::invoke_function_raw`) that include mandatory ABI translation, fuel/dispatch work, return/trap handling, relative-object table updates, lifecycle hooks, auth call-stack bookkeeping, context stack pushes/pops, and budget-visible copy charges. Prior review already found the narrow argument-buffer and lazy-snapshot components below threshold individually; combining them still does not justify Medium because the aggregate 1.4 s worker self-time must be divided by the configured eight clusters and spread across the trace's apply windows, while only a fraction of each broad zone is removable.

A correctness-preserving lazy rollback design would also need mutation journaling across storage, events, authorization trackers, instance-storage persistence/reload, and lifecycle-hook failure paths. That may be architecturally possible, but it would save only the snapshot-copy subset of `push_context`/`push auth frame`, not the mandatory frame/auth setup itself. Under the optimize-soroswap objective's Medium-only threshold, this is therefore NOT_VIABLE rather than a PoC candidate.

### Lesson Learned

Do not aggregate broad Soroban frame and VM self-time zones without separating mandatory ABI/frame/auth work from removable allocation or snapshot work, and always normalize aggregate worker time by cluster count and apply-window count before comparing against the soroswap Medium floor. A viable call-frame redesign would need narrow measurements proving more than about 8.4 ms per ledger of removable work, not just a union of individually sub-threshold micro-slices.
