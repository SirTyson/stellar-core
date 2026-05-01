# H001: Replace eager per-frame storage-map rollback clones with a lazy storage undo log

**Date**: 2026-05-01
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing full `StorageMap` physical clones from successful Soroban/SAC frames while preserving deterministic rollback and existing metering
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Soroban host frame must remain rollback-safe: if the frame fails, durable storage, events, authorization state, and instance-storage persistence must be restored exactly as they are today; if the frame succeeds, its writes must persist exactly as today. The host should still charge the same protocol-visible storage rollback metering at frame entry, but successful frames should not physically clone the whole durable `StorageMap` only to discard that clone on `pop_context(None)`.

## Mechanism

`Host::push_context` eagerly constructs every `RollbackPoint` with `storage: self.try_borrow_storage()?.map.metered_clone(self)?`, even though `with_frame` passes that rollback point to `pop_context` only on error and discards it on the common success path. In the current soroswap trace, `push context` is inside `applyLedger` for 40,716 of 40,872 events, with 73,349,688 ns self-time in aggregate export and 385,694,640 ns total in-apply execution time in unwrap export. A lazy storage undo log or overlay could keep a frame marker at push time, record old values only when `Storage::put` / `del` / TTL extension / instance persistence actually mutates durable storage, and replay the same metered clone charges without doing the physical full-map clone on frames that succeed or only read storage.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and export self-time with `csvexport-release -e`. Soroswap repeatedly enters nested Wasm and Stellar Asset Contract frames under `applyLedger`; each frame goes through `Host::with_frame` -> `push_context` before any frame body executes, and most successful frames later call `pop_context(None)`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-205` — `push_context` eagerly clones `StorageMap` into every rollback point.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` discards the rollback point on success and only restores it on error.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-389` — durable storage writes that should record before-values in a lazy rollback design.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-515` — TTL extension writes that mutate durable storage and need undo records.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1254-1278` — instance-storage persistence writes back to durable storage and must remain rollback-safe.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:397-407` — current `Vec` clone metering that a budget-preserving implementation must replay.

## Evidence

- Tracy scope check: unwrap export found 70 `applyLedger` windows totaling 5,092,107,609 ns. `push context` had 40,716 of 40,872 events fully inside those windows, totaling 385,694,640 ns of in-apply execution.
- Aggregate self-time export reports `push context` at `soroban-env-host/src/host/frame.rs:191` with 73,349,688 ns self-time over 40,872 calls. This excludes the child `push auth frame` and `snapshot auth` zones, so it is not a duplicate of the existing auth-snapshot hypothesis.
- The source-level inefficiency is direct: `push_context` clones the entire storage map before the frame body runs, while `with_frame` calls `pop_context(None)` on successful frames and never uses that cloned storage.
- This is distinct from prior storage-map failures. `002-in-place-storage-map-mutation` targeted physical rebuilds during map writes; this targets eager frame-entry rollback snapshots, including read-only and successful frames that perform no rollback.
- Determinism can be preserved by retaining chronological undo records and restoring them in reverse frame order; observable storage order remains the existing sorted `MeteredOrdMap` order after replay.

## Anti-Evidence

- Rollback is subtle: failed frames must also roll back events and authorization, and instance-storage persistence may fail after the frame body succeeds. The storage undo design must integrate with the existing `res.is_ok()` / `persist_instance_storage` / `maybe_reload_instance_storage_on_frame_pop` sequencing.
- Exact budget behavior constrains the design. The current eager clone charges heap allocation, shallow copy, and any substructure costs through `MeteredClone`; a PoC should initially replay those charges at frame push even if the physical clone is removed.
- The 73 ms self-time is an upper bound for removable production work. Some `push_context` cost is unavoidable context-stack bookkeeping and event-length capture, and replaying clone metering still does budget work.
- Recording/test modes and trace-observation helpers may depend on precise rollback behavior; a first implementation should either keep eager snapshots there or prove the undo log is observation-equivalent.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — prior soroban-env records cover auth snapshots, storage-map writes/lookups, XDR decode/serialization, budget tracking, and VM/module-cache paths; none duplicate durable-storage rollback snapshot elision
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge, constructs a p26 host with enforcing storage, and invokes `Host::invoke_function`. Top-level host functions, nested Wasm calls, and SAC calls enter `Host::with_frame`, whose `push_context` always clones the current durable `StorageMap` into a `RollbackPoint` before frame work starts. On successful frames, `with_frame` persists modified instance storage if needed and then calls `pop_context(None)`, so the cloned durable-storage rollback snapshot is unused; on errors, `pop_context(Some(rp))` restores that cloned map, events, and auth state.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2484-2511,2623-2670,2673-2710,3028-3029` — Soroban apply stages execute transaction bundles on apply threads, commit successful thread state, and remain inside the close-ledger apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,982-1002,1358-1378` — Soroban operations invoke the Rust host and record only returned storage effects on success.
- `src/rust/src/soroban_proto_any.rs:391-448,475-505` — the Rust bridge builds the budget, calls p26 `invoke_host_function_with_trace_hook_and_module_cache`, and extracts only successful ledger effects.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-485,493-520` — enforcing-mode storage is built, cloned once for final diffing, placed in a fresh `Host`, and finished after `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:40-48,190-205,404-562` — `RollbackPoint` owns a full `StorageMap`; `push_context` fills it with `map.metered_clone`; successful `with_frame` paths pass `None` to `pop_context`, while error paths restore the clone.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-784,923-980,1124-1183` — top-level `InvokeContract`, nested contract calls, Wasm frames, and SAC frames all use `with_frame`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-35,333-389,500-515` — durable storage is a `MeteredOrdMap<Rc<LedgerKey>, Option<EntryWithLiveUntil>, Budget>`; writes, deletes, and TTL extensions mutate `self.map`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1278` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:173-217,509-564` — instance storage is lazily loaded and, if modified, persisted back through durable storage before frame pop; failures in persistence must still roll back.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:49-94,190-255,355-407` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:349-365` — the current snapshot charges shallow map copy, vector heap allocation, shallow element copy, and then performs the physical clone.
- `ai-summary/fail/soroban-env/002-in-place-storage-map-mutation.md:47-80` and `ai-summary/fail/soroban-env/001-sparse-auth-frame-tracking.md:47-87,195-222` — prior records are related but distinct: one rejected storage write in-place mutation as below threshold, and one auth-snapshot PoC failed final benchmarking; neither investigated durable-storage rollback snapshot cloning itself.

### Why It Failed

The inefficiency exists, but the objective accepts only Medium or High findings and this target does not clear that severity floor. The hypothesis's own isolated self-time for `push context` is 73,349,688 ns across 40,872 calls, while the same evidence reports 5,092,107,609 ns of aggregate `applyLedger` time; even treating the entire `push context` self-time as removable gives only about 1.4% of the aggregate apply envelope. A correct lazy rollback design must still replay the protocol-visible `MeteredClone` charges at frame push, preserve the existing point where budget exhaustion can occur, keep context-stack/event/auth bookkeeping, and add mutation-time undo logging for durable writes, TTL updates, and instance-storage persistence. Those constraints make the physically removable subset smaller than the already-sub-Medium upper bound.

The broader 385,694,640 ns `push context` total is not a valid storage-snapshot savings estimate because it includes child work such as auth frame push/snapshot handling; the separate auth-snapshot hypothesis already targeted that child work and failed final non-Tracy benchmarking. This durable-storage snapshot angle is therefore novel but below the optimize-soroswap review threshold.

### Lesson Learned

For frame-entry rollback optimizations, use the dedicated self-time of the specific rollback component, not the parent `push_context` total that includes auth child zones. If exact metering must be preserved, eager snapshot removal can only claim the physical clone/allocation portion after replaying clone charges and subtracting unavoidable frame bookkeeping; here that upper bound is below the 3% Medium floor before those deductions.
