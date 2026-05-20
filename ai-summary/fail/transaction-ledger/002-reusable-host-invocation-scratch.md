# H002: Reuse per-worker non-metered Host invocation scratch across Soroban cluster transactions

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Soroban host invocation setup
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing repeated per-transaction Host setup allocations without sharing protocol-visible contract state
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Parallel Soroban apply must execute each transaction with a fresh `Host` state from a consensus perspective: fresh budget counters, storage map, auth entries, objects, events, call frames, PRNG seed, and module-cache reference. However, worker threads should be able to reuse non-metered scratch capacity for transient containers between transactions in the same cluster, as long as no `Val`, object handle, storage entry, event, budget count, diagnostic event, or rollback state survives across transaction boundaries.

## Mechanism

`e2e_invoke::invoke_host_function` constructs a new Rust `HostImpl` and several fresh transient vectors/maps for every Soroban transaction. `LedgerManagerImpl::applyThread` then repeats this thousands of times per apply run on stable worker threads that process one cluster sequentially. A per-worker scratch object, owned by `ThreadParallelApplyLedgerState` or the Rust bridge worker call path, could provide reusable capacity for non-metered buffers such as diagnostic event vectors, auth-entry decode buffers, host object/context/event backing vectors, and small C++/Rust bridge staging buffers, while resetting all logical state before each invocation. This differs from failed decoded-value/cache proposals because it does not reuse metered decoded ledger values or host objects; it only reuses allocation capacity.

## Trigger

Run the current soroswap apply-load Tracy benchmark from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.
Each cluster worker runs many Soroban transactions sequentially through `LedgerManagerImpl::applyThread`, and every transaction constructs a fresh host invocation in `e2e_invoke::invoke_host_function`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` processes all transactions in a cluster sequentially on the same worker thread, providing a natural owner for per-worker scratch capacity.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — `invoke_host_function` decodes inputs, builds storage, constructs `Host::with_storage_and_budget`, installs auth/ledger/module state, invokes the function, extracts events, and drops the host on every transaction.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:351-375` — `Host::with_storage_and_budget` allocates a fresh `HostImpl` with default object, context, event, auth, diagnostic, and PRNG containers.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ builds fresh bridge buffers for auth entries, host function, resources, source account, and PRNG seed before crossing to Rust.
- `src/rust/src/soroban_proto_any.rs:391-430` — the Rust bridge creates per-invocation budget/diagnostic containers and calls the protocol-specific host invocation.

## Evidence

- Current trace self-time inside `applyLedger` includes `invoke_host_function,soroban-env-host/src/e2e_invoke.rs:488` at **741,215,306 ns self-time** over **6,776** calls and `invoke_host_function_or_maybe_panic,src/rust/src/soroban_proto_any.rs:408` at **48,789,841 ns self-time** over the same call count.
- The worker loop is cluster-local and deterministic: `applyThread` processes a cluster sequentially, and cross-cluster parallelism is already bounded by the configured stage clusters. Reusing scratch capacity per worker would not increase parallelism beyond `NUM_CLUSTERS` and would not reorder ledger effects.
- The trace still shows high-frequency transient construction around host invocation after accepted map/SAC/storage optimizations: `new vec` **68,740,744 ns self-time**, `add host object` **270,971,092 ns self-time** (Tracy-visible, useful as an allocation-frequency proxy), `push context` **107,863,542 ns self-time**, and `contract_event` **55,969,657 ns self-time**. A scratch design that reduces allocator churn across all of these per-invocation containers may reach Medium where single-container capacity hints did not.
- This is not the failed `preallocate-host-objects-vec-capacity` hypothesis: that proposed one local capacity hint for `Host::objects`; this proposes a worker-owned scratch reset protocol spanning multiple non-metered host/bridge containers while explicitly forbidding reuse of metered decoded values.

## Anti-Evidence

- Some Tracy zones in this area include profiler-only overhead, so a PoC must measure non-Tracy apply time and use allocator counters or narrow spans to prove real allocation reduction.
- `Host::try_finish` currently consumes a unique `Host` and returns finalized storage/events. Reusing scratch requires a careful reset API that cannot leave stale object handles, events, auth frames, PRNG state, diagnostic settings, or module-cache references visible to the next transaction.
- The design must avoid reusing metered decoded ledger entries, host `Val`s, storage maps, or instance storage, because prior decoded-cache proposals failed on protocol-visible budget semantics. Only allocation capacity for logically empty containers should survive.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — this is broader than the prior single-`Host::objects` capacity hint, but it re-aggregates several previously documented sub-threshold allocation/capacity slices
**Failed At**: reviewer

### Trace Summary

The close-ledger path runs Soroban cluster transactions through `LedgerManagerImpl::applyThread`, which calls `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, and then `InvokeHostFunctionApplyHelper::invokeHostFunction` for each transaction. That helper builds fresh C++ `CxxBuf` inputs, crosses the Rust bridge, constructs a fresh `Budget`, empty diagnostic vector, enforcing storage maps, and `Host::with_storage_and_budget`, invokes the host function, consumes `Host::try_finish`, encodes events/ledger changes, and returns XDR buffers to C++ for result/meta processing. The path is hot, but the proposed reusable scratch only addresses allocator capacity around host/bridge containers; it does not remove metered XDR decoding, storage-map construction, storage snapshot cloning, contract execution, ledger-change serialization, event encoding, or C++ result processing.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — worker threads process a cluster sequentially, so per-worker ownership is possible, but each transaction still creates a fresh tx sub-seed and calls `parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:280-340,557-585,982-1017,1358-1377` — each parallel apply constructs a helper, reserves per-op ledger/TTL buffers, serializes inputs through `toCxxBuf`, invokes Rust, then records storage changes, events, fees, and result metadata.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` allocates a new `std::vector<uint8_t>` from `xdr::xdr_to_opaque`; reusable vector capacity would not remove the serialization work, and prior records cap broader CxxBuf precompute savings below Medium.
- `src/rust/src/bridge.rs:193-208` and `src/rust/src/soroban_invoke.rs:7-38` — the CXX bridge API accepts fresh input buffers and dispatches to the protocol-specific host module without any worker-scratch parameter.
- `src/rust/src/soroban_proto_any.rs:391-491` — every invocation builds a new `Budget`, empty `diagnostic_events` vector, trace hook option, calls p26 `invoke_host_function`, then reads budget counters and encodes diagnostics.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-508,892-900,1055-1065` — setup decodes resources, builds restored keys/footprint/storage/TTL maps, clones the initial storage map for change detection, constructs the host, decodes auth/host function/source account, invokes, extracts diagnostics only if enabled, encodes the result/events, and computes ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:91-114,351-375,526-552,747-757` — `HostImpl` owns `objects`, `storage`, `context_stack`, `events`, auth manager, ledger/source/PRNG state, and `try_finish` requires a unique `Host` and unwraps/destroys the `HostImpl`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-457` — `add_host_object` has a Tracy span and pushes into `objects`, but the visible span itself is profiler-only and the actual vector growth opportunity was previously rejected as far below Medium.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204,210-229` — context push/pop includes mandatory auth-frame setup, rollback-point storage map clone, event rollback index, metered charge, and frame stack mutation; retaining only Vec capacity cannot remove most of this work.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:175-190,211-248` and `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:250-263` — event recording/externalization must still charge deterministically and convert internal events to XDR-facing events; capacity reuse only avoids occasional backing allocation.
- `ai-summary/fail/transaction-ledger/summary.md:18,21,23,25-26,55,61,71,75,119-123,131` — prior records cap CxxBuf precompute, temporary object-builder fusion, disabled-meta construction, VM/frame buffer inlining, lazy frame snapshots, cluster batching, `Host::objects` preallocation, host-object traversal, and combined frame/argument redesigns below the objective's 3% Medium floor after critical-path normalization.

### Why It Failed

The inefficiency exists only as a collection of small allocation/capacity opportunities, not as a Medium-sized removable phase. The dominant work in the traced path is still required per transaction: budget construction from ledger cost models, metered XDR decode/encode, enforcing storage-map setup and initial map clone, auth and host-function decode, contract execution, event externalization, ledger-change extraction, C++ result decoding, and fee/meta accounting. Reusing empty backing capacity would not remove those operations, and for metered host containers the protocol-visible `charge_heap_alloc` / `charge_bulk_init_cpy` calls must remain even if the allocator reuses memory.

The cited evidence overstates production impact. `add host object` is a Tracy span inside `add_host_object`, and the transaction-ledger fail summary already records that targeting this self-time as allocator work is invalid; the actual amortized `Vec` reallocation cost is structurally tiny. `push context` includes required auth rollback snapshots and storage-map cloning, not just stack-vector allocation, and prior lazy-snapshot review found even the whole scope below Medium before subtracting mandatory work. C++ bridge staging is also already bounded: a broader `CxxBuf` precompute proposal capped at about 2.5%, while this scratch design would save only allocator capacity and not the XDR serialization itself.

The proposed resettable Host/scratch design is also invasive relative to the available gain. `Host::try_finish` currently enforces uniqueness and destroys the `HostImpl`, which is a simple isolation boundary for object handles, events, frames, auth manager, ledger/source account, PRNGs, storage, diagnostics, trace hooks, and module-cache references. A safe reset API could theoretically clear all logical state while retaining capacity, but the maximum credible saving is still below the optimize-soroswap Medium threshold, so it should not proceed to PoC under this objective.

### Lesson Learned

Per-worker scratch is only worth pursuing if it removes a measured Medium-sized operation, not merely if the worker loop is sequential and allocation-heavy in aggregate Tracy output. For Soroban host invocation, capacity-only reuse must be sized after cluster normalization and after subtracting profiler-only spans, deterministic metering, XDR work, storage-map work, contract execution, and event/ledger-change serialization; the remaining allocator churn is a Low-or-smaller optimization and is rejected by this objective.
