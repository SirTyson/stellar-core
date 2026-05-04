# H002: Single-pass linear-memory `Val` import for guest vectors and maps

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / Soroban host VM boundary
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing redundant initialization, copying, and budget-call overhead in VM-to-host value imports
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When guest Wasm passes a slice of raw `Val` payloads to the host, the host should read the linear-memory range once, translate each relative object handle to an absolute host handle, validate each `Val`, and construct the final host vector or map value storage directly. It should not first zero-fill a temporary `Vec<Val>`, then perform a second per-element byte-copy loop with an intermediate `[u8; 8]` buffer, then run a separate integrity-check pass, while also issuing multiple small budget charges for one logical import.

## Mechanism

`vec_new_from_linear_memory` and the value half of `map_new_from_linear_memory` both allocate `vec![Val::VOID; len]`, charge bulk initialization, separately charge conversion/relative-handle work, call `metered_vm_read_vals_from_linear_memory`, and then loop over the populated vector again to check integrity. The helper in `mem_helper.rs` borrows VM memory and copies each 8-byte chunk into a temporary array before converting it, even though the caller ultimately wants a contiguous `Vec<Val>`. A single-purpose `read_vals_from_linear_memory_fast` helper could use one checked memory borrow, construct the destination with spare capacity, translate and validate each element in one pass, and preserve or protocol-gate the equivalent aggregate budget charge, reducing a hot import path used by soroswap router/pair calls without altering deterministic execution order.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) using `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Guest contract calls that create argument vectors or maps from linear memory trigger `vec_new_from_linear_memory` and `map_new_from_linear_memory` inside the parallel Soroban apply workers.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2124-2150` — `vec_new_from_linear_memory` zero-fills a `Vec<Val>`, imports values, then separately checks every value.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1828-1856` — `map_new_from_linear_memory` repeats the same value-import pattern before constructing the `HostMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:153-193` — `metered_vm_read_vals_from_linear_memory` copies each 8-byte chunk through a temporary buffer and invokes a callback per element.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` shows the analogous host-to-VM argument marshaling shape; the proposed fast path is specifically for the opposite VM-to-host linear-memory imports and is not the previously rejected VM-call argument-buffer inlining.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — Soroban cluster workers are joined by the apply path, so worker-local VM import savings shorten `applyLedger` if they reduce the slowest cluster's execution time.

## Evidence

- `csvexport-release -e` reports `vec_new_from_linear_memory,soroban-env-host/src/vm/dispatch.rs:304` at **193,880,255 ns self-time** over **74,744 calls** and `map_new_from_linear_memory,soroban-env-host/src/vm/dispatch.rs:304` at **132,941,341 ns self-time** over **20,275 calls** in the current soroswap trace.
- Timestamp filtering to the seven long `applyLedger` windows confirms these imports are in scope: `vec_new_from_linear_memory` totals **272,802,089 ns** over **74,342 calls** (**38.972 ms aggregate per long window; 4.871 ms after T=8 normalization**) and `map_new_from_linear_memory` totals **252,665,091 ns** over **20,233 calls** (**36.095 ms aggregate per long window; 4.512 ms after T=8 normalization**).
- The same filtered windows show `charge,soroban-env-host/src/budget/dimension.rs:176` at **1,751,809,771 ns** over **20,247,202 calls** (**250.259 ms aggregate per long window; 31.282 ms after T=8 normalization**). The target functions issue several budget charges per logical value import (`charge_bulk_init_cpy`, explicit `MemCpy`, and `metered_vm_read_vals_from_linear_memory`'s `MemCpy`), so charge coalescing can contribute beyond raw copy savings if protocol-gated.
- The optimization preserves deterministic observable order: each imported value is still processed in slice order, `relative_to_absolute` still resolves handles against the same host object table, and `check_val_integrity` still runs before the host object is published.

## Anti-Evidence

- The current code's individual operations are small; if guest vector/map lengths are usually tiny, zero-fill and temporary-buffer removal may fall below the Medium threshold. A PoC needs narrow counters for `vec_new_from_linear_memory` and the value-import subphase of `map_new_from_linear_memory`.
- Budget accounting is consensus-visible. Combining or reducing the current `MemCpy` charges must either reproduce identical p26 totals or be gated behind a future protocol version.
- The implementation would likely need carefully audited `MaybeUninit` or spare-capacity code. That is acceptable only if it remains localized to the checked linear-memory import helper and keeps all out-of-bounds and invalid-`Val` errors identical.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — substantially equivalent narrower variant of the `ai-summary/fail/transaction-ledger/summary.md` entry for `001-fuse-linear-memory-object-builders.md`
**Failed At**: reviewer

### Trace Summary

The hot path is real: parallel Soroban apply reaches `InvokeHostFunctionOpFrame::doParallelApply`, calls the Rust `invoke_host_function` bridge, enters `Host::invoke_function`, and Wasm host-function dispatch invokes `map_new_from_linear_memory` / `vec_new_from_linear_memory` inside worker threads that are joined before `applyLedger` proceeds. The specific inefficiency also exists: both constructors allocate and initialize a temporary `Vec<Val>`, read guest memory through `metered_vm_read_vals_from_linear_memory`, translate handles in the callback, and then perform a separate integrity-check pass. However, the hypothesis is a narrower instance of a previously rejected linear-memory builder-fusion family, and its own normalized trace totals show that removing the entire vector and map import zones would only barely clear the Medium floor before subtracting all mandatory work.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:21` — prior reviewed failure for `001-fuse-linear-memory-object-builders.md` already found linear-memory map/vector builder fusion below threshold because mandatory guest-memory access, range checks, handle translation, `Val` integrity checks, and symbol conversion dominate.
- `ai-summary/fail/transaction-ledger/001-sdk-sorted-linear-memory-map-constructor.md:52-73` — related map-constructor fast-path review found the map side's entire normalized `map_new_from_linear_memory` zone below the Medium threshold once mandatory validation and construction work remain.
- `ai-summary/CURRENT_STATE.md:41-64` — authoritative soroswap median baseline is 272.895607 ms, so the objective's 3% Medium floor is about 8.19 ms per ledger.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-999` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — Soroban operation apply calls `invokeHostFunction` under the parallel apply helper.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-480` — the C++ bridge constructs enforcing host storage and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-253` — Wasm host-function dispatch transfers fuel, charges dispatch, marshals arguments, and calls the concrete host method.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1856` — `map_new_from_linear_memory` reads key slices, allocates and initializes `vals`, charges conversion/translation, reads value bytes, checks every imported `Val`, then builds the final `HostMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2124-2150` — `vec_new_from_linear_memory` performs the same value-import pattern before wrapping the resulting `Vec<Val>` as a `HostVec`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:153-193` — `metered_vm_read_vals_from_linear_memory` bounds-checks one linear-memory range, charges `MemCpy`, copies each 8-byte chunk through a temporary array, and invokes the conversion callback.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:362-409` and `src/rust/soroban/p26/soroban-env-common/src/env.rs:40-56` — handle translation and `Val`/object integrity checks are correctness requirements for untrusted guest-provided values, not removable bookkeeping.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:117-120`, `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:83-89`, and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — container construction and final invariant checks remain even if the value import loop is fused.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — worker futures are joined synchronously, so only per-cluster critical-path savings count, requiring T=8 normalization of aggregate worker time.

### Why It Failed

This is not viable for the optimize-soroswap objective because it fails novelty and severity. The prior `001-fuse-linear-memory-object-builders.md` failure already covered the same class of direct linear-memory map/vector construction and rejected it as below threshold after accounting for mandatory guest-memory access, range checks, handle translation, integrity checks, and construction work. The present hypothesis narrows that family to the `Val` import subphase and therefore cannot recover more than the broader rejected builder-fusion idea.

Independently, the hypothesis's own evidence gives a hard critical-path upper bound of about 9.38 ms per ledger for eliminating the entire `vec_new_from_linear_memory` plus entire `map_new_from_linear_memory` zones after T=8 normalization. A correct implementation cannot remove anything close to the entire zones: it must still borrow and bounds-check guest memory, read each element, convert bytes to `Val`, translate relative handles, validate each `Val`, allocate/publish the final host object, preserve map key handling, and either preserve p26 budget totals or protocol-gate any metering changes. The removable pieces — zero fill, an intermediate `[u8; 8]` copy that may already compile to simple loads, pass fusion, and budget-call coalescing within these two small zones — are a subset of that 9.38 ms upper bound and fall below the 8.19 ms Medium floor.

### Lesson Learned

For guest-boundary micro-optimizations, normalize aggregate worker-zone time by configured cluster parallelism before projecting apply-time savings. If the sum of entire target zones only barely reaches the 3% threshold, a subphase optimization that preserves mandatory validation and object construction should be rejected unless narrow counters show the removable subphase alone clears the Medium floor.
