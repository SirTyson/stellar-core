# H002: Fuse linear-memory `Val` imports for map and vector constructors

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Medium
**Impact**: Apply-time reduction on soroswap by removing redundant initialization and validation passes in VM linear-memory object construction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a guest contract builds a host vector or map from VM linear memory, the host should copy each encoded `Val`, translate relative object handles to absolute handles, validate the result, and create the host object exactly once per element. The final `HostVec` / `HostMap`, error behavior for malformed values, and deterministic map ordering should match the current implementation.

## Mechanism

`vec_new_from_linear_memory` and `map_new_from_linear_memory` allocate a `Vec<Val>` prefilled with `Val::VOID`, call `metered_vm_read_vals_from_linear_memory` to overwrite it while translating handles, and then run a second loop over the same values to call `check_val_integrity`. `map_new_from_linear_memory` also builds a separate `key_syms` vector before zipping keys and values into `HostMap::from_exact_iter`. A specialized linear-memory import iterator could read each 8-byte `Val`, translate and validate it immediately, and push initialized values without the `Val::VOID` fill or second validation pass; the map path could similarly stream `(Symbol, Val)` pairs into the sorted-map constructor after validating each element.

## Trigger

Run the current soroswap apply-load Tracy benchmark and inspect linear-memory constructor zones under `applyLedger`. Unwrap-mode analysis found all events in scope: `vec_new_from_linear_memory` has 36,919 events and 182,141,606 ns total time, `map_new_from_linear_memory` has 9,968 events and 169,680,508 ns total time, and `symbol_new_from_linear_memory` has 3,535 events and 13,961,482 ns total time. Their aggregate self-time from `csvexport -e` is about 184 ms, roughly 3.2% of the traced 5.774 s `applyLedger` envelope.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1857` — `map_new_from_linear_memory` scans key slices into `key_syms`, pre-fills `vals`, reads/translates values, validates in a second pass, then constructs the host map.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2124-2150` — `vec_new_from_linear_memory` pre-fills `vals`, reads/translates values, validates in a second pass, then wraps the vector.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:153-180` — `metered_vm_read_vals_from_linear_memory` copies linear-memory chunks into a caller-provided initialized slice, forcing callers to allocate and initialize the destination before reading.
- `src/rust/soroban/p26/soroban-env-common/src/env.rs:40-56` — `check_val_integrity` performs the validation that can be fused immediately after relative-to-absolute translation.

## Evidence

The current trace places the linear-memory constructors entirely inside `applyLedger`, and their combined self-time is just above the 3% Medium threshold before considering secondary savings from fewer allocations and fewer host-object integrity checks. The code shows two avoidable passes over imported values: one implicit initialization pass from `vec![Val::VOID; len]`, then a post-read validation pass after `metered_vm_read_vals_from_linear_memory` has already visited every element. A fused importer preserves deterministic element order and does not introduce parallelism, so it should not affect cross-node determinism.

## Anti-Evidence

The proposal must preserve all existing error checks: bounds checks in `metered_vm_read_vals_from_linear_memory`, `relative_to_absolute` object-handle validation, `Val::good`, and map sorted/unique validation. A prior vector-only allocation angle may be too small on its own, so this hypothesis depends on fusing the vector and map import paths together and recovering more than just heap allocation overhead. If the dominant cost in these zones is wasmi dispatch outside the shown constructors, the measurable non-Tracy win may fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/crypto` or `success/crypto`; prior crypto failures cover SHA256, signature verification, bridge buffers, storage-key hashing, and VM argument allocation, not linear-memory vector/map import fusion
**Failed At**: reviewer

### Trace Summary

The apply path enters Soroban through `InvokeHostFunctionOpFrame::invokeHostFunction`, crosses the Rust bridge, dispatches to the protocol-specific host, and eventually invokes the Wasm contract through `Host::invoke_function` and `Vm::invoke_function_raw`. Guest SDK helpers call the linear-memory host imports, and the generated VM dispatch converts relative arguments before calling `Host::{map,vec}_new_from_linear_memory`. Those functions do contain the claimed initialized `Vec<Val>` overwrite pattern and a later `check_val_integrity` loop, but most work in the cited zones is mandatory: linear-memory bounds/read, budget charging, relative-to-absolute object translation, object validation semantics, sorted/unique map validation, and final host-object insertion.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ Soroban apply calls `rust_bridge::invoke_host_function` from the operation application path.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:310-354,391-452` — Rust bridge selects the protocol host module, builds the budget, and calls the protocol-specific `invoke_host_function` implementation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — host invocation decodes resources and ledger state, constructs `Host`, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1193,750-775` — contract invocation converts XDR args to host `Val`s, sets up `Frame::ContractVM`, and enters the Wasm VM.
- `src/rust/soroban/p26/soroban-env-guest/src/guest.rs:123-153` — guest-side slice helpers call `map_new_from_linear_memory` and `vec_new_from_linear_memory`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:19-38,250-304` — generated dispatch translates relative VM values to absolute host values, calls the host function, and translates the return value back to a relative VM value.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1857,2124-2150` — map/vector constructors allocate `Vec<Val>` initialized with `VOID`, read linear-memory values into it, validate in a second loop, and then construct `HostMap`/`HostVec`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:153-193` — `metered_vm_read_vals_from_linear_memory` performs length arithmetic, bounds checks, memory access, budget charge, byte copying, and per-element conversion into a caller-provided slice.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:361-410` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:821-846` — relative-to-absolute translation and object-integrity checks are semantic validation and cannot simply be removed.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:82-118` — `HostMap::from_exact_iter` still collects pairs and checks sorted/unique order; `HostVec::from_vec` only wraps the already-built vector.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:107-132` — allocation/copy budget charges are protocol-visible metering and would need to be preserved even if the implementation avoids some physical initialization.

### Why It Failed

The inefficiency exists, but the projected apply-time improvement is below this objective's Medium severity threshold. The cited aggregate constructor self-time is about 184 ms, only slightly above the 3% floor on the 5.774 s `applyLedger` envelope, so a viable Medium hypothesis would need to remove nearly the entire measured constructor self-time. A fused importer can avoid the `Val::VOID` fill, avoid one extra vector in the map path, and combine validation with the import loop, but it still must read every byte from Wasm memory, preserve all budget charges, run `relative_to_absolute`, validate malformed `Val`s with the same error precedence, check map key sortedness/uniqueness, and add the resulting host object. Because the removable work is only a fraction of the traced zones, the realistic saving is below the 3% Medium floor required by optimize-soroswap.

### Lesson Learned

Do not promote linear-memory import cleanups by comparing them to an entire constructor self-time block when the block is barely above the Medium threshold. For these constructors, the local allocation/pass cleanup is real and may be a tidy low-level optimization, but the semantic work that remains dominates enough that it cannot be justified as a Medium-or-higher soroswap apply-time finding without a stronger trace that isolates the removable sub-costs.
