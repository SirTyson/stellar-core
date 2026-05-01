# H002: Build Vec and Map objects directly from linear-memory Val imports

**Date**: 2026-05-01
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing temporary allocations, zero-fills, and extra passes from hot Wasm linear-memory Vec/Map constructors while preserving relative-handle translation and metering
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`vec_new_from_linear_memory` and `map_new_from_linear_memory` should produce exactly the same `HostVec` and `HostMap` objects as today, with the same out-of-bounds errors, relative-to-absolute object-handle translation, value-integrity checks, sorted-map validation, and budget charges. They should not allocate and initialize intermediate `Vec<Val>` / `Vec<Symbol>` buffers or perform separate validation passes when the imported values can be decoded, translated, checked, and assembled into the final host object storage in one construction flow.

## Mechanism

The current vector path allocates `vec![Val::VOID; len]`, copies guest bytes into that initialized buffer via `metered_vm_read_vals_from_linear_memory`, runs a second loop for `check_val_integrity`, and then moves the buffer into a `HostVec`. The map path first scans key slices into a `Vec<Symbol>`, then allocates and fills a separate `Vec<Val>`, checks every value, zips both temporary vectors, and finally builds a `HostMap`. A specialized builder can reserve uninitialized or capacity-only storage, push each decoded/translated `Val` exactly once after integrity checking, and for maps build `(key_val, value)` pairs directly before handing them to the existing sortedness/duplicate validation, while replaying the same bulk-init and `MemCpy` charges now paid by the temporary buffers.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md` and inspect the linear-memory import zones. `csvexport-release -e` reports `vec_new_from_linear_memory` at `soroban-env-host/src/vm/dispatch.rs:304` with 154,780,911 ns self-time over 56,308 calls and `map_new_from_linear_memory` at the same dispatch line with 98,102,195 ns self-time over 15,220 calls. An unwrap timestamp check showed `vec_new_from_linear_memory` has 56,104 of 56,308 events inside apply for 252,792,077 ns total execution time, and `map_new_from_linear_memory` has 15,172 of 15,220 events inside apply for 246,296,754 ns total execution time.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1856` — `map_new_from_linear_memory` builds `key_syms` and `vals` as separate temporary vectors, then zips them into a `HostMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2124-2149` — `vec_new_from_linear_memory` zero-initializes a `Vec<Val>`, fills it from Wasm memory, then checks integrity in a separate pass before creating a `HostVec`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:153-183` — `metered_vm_read_vals_from_linear_memory` reads chunks into an already-initialized destination slice and invokes a per-element conversion closure.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:213-245` — `metered_vm_scan_slices_in_linear_memory` scans map key slices from guest memory before the separate values pass.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:82-124` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — final host containers can still validate length/sortedness and charge clone/allocation costs after direct construction.

## Evidence

- The target zones are inside the measured `applyLedger` windows. They are generated dispatch zones for Wasm host calls made during Soroban contract execution, not benchmark TX-set construction.
- The source has clear temporary-buffer work that is not required for the final data structure: `vec_new_from_linear_memory` initializes every element to `VOID` before overwriting it, and `map_new_from_linear_memory` keeps keys and values in separate vectors only to immediately zip them.
- The final host containers are immutable after creation, so direct construction does not change observable mutation semantics. Deterministic map ordering remains enforced by the existing `HostMap::from_exact_iter`/validation path or an equivalent pair-vector validation with the same comparison order.
- The optimization is budget-preserving in principle: current code already charges bulk vector initialization and explicit conversion/translation `MemCpy` amounts before doing the physical work. A direct builder can keep those charges exactly while avoiding the physical zero-fill and intermediate vector churn.
- The combined in-apply execution time of these two constructors is about 499 ms across the diagnostic run, with additional child time visible in `new vec` and `new map`. Removing a substantial fraction of the temporary allocation/pass overhead has a plausible path to a Medium soroswap apply-time reduction.

## Anti-Evidence

- The whole constructor zone is an upper bound. Guest memory bounds checks, actual memory reads, relative-to-absolute translation, integrity checks, map key symbol conversion, sortedness comparison, and final host-object allocation still remain.
- Using `MaybeUninit` or capacity-only vectors must be implemented carefully to avoid unsafe initialization bugs and to preserve error behavior if decoding fails partway through.
- Map construction must preserve duplicate-key and sort-order errors exactly. If a pair-vector fast path changes comparison order or skips `HostMap` validation charges, it is not viable.
- Prior soroban-env failures show that broad Tracy zones often overstate removable work. A PoC should instrument temporary-buffer lengths/counts and compare repeated non-Tracy apply-load runs; if the removable allocation/pass subset is less than roughly one third of the combined constructor cost, this likely falls below the objective’s 3% Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related fail/success records cover import validation, storage/map lookup, storage-map mutation, auth snapshots, and budget/serialization paths, but not direct linear-memory Vec/Map import construction
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban path reaches these constructors through generated Wasm dispatch functions: the VM returns fuel to the host, charges `DispatchHostFunction`, converts raw Wasm arguments, and calls `Host::vec_new_from_linear_memory` or `Host::map_new_from_linear_memory`. The vector constructor does allocate and overwrite a temporary `Vec<Val>`, and the map constructor does use separate key and value temporary vectors before creating the final `HostMap`. However, the existing implementation has a behavior-relevant phase ordering: it performs all guest-memory bounds checking and relative-to-absolute value translation before any value-integrity checks, and maps scan all keys before reading any values. A true one-pass decode/translate/check/push builder would change which error is returned when multiple malformed inputs are present.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-254` — generated dispatch wraps every Wasm host call, transfers fuel, charges dispatch, converts arguments, and invokes the host function named by the x-macro.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:303-304` — `call_macro_with_all_host_functions!` generates the traced `vec_new_from_linear_memory` and `map_new_from_linear_memory` dispatch functions.
- `src/rust/soroban/p26/soroban-env-common/env.json:1032-1050,1337-1352` — both APIs are guest-callable linear-memory constructors.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:59-73` — `get_mem_fn_args` only extracts the current VM and raw position/length; bounds checking happens later in the memory readers.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:153-193` — `metered_vm_read_vals_from_linear_memory` checks arithmetic and memory bounds, charges one `MemCpy`, then translates every element through the caller-supplied conversion closure.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:213-265` — `metered_vm_scan_slices_in_linear_memory` charges slice-reference copying and validates each map key slice before the value array is read.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1856` — `map_new_from_linear_memory` scans all keys into `key_syms`, charges and initializes a temporary `Vec<Val>`, translates all values, then checks value integrity and builds the final `HostMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2124-2149` — `vec_new_from_linear_memory` charges bulk initialization, physically initializes `len` entries to `VOID`, translates all values into that buffer, then runs a separate integrity pass before installing the `HostVec`.
- `src/rust/soroban/p26/soroban-env-common/src/env.rs:40-56` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:821-845` — `check_val_integrity` rejects malformed non-object values and visits object handles to verify type/tag integrity.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:362-410` — `relative_to_absolute` rejects forged absolute handles, unknown relative handles, and relative/object tag mismatches during the translation phase.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:107-132` — temporary and final vector construction charges are protocol-visible `MemAlloc`/`MemCpy` budget effects and must be replayed if the physical allocation is removed.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,318-334` — final map construction still needs sortedness/duplicate validation and the host-specific invalid-map error mapping.
- `ai-summary/fail/soroban-env/summary.md:20-32` and relevant individual fail/success records in `ai-summary/fail/soroban-env/` and `ai-summary/success/soroban-env/` — prior records are not duplicates, but they reinforce that aggregate Tracy zones are upper bounds and exact metering/ordering constraints usually leave only the physical wrapper work removable.

### Why It Failed

The claimed one-pass mechanism is not behavior-preserving. Today, `metered_vm_read_vals_from_linear_memory` translates every value first; only after that succeeds does the caller run `check_val_integrity` over the translated buffer. If a direct builder checked value integrity as it decoded each element, an earlier malformed `Val` would be reported before a later bad relative object reference, whereas the current implementation would hit the later translation error first. The map path has the same phase-ordering constraint across keys and values: all key slices are scanned and converted before any value bytes are read.

A corrected implementation could still use capacity-only or `MaybeUninit` storage to avoid some physical writes and intermediate containers, but it would need to preserve the current phases: scan all keys first, translate all values before checking any of them, replay all temporary-container metering charges, and then run the existing map sortedness/duplicate validation. That leaves the mandatory memory reads, relative-handle translation, value-integrity object visits, budget charges, final host-object allocation, and final map validation intact. The safely removable subset is therefore limited to `Vec<Val>` zero-fill and some temporary Vec allocation/copy churn, which is too small a fraction of the cited constructor zones to support the objective's required 3-10% apply-time reduction.

### Lesson Learned

Linear-memory import code has observable error phase ordering, not just successful-output semantics. For future constructor optimizations, first separate mandatory translation, integrity, metering, and validation phases from physical allocation work; only promote the hypothesis if focused instrumentation shows the phase-preserving removable work clears the Medium threshold.
