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
