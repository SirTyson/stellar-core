# H001: Fast-path small `ScVal`/`Val` conversions before depth-limited object conversion

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing generic depth-limiter and object-classification overhead from hot immediate-value conversions
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Host conversion between `ScVal` and `Val` should preserve exactly the same output values, error behavior, and budget charges as today. Small immediate values that cannot recurse and do not allocate host objects should not pay the physical overhead of the generic depth-limited conversion path; only object-valued conversions should enter the existing recursive `with_limited_depth` machinery and object visitor paths.

## Mechanism

`Host::to_host_val`, `Host::from_host_val`, and `Host::from_host_val_for_storage` always clone/borrow the budget, enter `DepthLimiter::with_limited_depth`, and call the generic `TryFromVal` conversion implementations even for immediate values such as bools, small integers, small symbols, and small timepoints/durations. Those immediate cases do not charge conversion budget and cannot overflow the recursive conversion depth, but the soroswap apply path executes them hundreds of thousands of times while converting SAC balance values, event topics/data, storage keys, and ledger-entry values. Adding direct small-value matches before the depth-limited path would preserve all object conversion behavior while removing repeated unmetered wrapper overhead from the common non-object case.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md` and export conversion zones with `csvexport-release -e`. The reference trace reports `ScVal to Val` at `soroban-env-host/src/host/conversion.rs:436` with 283.904 ms self-time over 480,076 calls, plus `Val to ScVal` at `conversion.rs:411` and `conversion.rs:423` with 101.015 ms combined self-time over 469,560 calls. An unwrap timestamp check showed all 480,076 `ScVal to Val`, all 469,560 `Val to ScVal`, and their full 1.375 s total execution time fall inside `applyLedger` windows, not TX-set construction.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443` — `from_host_val`, `from_host_val_for_storage`, and `to_host_val` always use depth-limited generic conversion today.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:419-508` — `TryFromVal<E, Val> for ScVal` already has a complete tag match for immediate `Val` cases that can be hoisted into a host fast path.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:521-600` — `TryFromVal<E, ScVal> for Val` first calls `Val::can_represent_scval` and `ScValObjRef::classify`, then handles small values; the small-value subset can be matched directly before object classification.
- `src/rust/soroban/p26/soroban-env-common/src/object.rs:124-198` — `ScValObjRef::classify` decides which values require host objects; the fast path must exactly mirror the `None` cases and leave all `Some` cases on the existing object path.

## Evidence

- Tracy scope check: `csvexport-release -u -f "ScVal to Val"` and `-f "Val to ScVal"` matched every conversion event within `applyLedger` windows. These zones are part of the measured close-ledger Soroban apply path through `InvokeHostFunctionOpFrame::doApply` -> Rust `invoke_host_function` -> `Host::invoke_function` / SAC built-ins / storage diffing.
- The current helper structure imposes the same physical wrapper cost on trivial conversions as on recursive object conversions. For example, `to_host_val` enters `budget_cloned().with_limited_depth` before matching `ScVal::Bool`, `ScVal::U32`, small `ScVal::I128`, or small `ScVal::Symbol`, even though these cases do not visit host objects and have no conversion-specific budget charges.
- The aggregate self-time is above the Medium threshold if a large immediate-value fraction can be fast-pathed. The conversion zones account for ~385 ms self-time and ~1.375 s total execution time inside the 5.774 s traced `applyLedger` envelope; saving even half of the self-time is a plausible multi-percent apply-time reduction.
- This is distinct from previous failed object-visit and `MeteredOrdMap<Val, _>` investigations. It does not cache address objects, change map comparisons, skip storage lookups, or alter `VisitObject`/`MemCpy` charges; it only bypasses unmetered generic conversion scaffolding for values that are already known to be immediate.

## Anti-Evidence

- The full conversion zones are upper bounds. Object-valued conversions for addresses, vectors, maps, strings, bytes, large integers, and storage keys must remain on the existing object path and keep all `VisitObject`, `MemAlloc`, `MemCpy`, and recursive depth-limit behavior.
- `from_host_val_for_storage` currently toggles `storage_key_conversion_active` so muxed addresses are rejected in storage keys. The fast path must only bypass the guard for immediate values; all object values, especially `MuxedAddressObject`, must keep the existing guarded path.
- `Val::can_represent_scval` rejects non-ABI `ScVal` variants such as `LedgerKeyNonce`, `LedgerKeyContractInstance`, and `ContractInstance`. The fast path must preserve those errors and should be implemented as an allow-list of immediate representable variants rather than a broad fallback.
- The PoC should instrument immediate-vs-object conversion counts before relying on the projection. If soroswap conversion time is dominated by object conversions, this falls below the Medium floor.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban-env` or `success/soroban-env`; cross-subsystem fail/success directories are absent

### Trace Summary

The conversion wrappers in `Host` do unconditionally enter the depth-limited generic conversion path before handling any `Val` or `ScVal`, including immediate values that cannot allocate host objects or recurse. The generic common-crate implementations then perform exactly the small-value tag/variant matches the hypothesis describes, while object-valued cases delegate back into host object conversion where metering and recursion are required. The traced apply path reaches these functions through storage-key conversion, persistent contract-data reads/writes, event externalization, authorization conversion, host-function return conversion, and vector/map conversion helpers. The optimization is viable if implemented as a strict immediate-value allow-list that preserves the current depth-limit failure boundary and leaves all object and storage-key object cases on the existing path.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443` — `from_host_val`, `from_host_val_for_storage`, and `to_host_val` always create the Tracy span, clone the budget, and call `Budget::with_limited_depth` before generic conversion.
- `src/rust/soroban/p26/soroban-env-host/src/budget/limits.rs:71-113` — `with_limited_depth` performs one enter and one leave around the conversion, each borrowing the `Budget`'s `RefCell`; immediate conversions pay this even though they do not recurse.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:419-508` — `TryFromVal<E, Val> for ScVal` first checks for object tags, then directly maps non-object tags such as bool, void, error, small integers, timepoints/durations, and small symbols.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:521-600` — `TryFromVal<E, ScVal> for Val` checks representability, classifies object-valued `ScVal`s, and only then matches the same small representable variants.
- `src/rust/soroban/p26/soroban-env-common/src/object.rs:124-198` — `ScValObjRef::classify` identifies the exact boundary between always-small, value-dependent-small, always-object, and non-Val-representable `ScVal` variants.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:156-166,197-221,266-288,463-565` — storage-key conversion, vector/map externalization, and object conversion recursively call `from_host_val`, `from_host_val_for_storage`, and `to_host_val`, so the fast path must preserve recursive object depth checks while avoiding leaf-only wrapper work.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2243` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-550` — persistent contract-data reads/writes convert storage keys and values through the target helpers in the SAC-heavy apply path.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:23-27` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1185-1194` — event externalization and top-level host-function returns convert `Val` results back to XDR `ScVal`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:596-603,619-627,1822-1835` — authorization entries convert XDR argument lists and signatures through `scvals_to_val_vec` / `to_host_val`, adding non-storage hot-path coverage.
- `ai-summary/fail/soroban-env/001-single-lookup-sac-try-get.md`, `002-in-place-storage-map-mutation.md`, `002-specialize-val-key-metered-map-lookups.md`, `011-eliminate-is-clean-fuel-check.md`, and `012-cache-repeated-ledger-entry-xdr-decodes.md` — related failures do not duplicate this immediate conversion fast path.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md` — the confirmed storage-map lookup optimization is related only by objective area; it does not address `ScVal`/`Val` conversion scaffolding.

### Findings

The inefficiency exists in source. Immediate `Val` tags and immediate representable `ScVal` variants currently traverse the same host wrapper as object conversions: an `Rc` budget clone, two depth-limiter `RefCell` mutations, closure dispatch, generic `TryFromVal` plumbing, `Val::can_represent_scval` / `ScValObjRef::classify` checks on the `ScVal` side, and post-conversion representability checking on the `Val` side. These operations are unmetered and therefore removable without changing `cpu_insns`/`mem_bytes`, provided the object path is unchanged.

The hot-path claim is plausible. The reference diagnostic data places roughly 950k target conversion calls inside `applyLedger`, with conversion self-time around 6.7% of the traced apply envelope. Soroswap/SAC paths repeatedly convert small symbols, bools, integers, timepoints/durations, and balance values for storage keys, storage values, events, auth arguments, and host-function returns. Because object-valued address/map/vector/string/bytes conversions must stay on the existing metered path, the PoC must count immediate vs object conversions and pass the objective's 3% non-Tracy apply-time floor; nevertheless the source-level target is broad enough to justify PoC work.

Correctness is the main constraint. A naive early return that skips all depth-limit checks would shift the exact `ExceededLimit` boundary for pathological nested structures with immediate leaves. The fast path should either preserve the current "depth remaining" failure condition with a cheap non-mutating check, or otherwise prove existing hostile-depth tests and near-limit behavior are unchanged. `from_host_val_for_storage` can skip `storage_key_conversion_active` only for proven non-object values; muxed addresses and all other object tags must continue through the guarded path. `ScVal` fast paths must be an explicit allow-list of representable immediate variants, not "anything classified as `None`", because `LedgerKeyNonce`, `LedgerKeyContractInstance`, and `ContractInstance` are also classified as non-object but are not valid ABI `Val`s.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs`, primarily `Host::from_host_val`, `Host::from_host_val_for_storage`, and `Host::to_host_val`. Add small private helpers there rather than changing the public generic `TryFromVal` behavior unless the helper can be shared safely.
- **Change description**: Add direct immediate conversion matches before the existing generic object path. For `Val -> ScVal`, match non-object tags handled at `convert.rs:436-484`; for object tags and invalid tags, fall back to the existing depth-limited path. For `ScVal -> Val`, match only representable immediate variants that fit small encodings; route large integers, long symbols, bytes, strings, vecs, maps, addresses, and invalid/non-representable variants to the existing path or existing error handling as appropriate.
- **Correctness check**: Preserve depth-limit behavior for recursive conversions, preserve `from_host_val_for_storage` muxed-address rejection for object values, preserve `ConversionError`/`HostError` mapping for invalid values, and preserve all `VisitObject`, `MemAlloc`, `MemCpy`, and recursive conversion charges. Existing tests to keep green include `depth_limit`, `hostile_opt` depth tests, storage muxed-address conversion tests, symbol/basic/map/vec conversion tests, and budget metering tests that cover object conversions.
- **Benchmark focus**: First instrument immediate-vs-object hit counts for the three target helpers in the soroswap apply window. Then run the required non-Tracy `scripts/run_apply_load_matrix.py` comparison against the current baseline three times. The promoted result must show a reproducible >=3% soroswap median apply-time improvement; otherwise this should be rejected later as below the objective severity floor.
