# H001: Preallocate Metered XDR Output Buffers in Ledger-Change Encoding

**Date**: 2026-04-28
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing hot per-invocation allocation/copy overhead without changing metered XDR charge counts
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a soroswap ledger applies thousands of successful Soroban invocations, the Rust host should return the same `LedgerEntryChange` records, result XDR, contract-event XDR, rent sizes, budget counters, and ledger state as today. The physical encoding path should avoid repeated `Vec` growth and reallocation when the approximate output size is already known from the input ledger-entry buffers or from nearby rent-size metadata.

## Mechanism

`metered_write_xdr` writes every output object through `Limited<MeteredWrite>` into a caller-provided `Vec<u8>` without reserving capacity first (`src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68`). Hot callers in `get_ledger_changes` and `encode_contract_events` repeatedly create empty vectors and then serialize keys, old entries, new entries, invoke results, and events (`src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:206-228`, `264-272`, `489-508`, `875-889`). In the current soroswap trace, zone `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:61` has 403.8 ms self-time over 67,330 calls, and event timestamps show 61,441 calls / 487.1 ms total duration inside `applyLedger` windows, so removing allocation growth around the same metered writes has enough headroom for a Medium win.

The optimization would add size-hinted variants of the output encoding path, for example carrying each input ledger entry's `entry_buf.as_ref().len()` from `build_storage_map_from_xdr_ledger_entries` into the snapshot metadata and reserving that length when re-serializing old entries, using the old-entry size as a reserve hint for same-key new entries, and reserving small fixed capacities for ledger keys and common contract events. This preserves determinism and protocol-visible metering because the same `WriteXdr` traversal and the same `ValSer` `charge()` calls still happen; only physical `Vec` capacity management changes.

## Trigger

Run the current soroswap apply-load benchmark (`TX=4000`, `T=8`) with Tracy enabled and inspect `write xdr` under `applyLedger`. A PoC should instrument `metered_write_xdr` buffer capacity changes, then add reserve hints for `get_ledger_changes` and event/result encoding and confirm identical outputs and budget counters while reducing median soroswap apply time by at least 3%.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — central metered writer currently serializes into whatever capacity the caller supplied.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-229` — `get_ledger_changes` serializes each key and old entry into fresh empty buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:248-272` — successful read-write entries serialize new values into fresh empty buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1044` — input ledger-entry buffer lengths are available while building the storage map, but are discarded before output encoding.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:875-889` — contract events are encoded through fresh empty vectors.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:474-497` — C++ already materializes encoded ledger-entry buffers and records their sizes before passing them to Rust.

## Evidence

The accepted current state points to `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`, where `applyLedger` totals 4.331724168 s. `csvexport-release -e` reports `write xdr,soroban-env-host/src/host/metered_xdr.rs,61,403774625,...,67330,...`; timestamp intersection with `applyLedger` windows shows 91.3% of `write xdr` event duration is in-scope. The code uses fresh `vec![]` allocations in hot loops, and the original encoded ledger-entry sizes are already known on both the C++ and Rust ingress paths, making reserve-only changes plausible without touching serialized bytes or charge counts.

## Anti-Evidence

Prior failed investigation `ai-summary/fail/soroban-env/summary.md` entry 004 ruled out skipping XDR writes or changing `ValSer` charge counts, so this hypothesis must not remove serialization or batch charges. If instrumentation shows `Vec` growth/copy is a small fraction of the 403.8 ms self-time and the time is dominated by mandatory `WriteXdr` traversal and Tracy/budget accounting, the improvement will fall below the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; related fail-summary entry 004 targeted skipping/batching XDR work and changing charge counts, while this hypothesis keeps the same writes and only reserves output capacity
**Failed At**: reviewer

### Trace Summary

The empty-buffer pattern exists on the successful Soroban invocation path: C++ serializes ledger entries into `CxxBuf`s, Rust decodes them into a `StorageMap`, invokes the host, then encodes the result, per-footprint ledger changes, and contract events through `metered_write_xdr`. However, the cited `write xdr` self-time is an upper bound on all metered serialization work, not a measurement of `Vec` growth. A reserve-only change would leave the XDR traversal, `Limited` wrapper, every `MeteredWrite::write` callback, every `ValSer` budget charge, and downstream C++ decode/hash work intact, so the trace does not support a 3%+ apply-time reduction.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` wraps the caller's `Vec<u8>` in `Limited<MeteredWrite>` and calls `WriteXdr`; reserving capacity would not remove the per-chunk `Budget::charge(ValSer, len)` or serialization callbacks.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` allocates fresh buffers for encoded keys, old entries, and new read-write entries; this confirms the inefficiency but also shows the same serialized bytes are needed for key hashing, rent sizing, and C++ output.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-508` — the enforcing invocation path decodes resources and ledger-entry inputs, clones the initial storage map, invokes the host, encodes the result value, then calls `get_ledger_changes` and `encode_contract_events` only after success.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:875-889` — contract events are individually serialized into fresh vectors and then bulk-charged for the resulting outer vector; preallocation can avoid some capacity growth but cannot remove event serialization.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — input ledger-entry byte lengths are available while decoding, but only `StorageMap` and `TtlEntryMap` are returned, so using those lengths later would require carrying additional metadata through the storage snapshot path.
- `src/rust/src/soroban_proto_any.rs:430-506` — the bridge wrapper collects budget counters, computes rent changes from the encoded ledger changes, converts modified entries and events into `RustBuf`s, and returns them to C++.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:474-497,575-584,654-720,770-799,879-918` — C++ creates the input `CxxBuf`s and later consumes Rust output by decoding modified ledger entries/events and hashing already-encoded return/event bytes; these downstream steps are unaffected by Rust-side reserve hints.
- `src/rust/soroban/p26/soroban-env-host/src/cost_runner/cost_types/val_ser.rs:25-33` — the ValSer cost runner intentionally measures typical `metered_write_xdr` usage with an empty vector, reinforcing that the broad serialization path includes allocation but not showing allocation is a dominant component.

### Why It Failed

The optimization target is too narrow for the objective's Medium threshold. The cited 403.8 ms `write xdr` self-time is about 9.3% of the referenced 4.3317 s apply window, but a reserve-only patch would need to save at least about 130 ms, or more than one third of all in-scope `write xdr` self-time, to clear the 3% objective floor. The traced code shows most of that zone is mandatory serialization and metering work that remains unchanged: `WriteXdr` still visits every field, `MeteredWrite::write` still charges every emitted chunk, encoded old/new values are still needed for rent/output, and C++ still decodes or hashes the returned bytes. Since `Vec` growth is only occasional geometric capacity management inside that broader work, the hypothesis has no code-path basis for a Medium projection and should not proceed without separate allocation-growth instrumentation showing a much larger removable share than the trace supports.

### Lesson Learned

For Soroban output-encoding optimizations, do not project from the whole `write xdr` Tracy zone unless the removable subcomponent has been isolated. Reserve hints are behavior-preserving and may be a small cleanup, but the optimization pipeline should only promote them if instrumentation shows `Vec` realloc/copy time alone exceeds the 3% apply-time threshold.
