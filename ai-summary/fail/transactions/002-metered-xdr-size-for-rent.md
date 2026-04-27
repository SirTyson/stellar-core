# H002: Replace temporary old-entry XDR buffers with metered size computation

**Date**: 2026-04-27
**Subsystem**: transactions
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding redundant XDR allocation/serialization in ledger-change extraction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When extracting Soroban ledger changes after a successful invocation, Core should compute rent sizes and emit changed ledger entries exactly as today, but should not allocate and serialize old ledger entries into temporary `Vec<u8>` buffers when only the encoded length is needed. The computed `old_entry_size_bytes_for_rent`, rent fee, refundable fee, and emitted `LedgerEntryChange` data must remain identical to the current XDR length semantics.

## Mechanism

`get_ledger_changes` serializes every existing old entry into a fresh temporary `Vec<u8>` solely to pass `buf.len()` into `entry_size_for_rent`. For read-only TTL bumps and read-write updates alike, this repeats full XDR writing even though the old entry bytes are not returned to C++; only their encoded size is used. Adding a metered XDR-size/counting writer, or an exact size helper that charges the same `ValSer` budget as `metered_write_xdr`, should remove allocation and byte-copy work while preserving rent accounting and budget semantics.

## Trigger

Run the current soroswap apply-load benchmark with Tracy and inspect the hottest `applyLedger` interval in `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`. In that interval, the `write xdr` zone accounts for 495.803 ms across 58,393 calls under `parallelApply` / `InvokeHostFunctionOpFrame doParallelApply`; the full trace self-time also shows `write xdr` at 388.068 ms self over 61,830 calls. A PoC should replace the old-entry temp-buffer path with metered size computation and verify the encoded output/rent fees are unchanged while soroswap median apply time decreases.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:225-231` — serializes `old_entry` into a temporary `buf` only to compute `old_entry_size_bytes_for_rent`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:263-272` — serializes new read-write entries into `encoded_new_value`; this path must remain because the bytes are returned to Core.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:330-360` — `extract_rent_changes` consumes old/new rent sizes and TTL changes, so exact size preservation is required.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` wraps `MeteredWrite` and `Limited`; the new size helper should preserve equivalent budget/error behavior without materializing bytes.

## Evidence

The target runs after `Host::invoke_function` inside `e2e_invoke::invoke_host_function`, which is called from `InvokeHostFunctionOpFrame::doParallelApply` in the measured apply path. Tracy verifies `write xdr` is hot inside the hottest `applyLedger` window, while the source shows at least one serialization path whose output bytes are immediately discarded after taking `len()`. Soroswap swaps modify and TTL-bump multiple contract-data entries per transaction, so old-entry size accounting is repeated thousands of times in the benchmark.

## Anti-Evidence

Not all `write xdr` calls are removable: encoded keys, encoded new values, return values, and events are observable outputs and must still be materialized. A size-only helper must also preserve budget exhaustion behavior; if it charges in a different order than XDR writing, it could change deterministic failure results for transactions near the budget limit.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban apply path reaches this code through `InvokeHostFunctionOpFrame::doParallelApply`, which constructs an apply helper, invokes the Rust host, then records returned storage changes and refundable resources. On a successful host invocation, `soroban_proto_any::invoke_host_function` calls `e2e_invoke::invoke_host_function`, which runs `Host::invoke_function`, calls `get_ledger_changes`, computes rent changes, extracts modified ledger entries, and returns the rent fee and encoded effects to C++. The claimed temporary old-entry buffer is real: `get_ledger_changes` XDR-writes each existing old entry into a fresh `Vec<u8>` only to pass `buf.len()` to `entry_size_for_rent`, and `extract_ledger_effects` never returns those bytes. However, an exact consensus-safe fix still has to traverse the old entry XDR and charge `ValSer` in the same order; it can only remove allocation/growth/copying of the temporary `Vec`, not most of the observed `write xdr` cost.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — common apply helper loads footprint entries, calls `invokeHostFunction`, records storage changes, collects events, consumes refundable resources, and finalizes success.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — v23+ parallel Soroban apply entry point used by soroswap calls the common helper.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ bridge call passes encoded resources, host function, ledger entries, TTL entries, source, auth, PRNG seed, rent configuration, and module cache into Rust.
- `src/rust/src/soroban_invoke.rs:7-38` — protocol dispatch selects the current Soroban host module and calls its `invoke_host_function`.
- `src/rust/src/soroban_proto_any.rs:430-506` — wrapper times `e2e_invoke::invoke_host_function`, then on success calls `extract_rent_changes`, computes rent fee, calls `extract_ledger_effects`, and returns encoded result/events/modified entries to C++.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes keys for returned effects, serializes old entries into temporary buffers for rent-size length only, serializes new read-write entries into buffers that are returned to Core, and stores old/new rent sizes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:329-366` — `extract_rent_changes` consumes only the old/new rent-size fields and TTL deltas when computing rent inputs.
- `src/rust/src/soroban_proto_any.rs:261-302` — `extract_ledger_effects` returns non-read-only `encoded_new_value` buffers and synthesized TTL entries; it does not consume old-entry bytes.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` wraps `WriteXdr` in a `Limited<MeteredWrite<_>>`, charging `ValSer` by write chunk before appending to the target `Vec`.
- `src/rust/soroban/p26/soroban-env-host/src/test/budget_metering.rs:191-197,212-234` — existing tests assert metered XDR charges exactly the encoded byte length and maps out-of-budget writes to budget exceeded.

### Why It Failed

This is below the objective severity threshold. The inefficient temporary old-entry buffer exists and a counting writer could preserve rent sizes, budget input totals, and error mapping if it reuses the same `WriteXdr`/`Limited` path. But the projected top-line effect does not reach the required 3-10% soroswap apply-time reduction: the cited `write xdr` zone aggregates many calls that cannot be removed, including encoded keys, encoded new ledger values, return values, events, and TTL effects. Even for the old-entry path, correctness requires continuing the XDR traversal and `ValSer` charge sequence, so the removable work is only a fresh `Vec` allocation plus byte copies for a subset of `write xdr` calls.

The benchmark baseline records soroswap median apply time at about 621 ms. Clearing the Medium bar would require roughly 19-62 ms of reproducible top-line improvement. The hypothesis's own trace evidence reports about 58k `write xdr` calls in the hot interval, but old-entry size-only calls are at most a fraction of that count, and the remaining per-call saved work is small for typical soroswap contract-data entries after preserving serialization traversal and metering. This makes the change a plausible micro-optimization, but not a viable optimize-soroswap finding under the Medium-or-higher review gate.

### Lesson Learned

For Soroban XDR hot zones, distinguish bytes that are observably returned from bytes that are only used for length, but also distinguish materialization cost from mandatory consensus metering. A counting writer can avoid temporary storage, but it does not eliminate `WriteXdr` traversal or `ValSer` charging, so aggregate `write xdr` time cannot be treated as fully removable.
