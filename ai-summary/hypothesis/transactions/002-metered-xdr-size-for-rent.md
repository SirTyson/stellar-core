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
