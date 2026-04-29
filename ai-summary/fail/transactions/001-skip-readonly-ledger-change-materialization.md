# H001: Skip No-Op Read-Only Ledger Change Materialization in Apply Output

**Date**: 2026-04-29
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding Rust-side XDR serialization and rent bookkeeping for read-only footprint entries that cannot affect ledger output
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Successful Soroban invoke application should return exactly the same modified ledger entries, TTL bumps, rent fee, result hash preimage, events, resource totals, and C++ ledger state. In enforcing apply mode, no-op read-only footprint entries that did not receive a TTL extension should not require a full `LedgerEntryChange` object, encoded key, old-entry rent size, or later filtering step, because the C++ embedder only consumes modified ledger entries and rent changes.

## Mechanism

`e2e_invoke::get_ledger_changes` currently iterates every entry in `storage.map`, including every read-only footprint key, and eagerly materializes a `LedgerEntryChange` for each one. That includes metered XDR encoding of the key, snapshot lookup of the old entry, old-entry XDR serialization for rent size, a footprint-map lookup to rediscover `AccessType`, and finally pushing a change that `soroban_proto_any::extract_ledger_effects` will ignore when `read_only == true` and no TTL increase occurred. For soroswap's steady-state footprint shape, roughly half the footprint is read-only; replacing the general "change for every footprint key" path with an enforcing-apply effect/rent extractor that only serializes read-write entries and read-only entries with actual TTL increases should remove a large fraction of the `write xdr` and map-lookup work while preserving deterministic output.

## Trigger

Run the current soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py`, `soroswap`, `TX=2000`, `T=8`) with the Tracy trace from `ai-summary/CURRENT_STATE.md`. Inspect `write xdr` under `applyLedger`: the current trace has 1,071.500 ms of apply-window overlap across 132,898 events, with a 74.389 ms hottest-thread overlap, and the source shows every successful invoke builds full ledger-change records for read-only and read-write footprint entries before most read-only records are discarded.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:41-53` — `InvokeHostFunctionResult::ledger_changes` is documented as containing an entry for every input-footprint item, including no-ops.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` iterates all `storage.map` entries and materializes encoded keys, old-entry sizes, new-entry values, and TTL changes.
- `src/rust/src/soroban_proto_any.rs:478-488` — successful apply immediately reduces `ledger_changes` to rent changes and modified ledger entries for the C++ bridge output.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` drops read-only changes except for TTL changes that produce a synthetic TTL entry.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:654-765` — C++ apply consumes only `out.modified_ledger_entries` to upsert or erase ledger state; no-op read-only ledger-change records are not consumed here.

## Evidence

The target is a descendant of the measured apply path: C++ `InvokeHostFunctionOpFrame::invokeHostFunction` calls the Rust bridge from `doParallelApply`, and `soroban_proto_any::invoke_host_function_or_maybe_panic` constructs `InvokeHostFunctionOutput` before returning to `recordStorageChanges`. The soroswap trace shows `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:61` with 764.103 ms self-time and 1,071.500 ms apply-window overlap; in the largest apply windows, generic host/storage work dominates worker time (`storage get` 847.114 ms overlap, `ScVal to Val` 721.780 ms, `obj_cmp` 669.669 ms), so removing redundant post-invoke serialization from every transaction is plausibly above the 3% Medium floor. This is broader than the prior rejected `metered-xdr-size-for-rent` idea: it avoids constructing whole no-op read-only `LedgerEntryChange` records, not just replacing one temporary old-entry XDR buffer.

## Anti-Evidence

The generic `LedgerEntryChange` vector is also used by recording/simulation paths, so the optimization should be limited to enforcing apply output or should introduce a separate compact effect/rent extraction path rather than changing recording-mode semantics. Metering is consensus-visible: skipping metered XDR work changes `cpu_insns` and `mem_bytes`, so a PoC must either deliberately gate the new behavior by protocol or add compatibility charges if exact p26 metering must remain. Read-only entries can still matter when `extend_ttl` raises live-until ledgers, so the compact path must detect and emit those TTL rent/effect records before skipping any read-only entry.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `ai-summary/fail/transactions`, `ai-summary/success/transactions`, or cross-subsystem fail/success records
**Failed At**: reviewer

### Trace Summary

The claimed materialization path is real: a successful enforcing Soroban invoke builds `Storage`, finishes the host, calls `get_ledger_changes`, and returns a `LedgerEntryChange` for every `storage.map` item. The Rust bridge then immediately reduces those changes to rent changes and modified ledger-entry buffers, and C++ apply consumes only `modified_ledger_entries`, so no-op read-only changes are not needed as embedder output. However, the expensive parts of this materialization use p26 metered XDR serialization, and the resulting `cpu_insns` and `mem_bytes` are returned to C++ for resource-limit decisions. Skipping the no-op read-only records in the current protocol would therefore alter protocol-visible metering and can change whether a near-limit transaction succeeds.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:41-53` — `InvokeHostFunctionResult::ledger_changes` explicitly includes every input-footprint item, even no-ops.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` iterates all `storage.map` entries, serializes the key for every entry, serializes the old entry for every existing entry to compute rent size, checks the footprint access type, and only serializes a new value for read-write entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:329-365` — `extract_rent_changes` filters out no-op rent changes only after the full `LedgerEntryChange` has already been built.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-521` — enforcing `invoke_host_function` decodes inputs, clones the initial storage map, runs the host, and calls `get_ledger_changes` on success before returning to the Rust bridge.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — initial storage construction adds missing footprint keys into `storage.map`, so `get_ledger_changes` sees present and absent read-only/read-write footprint entries uniformly.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-572,594-642` — TTL extension mutates the storage map only when live-until actually increases, which is the read-only case a compact extractor would still need to preserve.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` charges `ContractCostType::ValSer` through the XDR writer; removing serialization removes budget charges as well as physical work.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:60-80,369-372` — `ValSer` uses per-write iterations plus byte inputs and has a non-zero CPU constant term, so charge count is observable in `cpu_insns`.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` discards read-only changes except TTL increases that are converted into synthetic `TtlEntry` ledger-entry buffers.
- `src/rust/src/soroban_proto_any.rs:478-488` — successful bridge output computes rent changes, rent fee, and modified ledger entries from `res.ledger_changes`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-590,603-635` — C++ invokes the Rust bridge and checks returned `cpu_insns`/`mem_bytes` against transaction and network limits on failures.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-765` — C++ applies only `out.modified_ledger_entries`; read-only no-op `LedgerEntryChange` records never cross this boundary as ledger effects.

### Why It Failed

The inefficiency exists, but the proposed current-protocol optimization is not correctness-preserving. In p26, the no-op read-only materialization is not just output formatting: its `metered_write_xdr` calls contribute exact `ValSer` budget iterations and byte inputs, and the bridge exposes the consumed CPU and memory to C++ resource-limit checks. A compact extractor that skips key/old-entry serialization for unchanged read-only entries would lower `cpu_insns` and `mem_bytes`, potentially changing `INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED` outcomes for transactions near their declared instruction or memory limits.

Adding compatibility charges is not a simple fix for the stated mechanism. Exact p26 compatibility would need to reproduce the same recursive XDR write charge pattern, including the non-zero per-write `ValSer` constant term, without actually writing the XDR; traversing the XDR shape just to charge it would retain much of the targeted work and collapses back toward the previously smaller "counting writer" class of optimization. A protocol-gated compact output path could be designed for a future recalibrated cost model, but that is not a viable current soroswap apply-time optimization under this objective's Medium threshold.

### Lesson Learned

Soroban enforcing-output records can be semantically redundant for the C++ embedder while still being part of protocol-visible p26 metering. Ledger-change extraction optimizations must first separate removable physical output work from required budget charges; otherwise they risk changing consensus-visible resource-limit behavior rather than merely reducing apply time.
