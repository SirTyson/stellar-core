# H002: Single-Pass Soroban Ledger-Change Rent and Effect Extraction

**Date**: 2026-05-24
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction in Soroban invoke finish/output path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban invoke, apply should charge the same rent fee, return the same modified ledger entries to C++, preserve the same TTL bump semantics, emit the same events/result hash inputs, and enforce the same resource limits. It should not need to allocate a full `Vec<LedgerEntryChange>` containing read-only/no-op descriptors and then iterate it again to derive rent changes and modified-entry buffers.

## Mechanism

The current bridge finish path first builds a full `Vec<LedgerEntryChange>` in `get_ledger_changes`, then `soroban_proto_any.rs` walks that vector once in `extract_rent_changes` and again in `extract_ledger_effects` to build the actual C++ outputs. For the soroswap workload, many footprint entries are read-only or unchanged except for TTL accounting, while C++ ultimately consumes only rent fee data and `modified_ledger_entries`. A protocol-gated single-pass extractor could walk `storage.map` once, compute rent-change inputs, emit only changed entry buffers/TTL entries, and skip allocating durable read-only/no-op `LedgerEntryChange` structs, while still performing any protocol-required metering and preserving deterministic ordered output.

## Trigger

Run the current protocol-27 soroswap apply-load workload. Each successful invoke reaches `get_ledger_changes` after `Host::invoke_function`, then `soroban_proto_any::invoke_host_function_or_maybe_panic` converts the returned `ledger_changes` into rent changes and modified entries before C++ decodes those modified entries in `InvokeHostFunctionApplyHelper::recordStorageChanges`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-357` — constructs one `LedgerEntryChange` per storage-map entry and encodes keys/new values.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:393-430` — derives rent changes from the full ledger-change vector.
- `src/rust/src/soroban_proto_any.rs:478-499` — calls `extract_rent_changes` and `extract_ledger_effects` as separate passes before returning `InvokeHostFunctionOutput`.
- `src/rust/src/soroban_proto_any.rs:261-301` — extracts only non-read-only new values and changed TTL entries from the full vector.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-767` — C++ consumes only modified ledger-entry buffers and then erases missing RW entries.

## Evidence

The timestamp-filtered soroswap exports place this path inside `applyLedger`: `invoke_host_function` at `soroban-env-host/src/e2e_invoke.rs:488` has 828,296,243 ns self-time and 10,781,064,987 ns total time, while `Host::invoke_function` totals 8,276,651,656 ns, leaving a ~2.50 s aggregate worker envelope for setup/finish/output work. Direct output-related zones are visible but individually sub-threshold: `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:72` totals 147,687,000 ns in apply-window candidates, and C++ `recordStorageChanges` is separately exported at about 98,487,000 ns. The proposed change is larger than either micro-zone: it removes a full intermediate representation and two Rust passes over `ledger_changes`, while keeping the mandatory XDR bytes for changed entries.

## Anti-Evidence

A prior read-only ledger-change materialization idea failed because p26 metering treats some physically redundant XDR work as protocol-visible budget consumption. This hypothesis is only viable if it either remains next-protocol gated or explicitly preserves the required budget charges while removing physical allocation/iteration. The exact removable fraction of the invoke finish envelope is not isolated in the current exports, so a PoC should instrument `get_ledger_changes`, `extract_rent_changes`, and `extract_ledger_effects` separately before expecting the full Medium bound.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as this exact Vec/extraction mechanism; related `002-single-pass-ledger-change-map-diff.md` in the transactions fail summary covered map-probe reduction in `get_ledger_changes`, not this bridge-output extraction path
**Failed At**: reviewer

### Trace Summary

The protocol-23+ Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, constructs an `InvokeHostFunctionParallelApplyHelper`, and runs the common helper sequence: add footprint entries, call the Rust bridge, record modified storage, collect events, consume refundable rent fees, and finalize the success hash. The Rust bridge calls p26 `e2e_invoke::invoke_host_function`, which builds enforcing storage, invokes the host, then calls `get_ledger_changes` to materialize a `Vec<LedgerEntryChange>` for every storage-map/footprint entry. `soroban_proto_any::invoke_host_function_or_maybe_panic` then performs two more Rust passes over that vector: `extract_rent_changes` for `host_compute_rent_fee`, and `extract_ledger_effects` for the C++ `modified_ledger_entries` buffers consumed by `recordStorageChanges`.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — the common helper apply sequence invokes Rust, records returned storage changes, consumes `out.rent_fee`, and finalizes success.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-638` — builds bridge buffers and calls `rust_bridge::invoke_host_function`; output metrics and success state come directly from Rust.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-767` — C++ decodes only `out.modified_ledger_entries`, validates resource limits, upserts returned entries, and erases uncovered RW footprint entries.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:819-831` — C++ consumes the Rust-computed rent fee through the refundable fee tracker.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — parallel Soroban apply constructs the parallel helper used by the soroswap apply path.
- `src/rust/src/bridge.rs:34-55` — the CXX bridge output exposes `modified_ledger_entries` and `rent_fee`, not the intermediate `LedgerEntryChange` vector.
- `src/rust/src/soroban_proto_any.rs:391-487` — the wrapper calls `e2e_invoke::invoke_host_function`, then separately extracts rent changes and ledger effects from `res.ledger_changes`.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` consumes `LedgerEntryChange` values and emits only changed non-read-only entries plus TTL entries whose live-until ledger increased.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:49-61` — `InvokeHostFunctionResult` explicitly documents that `ledger_changes` contains an entry for every input footprint item, including no-ops.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-357` — `get_ledger_changes` performs the mandatory storage walk, old/new rent-size calculation, TTL change detection, restored-entry handling, and changed-entry XDR encoding before pushing one `LedgerEntryChange` per storage-map item.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:393-430` — `extract_rent_changes` builds a second vector containing only rent-relevant changes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-593` — enforcing-mode host invocation builds the storage map, invokes the host, calls `get_ledger_changes` on success, and returns the intermediate vector to the bridge wrapper.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:880-951` — recording mode still returns full ledger changes and uses them to derive resources, so an apply-only fast path would need to preserve this existing API for simulation/recording.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:26-28,245-267` — enforcing storage is an ordered map of `Rc<LedgerKey>` to optional `Rc<LedgerEntry>` plus side indices; the storage walk itself and old/new state lookups remain required.
- `src/rust/soroban/p26/soroban-env-host/src/fees.rs:290-321` — rent fee computation still requires a vector/slice of meaningful `LedgerEntryRentChange` records or an equivalent streaming fee accumulation.

### Why It Failed

The inefficiency exists, but the projected impact does not clear the objective's Medium threshold. A single-pass apply-only extractor could avoid allocating the full `Vec<LedgerEntryChange>` and avoid two linear passes over it, and it could skip storing some encoded keys for entries whose TTL metadata already provides the key hash. However, it cannot remove the dominant required work in this finish path: the storage-map walk, footprint/read-write classification, old-state and TTL metadata lookup, old/new rent-size calculation, metered XDR encoding of changed entries, TTL-entry construction for real extensions, rent fee calculation, event/result output, or C++ decoding/upserting of returned modified entries.

The measured evidence bounds the removable work below the review floor. The cited `write xdr` zone is only 147.7ms of aggregate worker time and includes mandatory changed-entry/result/event encoding, so its removable portion is far below 1% after dividing by T=8. `recordStorageChanges` is C++ work after the Rust output and would not be removed by this change. The related prior `002-single-pass-ledger-change-map-diff.md` record already found a much broader `map lookup` aggregate bound of 1,023ms across 70 apply windows, which is only about 2.51% critical-path before narrowing to the specific extraction loop. This hypothesis removes less than that broader bound, so it falls below the objective's accepted Medium range and must be rejected as below the severity threshold.

### Lesson Learned

`invoke_host_function` minus `Host::invoke_function` is only a broad upper bound on setup/finish work; it includes mandatory bridge, storage, rent, event, and output steps. Ledger-change extraction hypotheses need isolated timing for `get_ledger_changes`, `extract_rent_changes`, and `extract_ledger_effects`, then must divide aggregate worker time by Soroban parallelism before claiming a Medium soroswap apply-time improvement.
