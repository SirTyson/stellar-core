# H002: Cache decoded input entry XDR sizes for ledger-change rent accounting

**Date**: 2026-04-29
**Subsystem**: ledger / Soroban host invocation output
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing redundant per-footprint XDR serialization in successful host invocations
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each successful Soroban invocation, the Rust host must return the same ledger changes, rent size fields, TTL changes, events, and result XDR as today. Computing `old_entry_size_bytes_for_rent` should not require reserializing every old ledger entry when the embedder already supplied the exact encoded `LedgerEntry` bytes used to build the initial storage map.

## Mechanism

`build_storage_map_from_xdr_ledger_entries` decodes every input `LedgerEntry` from an encoded buffer, inserts only `(Rc<LedgerEntry>, live_until)` into `StorageMap`, and discards the original encoded length. Later, `get_ledger_changes` asks the initial snapshot for the old entry and serializes that same old entry back to XDR only to compute `old_entry_size_bytes_for_rent`. Carrying the input encoded length alongside the initial storage entry, or providing a parallel snapshot map of initial rent sizes, would avoid this redundant old-entry serialization while leaving the emitted `encoded_new_value` and `encoded_key` bytes unchanged.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with successful invoke-host-function transactions that touch multiple footprint entries. Each transaction decodes its input ledger entries into a host storage map, executes, then serializes old entries again during ledger-change construction even when those entries were supplied as XDR bytes moments earlier.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` — `invoke_host_function` decodes resources, builds the storage map from encoded ledger entries, clones the initial map, and later uses it as the snapshot.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes `entry_buf` but stores only the decoded entry and TTL, not the original XDR size.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes `old_entry` at lines 227-231 solely to compute old rent size, then serializes read-write new entries separately for output at lines 264-272.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `StorageMapSnapshotSource` currently exposes only `(entry, live_until)`, so it cannot answer "initial encoded size" without reserialization.

## Evidence

In the current soroswap Tracy trace, the `write xdr` zone is fully in-scope: `132,898` of `132,907` events overlap `applyLedger`, accounting for `1,071,500,405 ns` of overlapped time. `invoke_host_function` and `Host::invoke_function` are also descendants of `applyLedger`; the trace shows `invoke_host_function` total time `9,871,843,503 ns` across 3,335 calls and `write xdr` self-time `764,102,894 ns`. The code path demonstrates at least one avoidable serialization per old entry in the footprint: unlike `encoded_new_value`, the old entry bytes are not returned to C++ and are only used for `entry_size_for_rent`.

## Anti-Evidence

Not all `write xdr` time is removable: keys, result `ScVal`, events, and new read-write values still need encoded output, and contract-code rent size uses `entry_size_for_rent` semantics rather than raw XDR length. A safe PoC must preserve metering semantics or consciously account for any budget-charge differences, because `metered_write_xdr` currently charges `ValSer` while it serializes.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/ledger`, `success/ledger`, or cross-subsystem verdict directories

### Trace Summary

The successful C++ apply path materializes each footprint entry as XDR with `toCxxBuf`, passes those buffers to Rust, Rust decodes them into a `StorageMap`, clones that map as the initial snapshot, and then `get_ledger_changes` reserializes every existing old entry only to compute `old_entry_size_bytes_for_rent`. This redundant serialization runs after `host.invoke_function` succeeds and before rent extraction and modified-entry extraction, so it is inside `invoke_host_function` and the measured `applyLedger` window. The size cache is semantically available at ingress, and for non-code entries the cached XDR length is exactly the rent size input; for contract code it is still the correct XDR-size component passed to `entry_size_for_rent`.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` walks read-only and read-write footprint keys, serializes each existing ledger entry with `toCxxBuf`, records `entrySize`, and pushes the encoded `LedgerEntry`/TTL buffers into `mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584` — `invokeHostFunction` passes `mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs` through the Rust bridge on every successful Soroban operation attempt.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:430-487` — the bridge dispatches to the protocol-specific host, then computes rent changes and modified ledger effects from the returned `LedgerEntryChange` records.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` — enforcing-mode `invoke_host_function` decodes resources, builds the storage map from the encoded input entries, and clones the initial map for later snapshot comparisons.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` has `entry_buf.as_ref().len()` available immediately before decoding each `LedgerEntry`, but returns only `StorageMap` and `TtlEntryMap`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes each `old_entry` into a temporary `Vec` solely to pass `buf.len()` into `entry_size_for_rent`; the buffer is not emitted or reused.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:324-386` — `extract_rent_changes` consumes only the old/new rent-size fields and TTL deltas, while `entry_size_for_rent` explicitly expects a caller-provided XDR size and only adds Wasm memory cost for contract-code entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:86-90` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `SnapshotSource` currently returns only `(entry, live_until)`, so `StorageMapSnapshotSource` cannot provide the cached ingress size without an API or side-map extension.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` and `src/rust/soroban/p26/soroban-env-host/src/budget.rs:71-79,369-372,725-728` — the redundant serialization also charges `ValSer`; a PoC must deliberately handle the resulting budget-counter/resource-limit semantics.

### Findings

The inefficiency exists and is in a hot path. For every successful invoke-host-function transaction, C++ has already produced canonical XDR buffers for the footprint entries before Rust host execution. Rust decodes those buffers, discards their lengths, and later serializes the same old entries again even when the old entry is read-only, unchanged, classic/non-TTL, or about to be zeroed as an auto-restored old size. In the soroswap swap generator, a typical swap footprint contains five read-only entries and five read-write entries, so the waste is repeated many times per transaction; contract-code read-only entries can make the avoidable old-entry serialization materially larger than a scalar-key micro-optimization.

The proposed size cache is correct for rent-size computation if it carries the encoded `LedgerEntry` length, not merely a post-`entry_size_for_rent` value. `entry_size_for_rent` returns the raw XDR size for accounts, trustlines, contract data, and other non-code entries; for contract code it adds Wasm memory cost to that same raw XDR size. Therefore a cached ingress XDR length can replace `buf.len()` without changing `old_entry_size_bytes_for_rent`, while leaving key encoding, new read-write value encoding, result encoding, event encoding, and output ledger effects unchanged.

The main correctness constraint is metering. The current old-entry `metered_write_xdr` calls contribute `ValSer` CPU/memory charges and can affect `out.cpu_insns`, `out.mem_bytes`, and resource-limit failure behavior. If the intended optimization removes serialization entirely, the PoC must either be protocol-semantics-aware about the lower metered cost or add an explicit replacement charge policy that is accepted as preserving the intended metering semantics. A single charge by cached total length would preserve total `ValSer` input but not necessarily the historical per-`WriteXdr` iteration count because `ValSer` has nonzero constant CPU and memory terms, so this must be measured and reviewed rather than hidden.

The projected impact is plausibly Medium. The trace cited by the hypothesis puts in-scope `write xdr` work around one second total / 764 ms self-time across 3,335 invocations, and this target removes an entire old-entry write per existing footprint entry rather than only preallocating buffers. Since keys, events, results, and new values remain mandatory, the PoC still must prove a reproducible 3%+ apply-time reduction, but the removable share is large enough to pass review.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs`, especially `build_storage_map_from_xdr_ledger_entries`, `StorageMapSnapshotSource`, and `get_ledger_changes`; mirror the change across supported protocol host copies if the repository's protocol-generation workflow requires manual or generated synchronization.
- **Change description**: carry each decoded input ledger entry's original XDR length alongside the initial storage snapshot, expose it to `get_ledger_changes`, and compute old rent size from the cached length plus `entry_size_for_rent` instead of serializing `old_entry` to a temporary buffer. Preserve the existing serialization of `encoded_key`, read-write `encoded_new_value`, result values, events, and constructed TTL entries.
- **Correctness check**: verify identical ledger changes, modified ledger entries, TTL changes, rent fees, events, and result XDR for successful invoke-host-function tests. Explicitly document and test the intended budget behavior: either counters/resource-limit outcomes remain equivalent by an accepted replacement charge mechanism, or the metering delta is deliberate and protocol-safe for the targeted protocol version.
- **Benchmark focus**: run the soroswap apply-load matrix repeatedly and compare top-line `applyLedger` time plus Tracy `write xdr` self/total time inside `invoke_host_function`. The expected improvement should come from fewer old-entry `write xdr` events and lower per-success invocation time; the finding should only proceed if the median apply-time reduction is at least 3%.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:40,185-247,454-518,738-848,985-1081` — added `InitialEntryXdrSizeMap`, returned cached input `LedgerEntry` XDR lengths from `build_storage_map_from_xdr_ledger_entries`, threaded the map through enforcing and recording invoke flows, and used it in `get_ledger_changes` to compute old rent size without serializing old entries. The fallback serialization path remains for callers without a cached size map.
- `src/rust/soroban/p26/soroban-env-host/src/test/e2e_tests.rs:1400,1538,1609,2048,2115,2415,2558,2698,2835,2958` — updated only recording-mode instruction-count expectations that decreased after removing old-entry `ValSer` serialization from the ledger-change path.

### Demonstration

The optimization carries the canonical XDR length that Rust receives from C++ while decoding the initial storage map, then reuses that length for `old_entry_size_bytes_for_rent`. This removes the redundant temporary `Vec` allocation and `metered_write_xdr` call for every existing old footprint entry during successful ledger-change construction, while preserving key encoding, new read-write entry encoding, rent-size calculation, TTL changes, events, result XDR, and modified ledger effects.

The budget delta is deliberate for p26: successful recording-mode resource snapshots now charge fewer instructions because the old-entry `ValSer` work is no longer performed. Tests were adjusted only for the numeric instruction baselines that reflect this cheaper execution path.

### Test Results

Configured and built with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j30`. Final full regression run `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completed with exit status 0; `test/selftest-nopg` and `test/check-nondet` passed, including p26 `soroban-env-host` results of 750 passed, 0 failed, 2 ignored, 1 filtered out.

---

## Final Review — Needs Revision

**Date**: 2026-04-30
**Final review by**: gpt-5.5, high

### What Needs Fixing

The PoC handoff is not reproducible in the required final-review model. The outer worktree is on `poc/002-cache-old-entry-xdr-sizes`, but the recorded `src/rust/soroban/p26` gitlink still points at the previous accepted baseline SHA `e6728024aed9bb39cac3c2f247579bfac5b8bc79`, while the actual PoC source changes are uncommitted dirty state inside the detached `p26` submodule:

- `soroban-env-host/src/e2e_invoke.rs`
- `soroban-env-host/src/test/e2e_tests.rs`

Final review cannot run the required clean-checkout build, full `make check`, or three authoritative `scripts/run_apply_load_matrix.py` measurements against uncommitted submodule state. A fresh checkout of the outer branch would not contain the optimization, so any benchmark from this worktree would not be a reproducible validation of the handed-off PoC branch.

### Revision Instructions

Commit the `p26` submodule changes to the `github.com/SirTyson/rs-soroban-env` branch `poc/002-cache-old-entry-xdr-sizes`, then update the outer `stellar-core` gitlink to that submodule commit and commit the outer branch `poc/002-cache-old-entry-xdr-sizes`. The handoff must satisfy all of the following before final review can proceed:

1. `git status --short` in the outer worktree is clean except for orchestrator-managed `ai-summary` artifacts.
2. `git -C src/rust/soroban/p26 status --short` is clean.
3. `git submodule status src/rust/soroban/p26` reports the new committed PoC SHA, not the previous baseline SHA `e6728024aed9bb39cac3c2f247579bfac5b8bc79`.
4. The PoC file records the outer commit SHA and submodule commit SHA/branch used for the handoff.
5. Keep the test edits limited to the budget-number exception already claimed here: only numeric recording-mode instruction baselines may change, with no test logic, fixtures, control flow, assertions, or pass/fail semantics weakened.

Once the committed handoff is available, final review should check out the PoC branch from scratch, update the submodule, verify both worktrees are clean, run the full regression suite, and then run the three non-Tracy matrix benchmarks against `ai-summary/CURRENT_STATE.md`.

### Checks Passed So Far

- Source-level intent appears aligned with the hypothesis: the dirty diff adds `InitialEntryXdrSizeMap`, threads cached ingress `LedgerEntry` XDR sizes into `get_ledger_changes`, and keeps a fallback serialization path for callers without cached sizes.
- The visible test-file edits are only numeric recording-mode instruction-count reductions, matching the narrow budget-number exception shape.
- The prior accepted baseline in `ai-summary/CURRENT_STATE.md` is present and records the reproducible baseline submodule SHA and three authoritative non-Tracy runs needed for later comparison.

---

## PoC Revision

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: claude-opus-4.7, high

### Revision Summary

Addresses the prior "Needs Revision" feedback by committing the previously
dirty submodule state to the paired PoC branches required for reproducible
final review. No source-level changes were made on top of the prior PoC
diff — only the workflow/handoff issue was fixed.

### Handoff SHAs

- **Outer** branch `poc/002-cache-old-entry-xdr-sizes` on
  `github.com/SirTyson/stellar-core` at commit
  `a863ae68b6bdb74c646841e4af5d50fd040f9bdc` (gitlink bump only).
- **Submodule** branch `poc/002-cache-old-entry-xdr-sizes` on
  `github.com/SirTyson/rs-soroban-env` at commit
  `ac6316c2ba689385be61c9590086d65a762d6a9d`, applied on top of the prior
  accepted baseline `e6728024aed9bb39cac3c2f247579bfac5b8bc79`.

### Verification

- `git status --short` in the outer worktree is clean apart from the
  orchestrator-managed `ai-summary` artifacts (the `D ai-summary/...`
  entries reflect the now-untracked `ai-summary` directory and are
  pipeline-managed, not PoC-owned).
- `git -C src/rust/soroban/p26 status --short` is clean.
- `git submodule status src/rust/soroban/p26` reports
  `ac6316c2ba689385be61c9590086d65a762d6a9d` (v26.0.0-3-gac6316c2),
  not the prior baseline SHA.
- The submodule commit contains only the two files identified by final
  review (`soroban-env-host/src/e2e_invoke.rs` and
  `soroban-env-host/src/test/e2e_tests.rs`); test edits remain limited
  to numeric recording-mode instruction-count baselines, preserving all
  control flow and pass/fail assertions.
