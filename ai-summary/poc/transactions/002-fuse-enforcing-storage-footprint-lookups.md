# H002: Fuse Enforcing Storage Footprint and Entry Lookups

**Date**: 2026-04-28
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by removing duplicate `MeteredOrdMap` searches on every host storage access
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

In enforcing mode, Soroban storage access should keep rejecting keys outside the declared footprint, reject writes to read-only keys, return the same missing-entry errors, preserve budget metering, and produce the same ledger changes. The storage map should still contain exactly the entries implied by the validated footprint and C++ ledger-entry buffers, but reads, writes, `has`, and TTL extension should not perform two independent ordered-map searches for the same key when one deterministic lookup can establish both access permission and entry value.

## Mechanism

`Storage::try_get_full_helper` calls `prepare_read_only_access`, which performs `Footprint::enforce_access` and a `MeteredOrdMap::get` over the footprint map; it then immediately performs another `MeteredOrdMap::get` over the storage map for the same key. Writes similarly call `Footprint::enforce_access` and then `StorageMap::insert`, which performs another lookup/rebuild. In the current soroswap trace, the apply-descendant storage access zones overlap `applyLedger` heavily (`storage get` 392.563 ms total overlap, `storage has` 100.753 ms, `storage put` 67.946 ms, and `extend key` 112.316 ms), while the shared `map lookup` zone at `metered_map.rs:173` has 411.627 ms self-time and 603.561 ms of events overlapping apply windows; fusing access type and entry value in enforcing storage should remove one lookup per storage access without changing execution order or parallelism.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap`, 4000 tx, 8 clusters) with the Tracy trace from `ai-summary/CURRENT_STATE.md`. The issue triggers during every contract storage read, existence check, write, or TTL extension inside `Host::invoke_function`, especially the repeated SAC/router/pair storage accesses in each swap transaction.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — `Footprint::enforce_access` searches the footprint map to validate read/write permissions.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `Storage::try_get_full_helper` enforces footprint access and then searches `StorageMap` for the same key.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — writes perform the access lookup and then `StorageMap::insert`, which performs its own binary search.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:421-428` — `has` funnels through the same double-lookup read path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — enforcing-mode `FootprintMap` and `StorageMap` are built from the same validated footprint, making a combined enforcing view possible after input construction.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — `MeteredOrdMap::find` is the hot `map lookup` zone used by both maps.

## Evidence

This is distinct from the existing reviewed `001-bulk-build-soroban-storage-maps.md`, which targets repeated immutable-map inserts during host input construction. The runtime storage path still performs duplicate access and entry lookups after construction: enforcing mode has no read-through snapshot behavior, and `build_storage_map_from_xdr_ledger_entries` ensures the storage map is populated for all footprint keys, including missing entries. Tracy confirms runtime relevance inside `applyLedger`: `map lookup` has 382,266 events and 411.627 ms self-time in the trace, with 348,072 events overlapping apply windows; `storage get` alone has 89,580 events and 392.563 ms of apply-window overlap. A combined enforcing map entry such as `(AccessType, Option<EntryWithLiveUntil>)`, or an enforcing-only lookup helper that returns both permission and value from one sorted structure, should reduce repeated binary searches, comparison charges, and cache misses while preserving deterministic sorted-key behavior.

## Anti-Evidence

Recording mode has different semantics: it records footprint access, reads through a snapshot, and may insert newly discovered keys, so the fused path should be limited to `FootprintMode::Enforcing` unless recording semantics are redesigned separately. Metering must also be preserved: removing a lookup changes the number of `MemCpy`/comparison charges unless the replacement explicitly charges the same consensus-visible budget units, or unless the protocol deliberately accepts the metering change in a future version. If most `map lookup` self-time is from input map construction already covered by the reviewed bulk-builder hypothesis, the incremental runtime-only gain may fall below the Medium threshold and should be measured independently.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

Protocol-23+ Soroban parallel apply enters `InvokeHostFunctionOpFrame::doParallelApply`, serializes the transaction footprint and ledger-entry buffers, and calls the Rust bridge for every invoke-host-function operation. The p26 host builds a `FootprintMap` from `SorobanResources.footprint`, builds a `StorageMap` from the supplied ledger entries, fills missing footprint keys with `None`, and then constructs enforcing `Storage` from both maps. Runtime host storage calls then repeatedly validate access through the footprint map and immediately search or update the storage map with the same key, so the claimed duplicate ordered-map lookup exists on the measured apply path.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply serializes host-function inputs and calls `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `doParallelApply` confirms this path is the protocol-23+ parallel Soroban apply path used by soroswap.
- `src/rust/src/soroban_invoke.rs:7-60` and `src/rust/src/soroban_proto_any.rs:310-354` — bridge dispatch selects the protocol-specific host and forwards ledger-entry, TTL-entry, auth, and resource buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-452` — `invoke_host_function` builds the enforcing footprint and storage map before invoking the host.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — the footprint map and storage map are constructed over the same key universe; missing footprint keys are inserted into storage as `None`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — enforcing access performs a `FootprintMap::get` lookup and rejects out-of-footprint or read-only write access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `try_get_full_helper` performs the access lookup and then a second `StorageMap::get`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — writes perform the access lookup and then `StorageMap::insert`, which performs its own binary search.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:421-428` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-574` — `has` and TTL extension funnel through the same read path, with TTL extension possibly adding another storage-map insert.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — output ledger-change construction iterates storage entries and looks up the matching footprint access type again.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2315,2390-2415` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-560` — contract `has/get/put/del/extend_ttl` host functions and contract-data writes all use the storage helpers above.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242,294-300` — `get`, `contains_key`, and `insert` all enter the hot `map lookup` binary-search zone.

### Findings

The inefficiency exists and is in the soroswap apply hot path. In enforcing mode, `build_storage_map_from_xdr_ledger_entries` verifies every supplied entry belongs to the footprint and then inserts `None` for every footprint key not present in ledger-entry buffers, so a storage lookup that misses the storage map is already treated as an internal invariant error after the footprint check. This means an enforcing-only combined entry such as `(AccessType, Option<EntryWithLiveUntil>)` can preserve the observable distinction between out-of-footprint (`ExceededLimit`), read-only write (`ExceededLimit`), missing in-footprint value (`MissingValue`/`Ok(None)` depending on caller), and storage invariant failure.

The proposed change is correctness-sensitive but feasible. Recording mode cannot share the same fast path because it mutates the footprint, reads through a snapshot, and may have footprint-only entries after rollback, but normal apply constructs `FootprintMode::Enforcing` and never needs recording semantics. The PoC should either keep a compatibility `Footprint` view for tracing/testutils/recording code or derive the needed access-type iteration from a new enforcing storage map without changing ledger-change ordering.

The severity clears the Medium review threshold as a PoC candidate. The current accepted baseline has a best soroswap median apply time of 596.381 ms, so the 3% floor is about 17.9 ms wall-clock. The cited `map lookup` zone has 603.561 ms of apply-window aggregate overlap, and storage `get`/`has`/`put`/TTL zones account for a large fraction of that path; removing one ordered-map search from each enforcing storage access and from post-invoke ledger-change access-type lookup plausibly recovers more than 144 ms aggregate worker work, which is enough to exceed the floor at the configured 8-cluster parallelism if the duplicate footprint lookups are well distributed.

The main risk is consensus-visible budget accounting. `MeteredOrdMap::find` charges `MemCpy` for the binary search and invokes metered key comparisons, so removing a lookup also changes measured CPU/memory unless this is accepted as a protocol-versioned metering change or explicitly recharged. This does not make the hypothesis non-viable, but the PoC must treat metering as a first-class correctness check rather than simply deleting the footprint lookup.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/storage.rs`, `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs`, and any helper/testutils/trace callers that directly inspect `Storage::footprint` or `Storage::map`.
- **Change description**: Add an enforcing-only storage representation that stores access type beside the optional ledger entry for each key, or add an enforcing lookup/update helper that searches one sorted key structure and returns both `AccessType` and `Option<EntryWithLiveUntil>`. Limit the fast path to `FootprintMode::Enforcing`; preserve recording-mode behavior.
- **Correctness check**: Preserve out-of-footprint errors, read-only write errors, in-footprint missing-entry behavior, TTL extension behavior, ledger-change `read_only` flags, restored-key handling, and deterministic sorted iteration order. Pay special attention to budget outputs from `InvokeHostFunctionOpFrame` because removing `MeteredOrdMap` searches changes `cpu_insns`/`mem_bytes` unless deliberately gated as a p26 metering update or compatibility charges are added.
- **Benchmark focus**: Measure soroswap `apply_time` across repeated `scripts/run_apply_load_matrix.py` runs and compare Tracy `map lookup`, `storage get`, `storage has`, `storage put`, `extend key`, and `get_ledger_changes` descendants. The required target is at least a reproducible 3% median apply-time reduction, roughly 18 ms wall-clock from the current 596.381 ms baseline.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:320-343` — added `Storage::get_access_type`, which reuses the enforcing footprint side index when available and falls back to the legacy `FootprintMap::get` path otherwise. The indexed path preserves the previous missing-key lookup charge and returns the same `Option<AccessType>` shape used by ledger-change generation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:193-258` — changed `get_ledger_changes` to ask `Storage` for each key's access type instead of searching `storage.footprint.0` directly. This removes the remaining post-invoke footprint binary search for enforcing storage while preserving read-only flags, restored-key handling, storage iteration order, and recording-mode fallback behavior.

### Demonstration

The p26 host now routes the ledger-change access-type lookup through the same enforcing side index used by runtime storage access, so the storage entry iteration no longer performs an independent footprint-map binary search for every output entry. Combined with the existing enforcing side-index fast paths for storage reads, writes, and TTL updates in the p26 baseline, this demonstrates the proposed fused lookup strategy without changing execution order, ledger output ordering, or parallelism.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built with `make -j30`, and ran `env NUM_PARTITIONS=30 make check`. The full test command completed successfully; the tail included p26 Rust host tests passing (`750 passed; 0 failed; 2 ignored`) and the final make-check harness reported all tests passed.

---

## Final Review — Needs Revision

**Date**: 2026-04-30
**Final review by**: gpt-5.5, high

### What Needs Fixing

The PoC handoff is not reproducible because the source changes are left as dirty working-tree state in the `src/rust/soroban/p26` submodule. Final review found the outer branch at `poc/002-fuse-enforcing-storage-footprint-lookups`, but the p26 submodule remains at baseline commit `e6728024aed9bb39cac3c2f247579bfac5b8bc79` with uncommitted modifications to:

- `soroban-env-host/src/e2e_invoke.rs`
- `soroban-env-host/src/storage.rs`

The outer repo therefore only records `Subproject commit e6728024...-dirty`, not a concrete submodule SHA that can be fetched, checked out, tested, benchmarked, or promoted to `soroswap-perf`. The performance final-review handoff model explicitly requires the PoC source changes to be committed on the PoC submodule branch and recorded by an outer gitlink commit before final review measures anything.

### Revision Instructions

Commit the p26 submodule changes to `github.com/SirTyson/rs-soroban-env` on branch `poc/002-fuse-enforcing-storage-footprint-lookups`, then update the outer `stellar-core` branch `poc/002-fuse-enforcing-storage-footprint-lookups` with a gitlink bump pointing at that committed submodule SHA. Re-run the required build and `env NUM_PARTITIONS=30 make check` from a clean checkout, update the PoC notes with the committed outer SHA and p26 SHA, and ensure both `git status` in the outer repo and `git -C src/rust/soroban/p26 status` are clean before handing back to final review.

Do not change `ai-summary/CURRENT_STATE.md` for this revision; the current accepted baseline remains the reference until a reproducible committed PoC is benchmarked and confirmed.

### Checks Passed So Far

The hypothesis file and CURRENT_STATE baseline were readable, the claimed source files exist, and the dirty diff matches the PoC's stated implementation area (`storage.rs` and `e2e_invoke.rs`). No benchmark or full test validation was performed in final review because measuring uncommitted submodule state would violate the reproducible-handoff requirement.

---

## Revision (PoC handoff fix)

**Date**: 2026-04-30
**Revised by**: claude-opus-4.7, high

### Fix Summary

Committed the previously dirty p26 submodule changes so the PoC is
reproducible from a clean checkout:

- **p26 submodule branch**: `poc/002-fuse-enforcing-storage-footprint-lookups`
  on `https://github.com/SirTyson/rs-soroban-env`
  - Commit SHA: `a3fad963d283fe6092225a7d2f88947b6cb4d1e5`
  - Parent baseline SHA: `e6728024aed9bb39cac3c2f247579bfac5b8bc79`
    (`viable success 001-typed-sac-balance-storage-fast-path`, already on fork)
  - Diff: same `soroban-env-host/src/storage.rs` and
    `soroban-env-host/src/e2e_invoke.rs` changes as the original POC_PASS.

- **Outer stellar-core branch**: `poc/002-fuse-enforcing-storage-footprint-lookups`
  on `https://github.com/SirTyson/stellar-core`
  - Commit SHA: `0a9f3f2ab0256e8d3960405c6924b1a9bb88e21e`
  - Parent: `197d41b2ce4bf695ad24693702a9b96401f1063e`
    (`viable poc 001-bulk-build-soroban-storage-maps`)
  - Single change: gitlink bump of `src/rust/soroban/p26` to `a3fad963`.

### Reproducibility Verification

After committing both branches, ran from a clean working tree:

- `git status` (outer): clean (only the unrelated `ai-summary` symlink
  state appears, which is a worktree-local symlink pointing at the
  shared `ai-summary/` directory and is not part of this PoC).
- `git -C src/rust/soroban/p26 status`: clean.
- `make -j$(nproc)`: build succeeded (Tracy-enabled configure preserved).
- `env NUM_PARTITIONS=$(nproc) STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`:
  all tests passed (`PASS: test/selftest-nopg`, `PASS: test/check-nondet`,
  `All 2 tests passed`); p26 Rust host doc/integration tests passed cleanly.

The PoC source change is unchanged from the original POC_PASS notes;
only the packaging/handoff (committed branches + gitlink bump) was fixed.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-354` — added `Storage::get_access_type`, an enforcing-mode side-index lookup helper for footprint access types. It uses the precomputed enforcing footprint index when available, preserves the legacy lookup/access budget charges through `get_at_known_position`/`charge_lookup`, returns the same `Option<AccessType>` shape, and falls back to `FootprintMap::get` for recording/test-constructed storage.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:253` — changed `get_ledger_changes` to call `storage.get_access_type(key, budget)` instead of directly searching `storage.footprint.0` for every storage entry. This removes the post-invoke duplicate footprint binary search while preserving read-only flags, restored-key handling, deterministic storage iteration order, and recording-mode fallback behavior.

### Demonstration

The p26 host now reuses the enforcing footprint side index for ledger-change access-type lookup, so output materialization no longer performs an independent `MeteredOrdMap` binary search over the footprint for each storage entry. Together with the existing enforcing side-index fast paths for runtime storage reads, writes, and TTL updates in this baseline, the PoC demonstrates fused enforcing storage/footprint lookup without changing execution order, ledger output ordering, or parallelism.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built with `make -j $(nproc)`, and ran `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`. The full test command completed successfully; the tail included p26 Rust host tests passing (`750 passed; 0 failed; 2 ignored`) and the final make-check harness reported `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.

### Handoff Notes

The source changes are intentionally left in the `src/rust/soroban/p26` submodule working tree as the PoC deliverable. No commits were created because the PoC instructions for this run explicitly say the orchestrator handles commits.
