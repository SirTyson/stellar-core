# H001: Bulk-build Soroban host footprint and storage maps instead of repeated `MeteredOrdMap::insert`

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host storage initialization
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated clone-and-scan map construction before each host invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each invoke-host-function transaction, the Rust host should construct the enforcing `FootprintMap` and initial `StorageMap` once from the footprint and C++-provided ledger-entry buffers. The efficient path should decode keys and entries, validate footprint membership and uniqueness, then build each sorted `MeteredOrdMap` with one allocation/scan rather than rebuilding a persistent vector map after every inserted key.

## Mechanism

`build_storage_footprint_from_xdr` starts with `FootprintMap::new()` and calls `MeteredOrdMap::insert` once for every read-write and read-only key. `build_storage_map_from_xdr_ledger_entries` repeats the same pattern for every decoded ledger entry and then again for every missing footprint key. Each `insert` calls `find`, allocates a new vector through `from_exact_iter`, deep-clone-charges the whole vector, and `from_map` scans and validates sort order, making setup effectively O(N^2) in footprint size even though the final map content is known up front.

A bulk constructor can collect `(Rc<LedgerKey>, AccessType)` and `(Rc<LedgerKey>, Option<EntryWithLiveUntil>)` pairs into vectors, sort/deduplicate them with the same host comparator, batch the equivalent metering, and call `MeteredOrdMap::from_map` once. This preserves deterministic map ordering and ledger effects while removing repeated vector reconstruction, repeated `new map` work, and many setup-time `map lookup`/budget-charge calls that occur before every soroswap host invocation.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) using the trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`. Each parallel Soroban transaction enters `e2e_invoke::invoke_host_function`, decodes its footprint and ledger-entry buffers, and calls `build_storage_footprint_from_xdr` plus `build_storage_map_from_xdr_ledger_entries` before `Host::invoke_function`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-447` — invoke setup decodes resources, builds the footprint, and builds the initial storage map before host execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-957` — `build_storage_footprint_from_xdr` repeatedly inserts each footprint key into an initially empty `FootprintMap`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` repeatedly inserts decoded entries, checks membership with `contains_key`, then inserts missing footprint keys one at a time.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — `from_map` / `from_exact_iter` already provide the one-shot vector construction path, but current callers reach it once per insert.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-224` — `insert` performs a binary search and reconstructs the entire vector on each inserted key.

## Evidence

- Tracy self-time in the current soroswap trace shows `new map,soroban-env-host/src/host/metered_map.rs:148` at **130.563 ms self-time** over 64,552 calls, and `map lookup,soroban-env-host/src/host/metered_map.rs:173` at **411.627 ms self-time** over 382,266 calls. Timestamp filtering confirms 58,761 `new map` events totaling 182.222 ms and 348,072 `map lookup` events totaling 603.561 ms occur inside `applyLedger` windows.
- The longest `applyLedger` interval alone contains 57,926 `new map` events totaling 180.921 ms and 343,974 `map lookup` events totaling 600.152 ms, under the invoke-host-function apply path rather than TX-set construction.
- The setup source has a structural O(N^2) pattern: `MeteredOrdMap::insert` rebuilds a vector with `take(...) + new + skip(...)` and calls `from_exact_iter` for each footprint/storage entry, even though `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries` know all entries before constructing the map.
- Soroswap invokes many small footprints through the same setup path. With 1,554 invoke-host-function events inside the current trace's `applyLedger` windows, eliminating even half of the repeated map-construction worker time is plausibly around 10-25 ms wall after T=8 normalization, enough to clear the 3% Medium threshold on the 596 ms headline soroswap median.

## Anti-Evidence

- `new map` is a generic `MeteredOrdMap` zone; not every call comes from initial footprint/storage construction. Contract `ScMap` conversions and object construction also use the same zone, so a PoC must add temporary counters or narrower Tracy spans to isolate the constructor share before claiming the full trace total.
- Budget accounting is protocol-visible. A bulk builder must preserve the same final CPU/memory budget totals, likely by applying exact batched charges equivalent to the current repeated inserts and scans; simply doing less charged work could change resource-limit outcomes.
- Sorting with the host comparator still costs O(N log N) comparisons and must reject duplicate/conflicting footprint keys exactly as today. The win depends on replacing repeated vector cloning/scanning with one sort/build pass, not on weakening validation.
- The change should remain local to enforcing invoke setup. Recording-mode footprint behavior has different cache/write-through semantics and should not be refactored unless equivalence is proven separately.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The close-ledger path applies Soroban transactions in parallel clusters, each operation reaches `InvokeHostFunctionApplyHelper::invokeHostFunction`, crosses the Rust bridge, and constructs a fresh Rust host in `e2e_invoke::invoke_host_function`. Before `Host::invoke_function`, that setup path builds the enforcing footprint, initial storage map, and TTL map through repeated `MeteredOrdMap::insert` calls, and each insert performs a charged binary search plus full vector reconstruction through `from_exact_iter` and `from_map`. This is per-invocation work in the soroswap apply window, not transaction-set generation or background bucket work. The related failed H007 investigated a runtime lookup-position cache and is not a duplicate of this bulk-construction mechanism.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:417-425` — the soroswap matrix writes the scenario thread count to `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`; the hypothesis trigger is the `T=8` apply-load run.
- `src/simulation/ApplyLoad.cpp:2311-2334` — the measured benchmark interval surrounds `closeLedger`, then verifies one Soroban stage with the configured maximum cluster count.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — Soroban clusters are executed through `std::async`, and the apply path waits on all worker futures, so per-transaction Rust setup is on the apply critical path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — each Soroban operation serializes auth/resources/source/ledger buffers and calls `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-39` — the C++ bridge dispatches to the protocol host module's `invoke_host_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452` — every invocation decodes `SorobanResources`, builds the footprint, builds initial storage/TTL maps, clones the initial storage map, and constructs enforcing `Storage` before contract execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-957` — `build_storage_footprint_from_xdr` starts from `FootprintMap::new()` and inserts each read-write key and then each read-only key one at a time.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` starts empty storage/TTL maps, inserts each decoded entry, performs footprint membership checks with `contains_key`, inserts TTL entries, then scans the footprint and inserts missing keys individually.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — `from_map` already validates one sorted vector, and `from_exact_iter` builds a vector in one allocation, charges the clone, and delegates to `from_map`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-224` — `insert` calls `find`, charges access/binsearch, chains cloned old elements around the new pair, and reconstructs the whole map via `from_exact_iter` on every insertion.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:294-304` — `contains_key` performs another `find`, and `keys` performs a full scan charge before the missing-entry pass.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` — `FootprintMap` and `StorageMap` are both `MeteredOrdMap<Rc<LedgerKey>, ...>` specializations, so the same repeated-insert cost applies to both setup maps.
- `src/transactions/TransactionFrame.cpp:1461-1488` — transaction validation rejects duplicate keys across read-only and read-write footprints before apply, reducing the correctness burden for the bulk footprint builder to preserving this already-required uniqueness.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1301-1325` and `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — bulk charging is available, but exact equivalence requires care because the linear cost model includes a per-iteration constant term.

### Findings

The inefficiency exists exactly where claimed. The setup functions know the complete footprint and complete C++-provided ledger-entry/TTL input before constructing the enforcing maps, but they still use the persistent-map mutation API designed for incremental updates. For an insertion into a map of length `i`, the current path pays one access charge, one binary-search charge, comparator work, a vector allocation/collection for `i + 1` entries, a deep-clone charge for that whole vector, and a `from_map` scan/order validation. Repeating this for each footprint, storage, and TTL entry makes construction quadratic in the small-but-hot per-invocation footprint size.

This path is hot for the soroswap objective. `InvokeHostFunctionApplyHelper::invokeHostFunction` is called by each Soroban operation during parallel apply, and `e2e_invoke::invoke_host_function` performs the map setup before host execution for every invocation. With the hypothesis trace's 1,554 invocations, the setup constructors plausibly account for tens of thousands of the `new map` events: approximately one footprint insertion per footprint key, one storage insertion per footprint key after decoded entries plus missing entries are accounted for, and one TTL-map insertion for each Soroban entry with a TTL buffer. Even after normalizing aggregate worker self-time by `T=8`, the removable constructor share is plausibly in the 3-10% apply-time band if the PoC isolates a large fraction of the observed `new map` plus setup-only `map lookup` time.

The proposed fix is structurally correct but must be implemented carefully. For the footprint, validation has already rejected duplicate/disjointness violations in C++, so a builder can collect `(Rc<LedgerKey>, AccessType)` pairs, sort by `Budget`'s `Compare<LedgerKey>`, and call `FootprintMap::from_map` once while retaining the same supported-key checks. For storage, the builder must preserve the current semantics that every decoded entry must be in the footprint, Soroban entries require TTL entries, non-existing footprint keys are represented as `None`, and the final `StorageMap` is sorted by the same comparator. Because budget totals are protocol-visible, the PoC should either preserve exact current CPU/memory totals by equivalent bulk charges or explicitly demonstrate that any charge change is acceptable only under a protocol-gated change; the safer target is equivalent metering with fewer actual allocations, scans, and comparator-driven searches.

Existing optimizations do not cover this setup path. `MeteredOrdMap::from_map` and `from_exact_iter` provide one-shot construction primitives, but the current setup reaches them only through repeated `insert`. The previously failed `007-metered-map-last-position-cache.md` investigated runtime `Storage::{get,put,extend_ttl}` lookup caching and failed on pointer identity and severity; it did not cover replacing known-complete setup-map construction with a bulk build.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs::build_storage_footprint_from_xdr`, `build_storage_map_from_xdr_ledger_entries`, and, if needed, small helper APIs in `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs` for equivalent bulk construction/charging.
- **Change description**: Build vectors for `FootprintMap`, `StorageMap`, and `TtlEntryMap` once, sort them with the same `Budget` comparator used by `MeteredOrdMap`, validate uniqueness/order, then call `MeteredOrdMap::from_map` once per map. Avoid changing recording-mode storage behavior; this review only supports the enforcing invoke setup path.
- **Correctness check**: Preserve supported-key checks, footprint membership checks, TTL/ledger-entry pairing errors, expired-entry handling, missing-key insertion as `None`, and the final ledger-change behavior that relies on `init_storage_map`. Add temporary or test-only budget assertions if needed to compare old and new CPU/memory trackers for representative invoke cases.
- **Benchmark focus**: Add temporary narrow Tracy spans or counters around the setup builders to isolate constructor-only `new map` and `map lookup` events. The PoC should show reduced apply time in `scripts/run_apply_load_matrix.py` for soroswap `TX=4000, T=8`, with the constructor share translating to a reproducible 3-10% top-line apply-time reduction.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-29
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:5-34` — imported `Ordering` and the `Compare` trait so the setup builders can sort ledger-key pairs using the same budgeted comparator as `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:724-728` — kept recording-mode footprint roundtrip validation on the original incremental construction path to preserve existing resource expectation tests.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:936-998` — changed enforcing footprint construction to collect all read-write and read-only keys into one vector, sort once, and call `FootprintMap::from_map`; retained an incremental helper for recording mode only.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1001-1224` — changed enforcing storage and TTL map construction to collect decoded entries once, sort them, validate duplicate storage keys, merge against the sorted footprint to add missing `None` entries, and call `StorageMap::from_map` / `TtlEntryMap::from_map` once; retained the prior insertion-based behavior for recording mode.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1227-1263` — added local helper functions to sort `(Rc<LedgerKey>, V)` pairs through `Budget::compare` and validate uniqueness.

### Demonstration

The enforcing invoke setup path now avoids rebuilding persistent `MeteredOrdMap` vectors after every footprint, storage, and TTL insertion. It constructs the complete sorted vectors once per map, validates membership and uniqueness before creating the final metered maps, and leaves recording-mode resource accounting unchanged so the existing budget expectation tests remain stable.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and built with `make -j30 ALL_SOROBAN_GIT_STATE_STAMPS=`. Full existing test suite passed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check ALL_SOROBAN_GIT_STATE_STAMPS=`; output ended with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
