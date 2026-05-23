# H002: Rc-Key Enforcing Storage Side Indices

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing per-invocation deep `LedgerKey` cloning and hashing from enforcing-mode storage side-index construction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For enforcing-mode Soroban invocation, storage and footprint lookups should keep the accepted indexed fast path: every access must still enforce the declared footprint, return the same entries, preserve the same absent-key behavior, and charge the same lookup/access budget as the current `get_at_known_position` and `insert_at_known_position` paths. Building those unmetered helper indices should not deep-clone every `LedgerKey` after the footprint and storage maps have already been built from `Rc<LedgerKey>` entries.

## Mechanism

`Storage::with_enforcing_footprint_and_map` currently constructs two `HashMap<LedgerKey, usize>` side indices by iterating the `FootprintMap` and `StorageMap` and cloning `(**k)` for every key. Those maps already own stable `Rc<LedgerKey>` keys for the lifetime of the `Storage`, and the side index is only an unmetered physical accelerator used to find known positions before replaying the legacy lookup charge. Switching the side indices to `HashMap<Rc<LedgerKey>, usize>` (or building an equivalent Rc-backed/borrowed sidecar during map construction) avoids an O(n) second pass of deep `LedgerKey` cloning and hashing per host invocation while preserving deterministic lookup results and existing budget replay.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current next-protocol soroswap workload. Every successful invoke transaction calls `e2e_invoke::invoke_host_function`, builds a footprint and storage map from C++ XDR inputs, then immediately constructs enforcing-mode side indices before `Host::invoke_function`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-452` — constructs `Storage::with_enforcing_footprint_and_map` for every enforcing host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1013-1037` — builds the `FootprintMap` from cloned XDR footprint keys.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1039-1055` — starts storage-map construction from encoded ledger and TTL entries before the enforcing `Storage` wrapper adds side indices.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — builds `HashMap<LedgerKey, usize>` by deep-cloning every footprint and storage key.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:288-315,609-623` — consumes the side indices for footprint enforcement and storage replacement.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:325-347,356-360` — known-position lookup/insert paths already replay the legacy budget charge after the side index finds a position.

## Evidence

The current soroswap trace confirms this setup is on the measured apply path: `invoke_host_function` at `e2e_invoke.rs:488` has 828,296,243 ns self-time and 7,851 in-`applyLedger` invocations totaling 10,738,945,725 ns; `map lookup indexed` at `metered_map.rs:330` has 839,562 in-`applyLedger` events totaling 585,969,208 ns, showing the side index is heavily used after construction. The source-level structural issue is not in the indexed lookup itself but in its per-invocation construction: after XDR decoding and metered `Rc<LedgerKey>` allocation have already happened, the side-index constructor performs another full unmetered deep clone/hash of the same keys into owned `LedgerKey` hash maps.

## Anti-Evidence

The accepted storage lookup fast path depends on exact missing-key and present-key behavior, so the index replacement must not accidentally switch to pointer identity or skip the existing `idx.len() == map.len()` safety checks. The reviewer should verify that `Rc<LedgerKey>` hashing/equality remains value-based for lookup by the current key handles, that the memory overhead of retaining `Rc` keys is lower than deep-cloned `LedgerKey`s for the soroswap footprint mix, and that the construction saving is large enough after accounting for any extra reference-count traffic.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The enforcing invocation path still builds a `FootprintMap` and `StorageMap` from XDR, then passes them to `Storage::with_enforcing_footprint_and_map` for each host invocation. In the current p26 source, however, that constructor only stores the supplied footprint and map; it does not build `HashMap<LedgerKey, usize>` side indices or deep-clone the `Rc<LedgerKey>` keys. Subsequent footprint and storage operations use the ordinary `MeteredOrdMap` binary-search lookup/insert path, and the searched source contains no `get_at_known_position`, `insert_at_known_position`, or indexed map API to consume the hypothesized side indices.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-452` — enforcing invocation builds `storage_map`, clones it for later diffing, and constructs `Storage::with_enforcing_footprint_and_map`; no side-index construction happens at this call site.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-956` — footprint construction clones XDR keys into `Rc<LedgerKey>` entries for the `FootprintMap`, but does not build a second unmetered hash index.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — storage-map construction decodes ledger/TTL entries, checks footprint membership, inserts present entries, and inserts `None` for absent footprint keys using `Rc::clone(k)`; this is not the claimed deep-cloned side-index pass.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:230-239` — `Storage::with_enforcing_footprint_and_map` simply returns `Storage { mode: Enforcing, footprint, map }`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154,252-357` — read/write enforcement calls `Footprint::enforce_access` and `StorageMap::get`/`insert` directly through `MeteredOrdMap`, not through a storage-owned side index.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — `MeteredOrdMap` exposes the generic metered `find`, `insert`, and `get` path; the searched current tree has no known-position lookup/insert helpers.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md` — related accepted storage lookup optimization exists, but it specialized validated-key binary search and was only Low severity; it is not this claimed side-index construction issue.

### Why It Failed

The central inefficiency does not exist in the code under review. There is no per-invocation `HashMap<LedgerKey, usize>` side-index construction in `Storage::with_enforcing_footprint_and_map`, so switching such an index to `HashMap<Rc<LedgerKey>, usize>` cannot remove any work from the current apply path. The trace labels cited by the hypothesis (`map lookup indexed`, `get_at_known_position`, `insert_at_known_position`) appear to describe a different or transient source state, not the current p26 submodule checked by this review.

### Lesson Learned

Storage-map optimization hypotheses must be anchored to the current checked-out p26 source, not only to prior trace labels or accepted-summary terminology. If a future branch reintroduces side indices, review should first confirm the constructor and consumer APIs exist in that branch before estimating clone/hash savings.
