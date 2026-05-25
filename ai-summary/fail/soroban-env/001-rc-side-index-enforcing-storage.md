# H001: Rc-Key Enforcing Storage Side Indices

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated deep `LedgerKey` clones from enforcing storage setup
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Constructing enforcing `Storage` for a Soroban invocation should build its lookup side indices without deep-cloning every `LedgerKey` in both the footprint and storage maps. The side indices only need stable ownership of keys for the lifetime of the `Storage`, so they should be keyed by `Rc<LedgerKey>` (or an equivalent borrowed/owned wrapper) and populated with `Rc::clone` from the already-owned sorted maps while preserving the same `Hash`/`Eq` semantics for lookups by `&LedgerKey`.

## Mechanism

`Storage::with_enforcing_footprint_and_map` currently builds `HashMap<LedgerKey, usize>` side indices at `storage.rs:245-267` by executing `(**k).clone()` for every key in both `footprint.0.map` and `map.map`. This is unmetered physical work inside the hot `invoke_host_function` setup path; it is not needed for protocol-visible budget compatibility because the indices are an internal acceleration structure and all metered map charges are replayed later through `get_at_known_position`, `charge_lookup`, and `insert_at_known_position`. Replacing the indices with `HashMap<Rc<LedgerKey>, usize>` removes repeated deep XDR-key copies while preserving deterministic key order, lookup results, and the existing exact budget profile.

## Trigger

Run the current `soroswap` apply-load scenario (`TX=2000,T=8`) on a next-protocol build. Every successful Soroban invocation enters `e2e_invoke::invoke_host_function`, builds a footprint/storage map from XDR, then calls `Storage::with_enforcing_footprint_and_map`; the current trace records 8,705 `invoke_host_function` calls and all but 18 are inside `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:180-194` — side-index field types are `Option<Rc<HashMap<LedgerKey, usize>>>`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — index construction deep-clones every footprint and storage key.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:288-320,323-353,418-457` — indexed lookup/replace call sites can continue to query by borrowed key while replaying the same budget charges.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — enforcing storage construction is in the current `invoke_host_function` setup zone.

## Evidence

The current soroswap Tracy trace
`/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`
shows `invoke_host_function` at `soroban-env-host/src/e2e_invoke.rs:639` with 976,933,609 ns self-time across 8,705 calls, with 8,687 calls contained in `applyLedger`. It also shows the indexed-storage fast path is heavily exercised (`map lookup indexed`, `host/metered_map.rs:330`, 532,467,330 ns self / 931,436 calls; `storage get`, `storage.rs:329`, 266,675,391 ns self / 357,046 calls), so the side indices are on the critical Soroban apply path rather than a dead structure. Source inspection shows the index keys are cloned only to own them in the `HashMap`; the storage and footprint maps already own `Rc<LedgerKey>` entries whose lifetimes match the `Storage`.

This is related to an older failed note named `002-rc-key-enforcing-storage-side-indices`, but that investigation failed because the target side-index code did not exist in the checkout it reviewed. The current source now contains the exact `HashMap<LedgerKey, usize>` side-index construction and lookup sites, so the premise has changed.

## Anti-Evidence

The trace does not isolate side-index construction in its own child zone, so `invoke_host_function` self-time is only an upper bound. Hashing the keys and allocating the hash tables remain, and the change must confirm that `HashMap<Rc<LedgerKey>, usize>` supports borrowed lookup without adding extra hashing indirection or changing equality. If focused instrumentation shows the deep-clone fraction is only a small part of the 976 ms wrapper self-time, this could fall below the 3% Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban-env/031-rc-key-side-indices-in-with-enforcing-footprint.md`
**Failed At**: reviewer

### Trace Summary

The referenced p26 source currently has enforcing-mode side-index fields typed as `Option<Rc<HashMap<LedgerKey, usize>>>` and constructs them in `Storage::with_enforcing_footprint_and_map` by deep-cloning each `LedgerKey` from the footprint and storage maps. `e2e_invoke::invoke_host_function` constructs this enforcing `Storage` once per Soroban invocation after building the footprint and storage map from XDR, so the code path is real. However, the exact same proposed change to use `HashMap<Rc<LedgerKey>, usize>` and populate it with `Rc::clone(k)` was already investigated in fail record H031 and rejected as below the objective severity threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:180-194` — enforcing side-index fields are currently keyed by owned `LedgerKey`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — constructor builds both side indices with `(**k).clone()`, matching the claimed mechanism.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:288-320,323-353,418-457` — indexed footprint/storage lookup and replace paths query by borrowed key and would be the same call sites as the prior H031 proposal.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — invocation setup calls `Storage::with_enforcing_footprint_and_map` before host construction.
- `ai-summary/fail/soroban-env/031-rc-key-side-indices-in-with-enforcing-footprint.md:1-100` — prior investigation covers the same mechanism, trigger, target constructor, `Rc<LedgerKey>` map type, and impact estimate.

### Why It Failed

This is not novel. The prior H031 failure record already investigated this exact optimization and concluded that, while the shallow-clone substitution is safe and mechanically plausible, the per-invocation construction cost is projected at roughly 0.2-0.4% apply-time improvement, below both the 3% Medium threshold and the objective's accepted severity floor.

### Lesson Learned

For this objective, second-order refinements to already-added storage side indices need focused evidence showing a Medium-scale apply-time impact before being reintroduced; otherwise they duplicate the H031 finding and remain below threshold.
