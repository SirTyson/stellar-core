# H014: Replace eager `init_storage_map` whole-map clone with lazy per-key snapshot in `e2e_invoke`

**Date**: 2026-05-03
**Subsystem**: soroban-env (rust)
**Severity**: Low (below objective threshold)
**Impact**: per-invocation storage-map snapshot allocation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`e2e_invoke::invoke_host_function` snapshots the initial `storage_map` so
that `get_ledger_changes` can compute the post-execution diff against the
ingress state. The expected behavior of an optimized path is to avoid
materializing a full deep clone of the storage map for invocations whose
write set is small relative to the read footprint, because
`get_ledger_changes` only needs the original value of an entry that was
*actually* mutated. For read-only entries that the contract never writes,
the original is identical to the final value and no comparison is required.

## Mechanism

Today, `e2e_invoke.rs:449` performs
`let init_storage_map = storage_map.metered_clone(budget)?;` immediately
after building the enforcing footprint and storage map. This eagerly
deep-clones the entire `MeteredOrdMap<Rc<LedgerKey>, Option<EntryWithLiveUntil>, Budget>`
including every read-only entry. `get_ledger_changes` later wraps this
clone in `StorageMapSnapshotSource` and consults it only when iterating
post-execution storage entries that may have changed. The deviation is
that read-only entries — which form the majority of typical soroswap
footprints — are cloned unnecessarily on every invocation. A lazy snapshot
that only clones an entry on first mutation (copy-on-write undo log) would
preserve `get_ledger_changes` semantics while skipping the per-invocation
clone of unmodified entries.

## Trigger

Every `e2e_invoke::invoke_host_function` call performs the eager clone.
Soroswap workloads execute ≈10,000 invocations per benchmark window with
typical footprints of 10–30 entries (largely read-only `CONTRACT_DATA` and
`CONTRACT_CODE`), so the clone runs ≈10K times per ledger.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:449` —
  `let init_storage_map = storage_map.metered_clone(budget)?;`
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:494-507` —
  `StorageMapSnapshotSource { budget, map: &init_storage_map }` is fed to
  `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs` —
  `MeteredClone` implementation that charges `MemCpy` per cloned entry
  and is protocol-visible.
- `src/rust/soroban/p26/soroban-env-host/src/host/ledger_info_helper.rs` /
  `e2e_invoke.rs::get_ledger_changes` — diff computation that consumes
  `init_storage_map`.

## Evidence

- `MeteredOrdMap::metered_clone` charges `MemCpy` per (key, value) pair
  plus the heap-alloc cost of the new Vec; for a 20-entry footprint the
  charge sequence is dominated by 20 `MemCpy` invocations on
  `Option<EntryWithLiveUntil>`.
- For typical soroswap swaps, the write set is ≤5 entries (token balances
  for source and destination, pair reserves) while the full footprint is
  often 15–25 entries — so 60–80% of the clone work corresponds to
  read-only entries that are never modified.
- The CoW pattern is well-known and would not require XDR re-decoding —
  the original `Rc<LedgerEntry>` already held in `storage_map` could be
  used directly as the snapshot value.

## Anti-Evidence

- **Per-entry physical clone work is small.** `Option<EntryWithLiveUntil>`
  cloning is dominated by `Rc::clone` (refcount bump, ~10 ns each) and a
  few discriminant copies. For a typical soroswap footprint of ~20 entries,
  per-invocation clone physical cost is ≈20 × 50 ns = 1 µs. With ~10,000
  invocations per ledger, total physical clone time is ~10 ms; with
  8-thread apply parallelism, wall savings ≈ 1.25 ms ≈ 0.46% of the 272 ms
  soroswap apply baseline. This is below the 1% noise floor and far below
  the 3% Medium severity threshold.
- **Mandatory `MemCpy` budget charges remain.** `MeteredOrdMap::metered_clone`
  charges a protocol-visible `MemCpy` (cpu `const_term=42`) per cloned
  (K, V) pair. Per the established meta-pattern (fail summary item 2:
  "Protocol-visible `const_term` makes charge-count changes infeasible"),
  reducing the number of `MemCpy` charges shifts `cpu_insns` and breaks
  exact-budget tests. To preserve budget compatibility, a CoW
  implementation would still need to replay the same per-entry `MemCpy`
  charges, leaving only the small physical Rc-clone work as removable —
  which is below the noise floor as computed above.
- **Protocol-gating to next-protocol does not raise the impact** to the
  Medium tier: even at a generous 100% of the physical clone cost being
  removable, the upper bound is ≈0.5% of apply time, well below 3%.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior `001-lazy-storage-rollback-snapshot`
(which targeted *per-frame* `push_context` rollback clones during
intra-invocation host frame entry, not the *e2e_invoke top-level*
ingress snapshot used by `get_ledger_changes`); also distinct from
`002-in-place-storage-map-mutation` (which targeted storage-map writes,
not the snapshot construction).

### Why It Failed

The physical Rc-clone cost of the `init_storage_map = storage_map.metered_clone()`
call in `e2e_invoke.rs:449` is small per invocation (~1 µs) because
`Option<EntryWithLiveUntil>` cloning bottoms out in `Rc::clone` rather
than deep value clones. Aggregate physical savings are ≈10 ms total Tracy
time → ≈1.25 ms wall at 8-way apply parallelism → ≈0.46% of soroswap apply
time, well below the objective's 1% noise floor and 3% Medium threshold.
Mandatory protocol-visible `MemCpy` charges further constrain a
budget-preserving implementation to replay the same charge count, leaving
only the physical work as removable.

### Lesson Learned

For storage-snapshot optimizations in `e2e_invoke`, separately measure
(a) physical clone work (typically dominated by `Rc::clone` for
`Option<EntryWithLiveUntil>` and therefore small) and (b) mandatory
protocol-visible `MemCpy` budget charges. The aggregate
`metered_clone` Tracy signal is dominated by (b) — which cannot be
removed within a single protocol version — leaving only the small (a)
component as a candidate. Soroban storage-snapshot hypotheses for this
objective need either a cheaper *protocol-gated* charging scheme that
itself clears the Medium floor (cf. accepted `001-protocol-gated-host-metering-coalescing`)
or a workload where the per-invocation footprint is dramatically larger
than typical soroswap.
