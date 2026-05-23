# H025: Batch Two-Key MeteredOrdMap Insert for Reserve Writeback in Native Pool Swap

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: <0.5% soroswap apply-time reduction; sub-Medium and rejected under objective threshold
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `call_native_soroswap_pool_swap` writes the two updated reserves (instance-storage keys `2`
and `3`) back to the pair's instance storage map, it should persist both updates to the
`InstanceStorageMap` with a single internal traversal/allocation cycle, since both keys are known
statically, the surrounding `with_mut_instance_storage` already holds an exclusive borrow, and the
two writes are committed atomically as part of the same swap success path.

## Mechanism

The current code performs two independent `MeteredOrdMap::insert` calls
(`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1260-1266`):

```rust
self.with_mut_instance_storage(|s| {
    let k0 = Val::from_u32(2).to_val();
    let k1 = Val::from_u32(3).to_val();
    s.map = s.map.insert(k0, new_reserve_0_val, self)?;
    s.map = s.map.insert(k1, new_reserve_1_val, self)?;
    Ok(())
})?;
```

Each `MeteredOrdMap::insert`
(`src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225`) performs:
- One `charge_access(1, ctx)` (MemCpy + access charge).
- One `find(&key, ctx)` binary search (Compare<Val> charges + comparator work).
- One `from_exact_iter` rebuild that allocates a fresh `Vec<(K, V)>` of length `n` and clones every
  unchanged entry (plus the replaced entry).

For a 5–6 entry pool instance-storage map, the dominant cost per insert is the new-Vec allocation
and the per-entry shallow clones. A hypothetical `insert_pair_known_positions` that performs both
key lookups, then materializes a single new `Vec<(K, V)>` with both replacements applied in one
allocation/copy pass would remove: one access charge, one binary-search comparator pass, and one
length-`n` Vec allocation + `n` shallow clones per swap.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on the next-protocol soroswap
workload (`soroswap, TX=2000, T=8`). Every accepted native pool swap currently performs two
back-to-back `MeteredOrdMap::insert` calls at line 1263–1264.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1260-1266` — the consecutive
  `insert(k0, ..)` then `insert(k1, ..)` calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225` — `insert` implementation
  showing the per-call allocate-and-clone-everything cost.

## Evidence

The Tracy CSV from
`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`
shows `new map` self-time at 350.83 ms aggregate (3.41%) and `map lookup` self-time at 373.79 ms
(3.63%). These zones include all `MeteredOrdMap` construction/lookup across the host. The
pair-reserve-writeback subset would be ~14k inserts (~7,000 swaps × 2 inserts) plus their
binary-search lookups.

## Anti-Evidence

The per-swap removable work is bounded by:
- One redundant `charge_access`: ~50 ns of CPU charge work.
- One redundant `find()` binary search on a 5-entry sorted Vec: ~3 comparator calls × ~200 ns =
  ~600 ns.
- One redundant `Vec<(K, V)>` allocation + 5 shallow clones: ~1.5 µs allocator + ~5 × 50 ns clone
  = ~1.8 µs.

Total per-swap removable physical work: ~2.5 µs. With ~7,000 native pool swaps per soroswap apply
window across 70 ledgers and 8-way cluster parallelism, the wall-time reduction is
`7,000 × 2.5 µs / 8 / 70 = 0.031 µs per ledger`. Even taking the more generous "no parallelism
amortization within a single ledger's pool-bearing cluster" assumption, the total aggregate wall
time saved across the benchmark is `7,000 × 2.5 µs / 8 ≈ 2.2 ms` against a 215-millisecond
soroswap median apply window — about **0.001%** of apply time, three orders of magnitude below
the 1% benchmark-noise floor and four below the 3% Medium threshold.

Additionally, p26 metering protocol-visibly charges `charge_access(1)` once per insert and
comparator/`MemCpy` charges once per `find`. A safe `insert_pair_known_positions` that physically
collapses the work but preserves protocol-visible budget counts must replay those charges manually,
leaving only the bare Vec allocation/copy savings (~1.8 µs/swap) — the same Low ceiling, just
implemented at higher complexity.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Adjacent fail entries
(`002-in-place-storage-map-mutation.md`, `002-specialize-val-key-metered-map-lookups.md`) target
*generic* `MeteredOrdMap` insert/lookup specialization; this hypothesis targets the *specific*
two-consecutive-inserts pattern in the native pool reserve writeback.

### Why It Failed

Projected impact is sub-0.01% apply-time reduction — three orders of magnitude below the
objective's 3% Medium acceptance floor and well below the 1% benchmark-noise floor. The removable
work per swap (one `charge_access`, one binary-search comparator pass, one Vec allocation + 5
shallow clones) totals ~2.5 µs; the call count (~7,000 swaps × 1 saved insert) and 8-way parallel
apply normalize this to ~2 ms wall against a 215 ms apply window. p26 metering also forces a
correct `insert_pair_known_positions` implementation to replay the otherwise-removable
`charge_access`/`MemCpy`/comparator charges to preserve protocol-visible budget counts, capping
removable physical work even lower.

### Lesson Learned

Within-swap pool-reserve writeback batching follows the same sub-Medium pattern as
`fail/004-static-wasm-hash-skip-instance-retrieve-in-pool-code-ttl-extend.md` and
`fail/023-deduplicate-instance-lookup-in-extend-current-instance-and-code-ttl.md`: a single
removable per-swap operation (one allocation, one charge, one comparator pass) on a low call count
(<10k events per benchmark) is fundamentally incapable of clearing Medium even before subtracting
mandatory replayed metering charges. Future map-write optimizations on the native pool path must
either change the *number* of writes per swap (impossible — both reserves must be updated) or fold
the writes into a broader-scope multi-frame redesign that also removes adjacent dispatch/auth/event
work.
