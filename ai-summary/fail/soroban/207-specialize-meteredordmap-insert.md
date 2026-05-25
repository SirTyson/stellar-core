# H207: Specialize MeteredOrdMap::insert to Use Direct Vec::insert

**Date**: 2026-05-25
**Subsystem**: soroban
**Severity**: Medium (claimed; investigated and rejected)
**Impact**: reduce `new map` construction cost per `MeteredOrdMap::insert` by
  replacing the take/chain/skip-then-collect rebuild with a single
  `Vec::insert` at the known position
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`MeteredOrdMap::insert` should perform a single position lookup, allocate
a single new backing `Vec` of size `len + 1`, and insert/replace the
element with one contiguous memmove. The minimum work for a sorted-Vec
insert at known position `pos` is: one allocation of size `len+1`, one
memcpy of `[0..pos]`, one element write, one memcpy of `[pos..len]`. The
metering charges for the allocation and copies should be preserved.

## Mechanism

The current implementation (`host/metered_map.rs:196-225`) uses:

```rust
let init = self.map.iter().take(insert_pos).cloned();
let fini = self.map.iter().skip(insert_pos).cloned();
let iter = init.chain([(key, value)]).chain(fini);
Self::from_exact_iter(iter, ctx)
```

`from_exact_iter` (line 144) does `iter.collect::<Vec<_>>()`, then
`charge_deep_clone`, then `from_map` (which walks the sorted output
verifying ascending order via `Compare::compare` between every adjacent
pair — a second N-element pass with N-1 comparison budget charges).

The DEVIATION: the chain-of-iterators construction and the post-collect
sort-order verification do work that is not strictly necessary when the
caller already knows the insert position from `find()`. A specialized
insert-at-known-position would build the Vec directly and skip the
re-validation walk (since by construction the result IS sorted: prefix
+ new key (at correct position) + suffix).

## Trigger

Trace zone `new map` (host/metered_map.rs:148) shows 183,555 calls /
394M ns self = 2.14µs/call. After 8-way cluster normalization and 71
ledgers: 394M / 8 / 71 = 694µs/ledger = **0.33% of 207ms baseline**.

The `new map` zone covers all `from_exact_iter` callers including
`insert`, `remove`, `from_map`, and explicit map constructors
(`map_new_from_slices`, etc.). The `insert` callers come from durable
storage writes, instance storage updates, and `HostMap` updates.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225` —
  `MeteredOrdMap::insert` chain-collect pattern
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-166` —
  `from_exact_iter` collect + charge_deep_clone + from_map
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:115-138` —
  `from_map` sort-order verification walk that runs even when called from
  insert/remove that produce by-construction sorted output

## Evidence

- 183,555 `new map` calls in the soroswap trace
- 2.14µs/call average; the `from_map` sort-order walk charges
  `Compare<K>` per adjacent pair (N-1 charges per insert into a size-N
  map)
- Storage maps in enforcing mode for soroswap contain ~5-15 footprint
  entries; each persistent storage `put` triggers a rebuild
- The current chain-of-iterators construction requires the compiler to
  fuse three iterator adaptors into the `collect()` loop; even with
  perfect inlining the per-element overhead exceeds a flat memcpy

## Anti-Evidence (and why this fails)

1. **Sub-Medium ceiling.** Full elimination of `new map` self-time would
   save 0.33% of apply, which is below the 1% Low floor and well below
   the 3% Medium threshold. The realistic recoverable slice (just the
   chain/collect overhead minus the actual memcpy work) is a small
   fraction of that 0.33% — likely 0.05-0.15%, comfortably in
   benchmark noise.

2. **Metering preservation forces the comparison walk.** The
   `from_map` sort-order walk charges `<Ctx as Compare<K>>::compare`
   per adjacent pair. Skipping this walk reduces the charge count by
   `N-1` per insert, which IS protocol-visible (changes `Budget`
   accounting per insert). Preserving metering requires replaying the
   exact same `Compare` charges — at which point the comparison work
   itself (which is the bulk of the walk's cost) must also be done.
   This is the same protocol-metering blocker as fail #015
   (`015-init-storage-map-per-invoke-clone-elimination.md`) and
   fail #015 (`002-index-host-storage-map-lookups.md`).

3. **`from_map` is also used by external entry points.** Removing the
   sort-order walk from `from_map` would weaken invariants for callers
   that construct from untrusted input (e.g., `ScMap` → `HostMap`
   conversion). A specialized `insert_at_known_position` would be a new
   API, which works, but the metering-preservation rule above still
   bounds the recoverable cost.

4. **The actual hot fraction is even smaller.** Soroswap with native
   pool raw instance storage (accepted baseline) routes pool reads and
   reserve writes through fixed `ScMap` access, not through
   `MeteredOrdMap::insert` on durable storage. The remaining hot users
   are SAC balance writes (per swap: 2 SAC transfers × 2 balance
   writes = 4 inserts/swap × ~125 swaps/cluster = ~500 inserts/cluster
   /ledger). At 2µs/insert × 500 = 1ms/cluster/ledger; after 8-way
   normalization the saving from a perfect rewrite is ≈0.06% of apply.

5. **Modern Rust iterators are already efficient.** The chained
   take/chain/skip pattern is a standard Rust idiom that LLVM inlines
   into a single tight loop with stack-allocated state. The actual
   pessimization vs `Vec::insert` is small: one extra branch per
   element to dispatch between init/middle/fini sub-iterators.

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — direct specialization of `MeteredOrdMap::insert` (as
opposed to the H002 indexed read fast path in fail
`002-index-host-storage-map-lookups.md`, or the CoW
`init_storage_map` variants in fail
`002-cow-invoke-storage-snapshot.md` / fail #015) was not previously
written up. However, the relevant metering and sizing meta-patterns
already capture the underlying blockers.

### Why It Failed

The `new map` zone totals 0.33% of apply after cluster normalization;
the recoverable slice (after preserving the `from_map` sort-order
`Compare` charges that are protocol-visible) is sub-noise. Modern Rust
iterator chaining is efficient enough that the structural improvement
over `Vec::insert` is small, and the metering charges that DO matter
must be replayed regardless of the rebuild shape.

### Lesson Learned

For `MeteredOrdMap` rebuild-style micro-optimizations: the
sort-order verification walk in `from_map` is a metering-protected
charge sequence (one `Compare` per adjacent pair). Removing or
shortening that walk is protocol-visible. Specialized
insert-at-known-position can avoid the iterator-chain overhead but
NOT the metering charges. Project against the `new map` zone's
post-cluster-normalization total (0.33% in soroswap) before writing
up; this zone is structurally below 1% Low even under perfect
elimination. Add this to meta-pattern #14 alongside
`commitChangesToLedgerTxn` (0.14%), `getAllEntries` (0.083%), etc.
