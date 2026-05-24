# H012: Replace `soroswap_pool_reserves_updated_scmap` Full Rebuild With In-Place Delta-Only Mutation

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low (below objective severity threshold)
**Impact**: per-swap ScMap allocation reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the native soroswap pool path updates its `reserve_0` /
`reserve_1` slots after a swap, the implementation should mutate only
the two ScMapEntry values whose keys change, leaving the four unchanged
entries (`token_0`, `token_1`, `factory`, …) untouched in memory.
Persisting the modified pool instance to storage should require only
the cost of replacing two i128 values in an `Rc<ScMap>`, not the cost
of constructing a fresh `Vec<ScMapEntry>` of six entries and cloning
every entry into it.

## Mechanism

`soroswap_pool_reserves_updated_scmap` (frame.rs:1414-1448) currently
takes the existing pool-instance ScMap, iterates all six entries, and
builds a brand-new `Vec<ScMapEntry>` cloning every entry — only two of
which are actually changed (the two reserve slots). The resulting
`ScMap` is then passed to `store_contract_instance` which clones it
again as part of the storage write (and `persist_instance_storage` at
frame.rs:2001-2026 may additionally `metered_clone` the
`instance.storage` ScMap before the store). The two-stage clone pattern
means each swap performs 6 `ScMapEntry::metered_clone` calls when only
2 entries actually changed. A delta-only mutation would clone exactly
2 entries (the new reserve `ScMapEntry`s) and reuse the four
unchanged entries via `Rc` sharing or in-place `VecM` index assignment.

## Trigger

Every native soroswap pool swap (~28 per ledger, 70 ledgers/run) calls
`soroswap_pool_reserves_updated_scmap` exactly once, producing a fresh
6-entry ScMap clone.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1414-1448` — `soroswap_pool_reserves_updated_scmap`: full ScMap rebuild that clones every entry.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:2001-2026` — `persist_instance_storage`: the second clone via `instance.storage.metered_clone(self)` for the native pool path.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs` — `store_contract_instance`: the third clone when constructing the storage entry.

## Evidence

- The two reserve `ScVal::I128` updates are the only semantic change per
  swap; the four other entries (`token_0`, `token_1`, `factory`,
  whatever the protocol's pool instance schema dictates) are byte-equal
  before and after.
- ScMapEntry is `(ScVal, ScVal)`; for `ScVal::I128`/`ScVal::Address`
  variants the metered_clone is cheap but still charges
  `Budget::charge(HostMemAlloc, …)` per call.
- The chain produces ~3 full-ScMap clones per swap (rebuild +
  persist_instance_storage clone + store_contract_instance write), each
  cloning 6 ScMapEntries.

## Anti-Evidence

- Per-swap savings (best case): replace 18 ScMapEntry clones with ~6
  (delta-only) → 12 clones eliminated. Each clone ≈ 200 ns budget
  charge + small allocation work ≈ 1 µs total. So ~12 µs/swap aggregate
  worker CPU.
- 28 swaps × 70 ledgers = 1,960 swaps/run → ~24 ms aggregate worker CPU/run.
- Divided by 70 ledgers and 8-way parallelism = **~43 µs/ledger
  serial critical-path** = **0.02% of the 211 ms baseline**. Below the
  1% Low floor by a factor of ~50.
- Additional structural cost: ScMap is held inside an `Rc<VecM<…>>`
  via the `ScMap` newtype; "in-place mutation" requires either
  `Rc::make_mut` (which clones if shared) or a redesign of how
  `instance.storage` is stored. The redesign would touch
  serialization/persistence paths and increase audit surface for
  marginal benefit.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — neither fail summary nor any individual fail file
covers this specific allocation pattern. Closest prior records are
`fail/soroban/001-raw-native-pair-instance-storage.md` (which addressed
the overall native pool storage path and was accepted/landed) and
`fail/soroban/010-hoist-scaddress-from-address-native-pool-swap.md`
(which targeted the *outer* native pool path Address handling, not the
ScMap rebuild inside the reserves updater).

### Why It Failed

The total addressable savings (~24 ms aggregate worker CPU/run, ~0.02%
of apply time after 8-way parallelism normalization) is two orders of
magnitude below the 1% Low floor and three orders of magnitude below
the 3% Medium floor. The fail summary meta-pattern "Sub-µs hot-path
micro-opts blocked by 8-way parallelism normalization" applies
directly: even though the ScMap allocation pattern is genuinely
suboptimal, the per-swap cost is sub-microsecond once `BudgetImpl::charge`
coalescing is factored in (fail summary item 16). The structural cost
of redesigning `instance.storage` to support delta mutation through
shared `Rc<ScMap>` ownership is high relative to the win.

### Lesson Learned

When the native pool path was first proposed, the cost of raw instance
storage rebuild looked large because it was being compared to the
full router→pair Wasm execution path. After the native pool path
landed and that VM cost was removed, the residual rebuild cost shrunk
to micro-op territory. Future hypotheses against the native pool path
need to count the *residual* cost (post-current-baseline), not the
*original* cost relative to a pre-optimization baseline. ScMap and
similar Rc-shared collections look like prime allocation targets, but
the per-entry clone cost is dominated by `Budget::charge` not by the
allocation itself, and per-swap volumes (6 entries × ~28 swaps × 70
ledgers ÷ 8 workers) put aggregate savings deep in the sub-Low bucket.
