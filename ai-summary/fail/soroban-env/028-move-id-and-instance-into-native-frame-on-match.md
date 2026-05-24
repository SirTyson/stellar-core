# H028: Move (Not Clone) Contract `id` and `instance` Into `Frame::NativeContract` On Match

**Date**: 2026-05-24
**Subsystem**: soroban-env
**Severity**: Low (sub-noise; also blocked by protocol-visible metering)
**Impact**: Removes one `id.metered_clone` and one `instance.metered_clone`
per matched native Soroswap pool getter/swap dispatch
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `Host::call_contract_fn` (p26 `host/frame.rs:783-838`) routes a
matching call into a native Soroswap fast-path, it should be able to *move*
the already-owned `ContractId` and `ScContractInstance` into
`Frame::NativeContract(id, func, args_vec, instance)` instead of cloning
them. The original `id` (a `&ContractId` argument) and `instance` (an
owned `ScContractInstance` from `retrieve_contract_instance_from_storage`)
will be dropped immediately after the function returns; cloning them and
discarding the originals is observable physical work that a careful
refactor could eliminate.

## Mechanism

At `host/frame.rs:864-869`:

```rust
let frame = Frame::NativeContract(
    id.metered_clone(self)?,
    *func,
    args_vec,
    instance.metered_clone(self)?,
);
self.with_frame(frame, || self.call_native_soroswap_pool_getter(getter))
```

Both `metered_clone` calls perform full metered clones of their arguments:

  * `ContractId::metered_clone` — small (`[u8; 32]`) shallow copy + a
    `MemCpy` budget charge.
  * `ScContractInstance::metered_clone` — clones the `executable` enum and
    the `storage: Option<ScMap>` (the pool's instance storage map: 5
    `ScMapEntry`s for the Soroswap pair). Each `ScMapEntry` carries an
    owned `ScVal::Symbol(...)` key (`ScSymbol` is a `BytesM<32>` shallow
    copy) and an owned `ScVal::Address`/`ScVal::I128`/`ScVal::Map` value;
    the i128 reserves are `Copy`-tier but the address entries clone the
    underlying `[u8;32]`. Each clone charges `MemCpy` and `MemAlloc` per
    sub-component.

The original owned `instance` and the borrowed `id` are dropped after
`with_frame` returns, since they are not used downstream. A targeted
refactor could thread ownership: take `id` by value (or accept that
`id_storage_key`/`contract_id` is already owned), and pass `instance` by
value into `try_call_native_*`, then move it into the frame on success or
return it back to the caller on no-match (for the Wasm fallthrough path
that itself needs to consume `instance`).

## Trigger

Apply-load `soroswap` scenario (`TX=2000,T=8`): every matched native
Soroswap pool getter call (`token_0`, `token_1`, `factory`, `get_reserves`,
`k_last`) and every matched native pool `swap` call pays one
`id.metered_clone` plus one `instance.metered_clone` at frame construction.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:864-871`
  (`try_call_native_soroswap_pool_getter` frame construction) — the
  redundant clones.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` near the
  `try_call_native_soroswap_pool_swap` frame construction (same pattern).
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:790-794`
  (`call_contract_fn` — the parent owner of `instance`).

## Evidence

Source-level reading: the parent `call_contract_fn` owns `instance` after
`retrieve_contract_instance_from_storage` and the only consumers are (a)
the native fast paths (which clone), (b) the SAC builtin frame at line
831 (`StellarAssetContract(id.metered_clone(self)?, *func, args_vec,
instance)` — moves `instance` directly), and (c) the ContractVM frame at
line 824 (moves `instance` directly). So the *Wasm* and *SAC* paths
already move; only the native Soroswap paths clone.

## Anti-Evidence

The two clones are **metered**: `metered_clone::<ContractId>` and
`metered_clone::<ScContractInstance>` both call `Budget::charge` with
`ContractCostType::MemCpy` (and `MemAlloc` for heap-allocated sub-fields
like `ScMap` and the SymbolObject `BytesM`s). The p26 metering model
treats those charges as protocol-visible — any reduction in the number of
`charge()` calls or in the input bytes counted will shift `cpu_insns` /
`mem_bytes` and would be caught by exact-budget assertions in
`budget_metering.rs` and `e2e_tests.rs`. This places the change in the
same class as the `005-batch-build-host-storage-maps` and
`002-in-place-storage-map-mutation` (already-rejected) attempts — the
metering must be preserved verbatim across the refactor, which forces the
removed clone work to be replayed in another form.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not duplicated by any current fail/hypothesis/reviewed/poc entry

### Why It Failed

Two independent disqualifying factors:

1. **Protocol-visible metering blocks the move**. `metered_clone` is more
   than a physical copy: it issues `Budget::charge(MemCpy, ...)` and
   `charge_heap_alloc` calls whose totals are exact and observable. A
   move-not-clone refactor would either (a) drop those charges and shift
   `cpu_insns`/`mem_bytes` (failing exact-budget tests), or (b) replay the
   same `charge` calls without doing the physical copy (which still pays
   the budget-tracker update cost — the dominant per-call work). This is
   the same wall as Meta-Pattern #2 in `fail/soroban-env/summary.md`.

2. **The removable physical residual is sub-Low**. Even if metering were
   ignorable, the per-call savings is one shallow `[u8;32]` copy plus a
   shallow clone of a 5-entry `ScMap`. Per the existing accepted baseline,
   the native pool getter / swap paths fire ~7000 + ~7000 + small-pool-of-
   getter-calls = ~30K matched dispatches per benchmark window (8K of
   which pay the full instance clone). At ~150–400 ns per pair of clones,
   that is ~6–12 ms aggregate self-time / 8 workers / 71 ledgers ≈
   0.01–0.02 ms/ledger ≈ 0.005–0.01 % of the 211 ms soroswap apply
   baseline — three to four orders of magnitude below the 1 % noise floor.

Either factor alone is disqualifying; together they make the change
non-viable for this objective.

### Lesson Learned

Frame-construction clones on the matched native fast-paths look removable
at the source level (the parent stack-owned values are about to be
dropped), but in p26 the clones are *metered*, so the change is in the
same protocol-visible class as the previously rejected batch-build and
in-place map families. Any future "move into native frame" hypothesis must
either (a) propose a coordinated next-protocol metering recalibration that
formally redefines `Frame::NativeContract` push as not charging the
instance/id MemCpy, or (b) confirm that the physically removable work
(post-metering replay) clears the 3 % Medium floor — for instance- and
id-sized objects under typical Soroswap call volumes, it does not.
