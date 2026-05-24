# H030: Pool/Reuse Wasmi `Store` Allocations Across Invocations

**Date**: 2026-05-24
**Subsystem**: soroban-env
**Severity**: Low (sub-Medium; bordering benchmark noise)
**Impact**: Removes a fresh `wasmi::Store<Host>` heap allocation per
contract invocation in `Vm::instantiate_wasmi`. Soroswap apply window
performs ~16,000 `Vm` instantiations (one per contract invocation, with
many calls per tx).
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Vm::instantiate_wasmi`
(`src/rust/soroban/p26/soroban-env-host/src/vm.rs:100-218`) builds a
fresh `wasmi::Store<Host>` for every contract invocation. The
`Store` is the wasmi engine's per-execution heap holding global
mutable state slots and the host-resource arena. A correctly-bounded
optimization would reuse a `Store` across invocations *within the same
worker thread*, resetting its slot tables to a clean state before
each new `Instance` is created on it. Because `Store` is the
allocation root for `Linker::instantiate`, reusing one across
sequential invocations on a single thread should be safe so long as
(a) the previous `Instance` no longer holds live references into it,
(b) all engine-side mutable state (globals, tables, memories) is
re-initialized from the module, and (c) the contained host data is
reset to the new `Host` instance for the next invocation. The
budget-charged per-call work that is *strictly* per-instantiation
(`wasmi::Linker::instantiate` plus engine-side validation) would
remain unchanged.

## Mechanism

Today `Vm::instantiate_wasmi` (vm.rs lines ~100-218) executes per call:

```rust
let _span0 = tracy_span!("Vm::instantiate_wasmi - store");
let mut store = Store::new(&module.wasmi_engine, host.clone());
// ... store.limiter(...), check_imports, linker.instantiate, ...
```

The wasmi `Store::new` performs heap allocation for the store's
internal `StoreInner` (engine handle, fuel state, resource limiter
slot, host-data field, growing arenas for `MemoryEntity`,
`TableEntity`, `GlobalEntity`, `ElementSegmentEntity`, etc.). On
contract drop, the `Store` is freed.

If a worker thread maintained one persistent `Store<Host>` and reset
its host-data field and internal arenas at the start of each
invocation, the per-call `Store::new` allocation would be replaced
by an in-place `Store::reset`-style call. Tracy shows
`Vm::instantiate_wasmi - store` at 0.96 ms self-time across all
~16,000 invocations — i.e. the store-creation step itself is already
extraordinarily cheap relative to the dominant
`Vm::instantiate_wasmi - instantiate` step (499 ms self) which
performs the actual module-to-instance binding work (Linker probing
and `Instance` construction).

## Trigger

Apply-load `soroswap` scenario (TX=2000, T=8): ~16,000 contract
invocations across the benchmark window, each constructing one
`Store<Host>`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:100-218`
  (`Vm::instantiate_wasmi`) — call site of `Store::new`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:218-330`
  (`Vm::new`, `Vm::invoke_function_raw`) — store lifetime owner.
- `wasmi::Store` impl (external crate, pinned at the wasmi version
  vendored under `lib/wasmi/`) — would need a `reset`-equivalent API
  or unsafe in-place reinitialization.

## Evidence

Tracy soroswap trace top zones inside `Vm::instantiate_wasmi`:

- `Vm::instantiate_wasmi - instantiate`: 499 ms self / 16,070 events
  (the dominant work — Linker probe + Instance construction).
- `Vm::instantiate_wasmi - check_imports`: 95 ms self / 16,070 events.
- `Vm::instantiate_wasmi - store`: 0.96 ms self / 16,070 events.

The "store" sub-zone is the *exclusive* removable work for a store-pool
optimization. The "instantiate" and "check_imports" zones perform
work that any non-trivial pool design must still run.

Other allocator-pressure indicators: `Vm::new` shows 56 ms self at
16,070 events; `new_with_isolated_host_storage_and_budget` shows
0.39 ms self at 16,068 events; the host-side `Rc<HostImpl>` allocation
is amortized into `with_storage_and_budget` and is not separately
visible.

## Anti-Evidence

1. **The removable cost is 0.96 ms self-time TOTAL across the entire
   trace**, before any parallelism normalization. At 8-way cluster
   parallelism that becomes 0.12 ms wall, and divided across ~71
   measured ledgers that is 0.0017 ms per ledger — about 0.0008 %
   of the 211 ms apply baseline. This is roughly four orders of
   magnitude below the 3 % Medium threshold and three orders of
   magnitude below the 1 % noise floor.
2. The vendored wasmi `Store` does not expose a `reset` API today;
   adding one requires forking the engine or unsafe reach-in to its
   private fields. Either route bloats the diff well beyond the
   "clean low-risk" requirement for Low severity.
3. The host-data slot inside `Store` holds an `Rc<HostImpl>`. Reusing
   a `Store` requires also dropping the old `Rc` reference cleanly
   before installing the new one to keep the per-invocation refcount
   invariants used by `Host::try_finish` intact.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Adjacent to fail
notes about wasmi `InstancePre` (which is bound to a `Store` and so
cannot be reused) but distinct: those targeted *Instance* reuse;
this targets *Store* reuse without an `Instance` cache.

### Why It Failed

The Tracy `Vm::instantiate_wasmi - store` self-time is 0.96 ms across
all 16,070 invocations in the entire 71-ledger benchmark window. Even
under the impossible-best assumption that a store-pool eliminates
100 % of that zone (no remaining `reset` cost), the savings are:

- Trace self-time saved: 0.96 ms.
- After 8-way cluster parallelism: 0.12 ms wall.
- Per ledger: 0.0017 ms.
- Fraction of 211 ms apply baseline: ≈ 0.0008 %.

That is four orders of magnitude below the 3 % Medium threshold
required by this objective and three orders of magnitude below the
1 % benchmark-noise floor. The dominant work in `Vm::instantiate_wasmi`
is `instantiate` (499 ms self) and `check_imports` (95 ms self),
neither of which a store-pool design avoids. Implementing this
optimization would also require either forking wasmi to add a
`Store::reset` API or unsafe in-place reinitialization of `Store`'s
private internals, neither of which meets the "clean low-risk diff"
requirement that Low severity demands.

### Lesson Learned

Tracy sub-zones inside `Vm::instantiate_wasmi` are already
well-quantified by the existing instrumentation. The `store`
sub-zone at < 1 ms self-time is below benchmark noise even before
parallelism normalization, and the dominant `instantiate` (499 ms)
and `check_imports` (95 ms) sub-zones perform work that is intrinsic
to per-invocation `Instance` construction — they cannot be amortized
across invocations without redesigning the linker/instance lifecycle.
Future wasmi-targeted optimizations need to either (a) replace
`wasmi::Linker::instantiate` with a faster instance constructor at
the engine level, or (b) eliminate the per-invocation instantiation
entirely by reusing an `Instance` (which requires either pre-binding
the `Host` into the `Store` permanently, or proving that the wasmi
`Instance` state — globals, memories, tables — is reset to module
initializers between calls).
