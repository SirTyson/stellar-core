# H001: wasmi `extract_functions` does N per-call `alloc_func` Vec pushes per Vm instantiation; bulk-allocate with capacity hint and a single contiguous `Vec::extend` to shrink the dominant per-Store work

**Date**: 2026-05-03
**Subsystem**: rust / soroban-env (forked wasmi-0.31.1-soroban.20.0.1)
**Severity**: Medium
**Impact**: Reduce wasmi `Vm::instantiate_wasmi - instantiate` self-time, which is **~25% of `applyLedger` Tracy time** (1.32 s of 5.23 s) and the largest single in-apply Soroban hotspot after parallel-stage wall-wait.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Per Soroban transaction, `Vm::instantiate_wasmi` (`src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187`) creates a fresh `wasmi::Store<Host>` and instantiates a `wasmi::Module` into it. The instantiation runs `extract_functions`
(`soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/mod.rs:167-182`) which copies, for every Wasm internal function defined by the module, a `Func` handle into the Store's per-instance function arena.

For each instantiation the Store starts empty, so the destination `Vec<FuncEntity>` inside `StoreInner` (`store.rs:711` `alloc_func`) grows from zero to `module.internal_funcs().len()`. Since the module already knows the exact count up front (it is a fixed property of the parsed module recorded in `ModuleHeader`), the correct, allocation-minimal pattern is to:

1. Reserve capacity once via `Vec::reserve_exact(n)` on the destination arena.
2. Build the `n` `FuncEntity` values into a contiguous source slice.
3. Push them into the arena with a single `extend` (or memcpy-equivalent) and emit the contiguous `[Func; n]` handle range to the `InstanceEntityBuilder`, instead of pushing one entry at a time and re-checking arena bounds on every push.

Independent functions and tables/globals/memories are similarly bounded by counts the parsed module carries.

## Mechanism

The current `extract_functions` body iterates `self.internal_funcs()` and for each pair calls
`context.as_context_mut().store.inner.alloc_func(wasm_func.into())` then `builder.push_func(func)`
(`module/instantiate/mod.rs:173-181`). `alloc_func` performs a `Vec::push` on the `Store`'s function arena
(`store.rs:711`) which incurs amortised-but-non-zero capacity-doubling realloc work and re-runs the
`StoreLimits` check on each push, and `builder.push_func` performs a second `Vec::push` on the
per-instance function table.

For a soroswap pair contract (a non-trivial Wasm contract with on the order of hundreds of internal
functions) and ~3 instantiations per Soroban transaction (top-level entry plus sub-call
instantiations), the per-ledger cost is `~hundreds × ~3 × ~6.7 k txs` = **on the order of millions of
`Vec::push` / per-push limit checks per ledger**, all on the worker critical path of
`applySorobanStageClustersInParallel` (the 33% wall-time zone). This is the same micro-cost class as
fail #074 (`HostObject` Vec growth) and fail #027 (per-call alloc + virtual dispatch in
`InMemorySorobanState::get`), each of which already moved benchmarks measurably when attacked.

The deviation from expected behavior is purely a quality-of-implementation defect inside our forked
wasmi: the module knows `n` exactly but the instantiate path does not exploit that knowledge.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py --benchmark soroswap`) and capture a Tracy trace.
The `Vm::instantiate_wasmi - instantiate` zone (`vm.rs:171`) currently averages 64 µs per call
across 20 389 calls per benchmark window. With per-Store function arena pre-allocation, the per-call
cost of the `extract_functions` sub-step should drop measurably and the parent zone should shrink.
The optimisation is purely internal to our wasmi fork and changes no observable contract semantics
(deterministic instantiation order is preserved because we still iterate `internal_funcs()` in
declaration order).

## Target Code

- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/mod.rs:167-182` — `extract_functions` per-call `alloc_func` + `push_func` loop.
- Same file `:184-237` — `extract_tables`, `extract_memories`, `extract_globals` follow the same pattern; the same fix applies, though function count dominates by an order of magnitude.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/store.rs:705-720` — `alloc_func` body; Vec push on `StoreInner.funcs`.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/instance/builder.rs` — `InstanceEntityBuilder::push_func`; the receiving Vec also benefits from `reserve_exact`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — caller `Vm::instantiate_wasmi`; no change required, just downstream beneficiary.

Suggested change shape (per-Store path):

```rust
// in extract_functions, before the loop:
let n = self.len_internal_funcs();
context.as_context_mut().store.inner.reserve_funcs(n);
builder.reserve_funcs(n);
// loop body unchanged
```

with `StoreInner::reserve_funcs(n)` and `InstanceEntityBuilder::reserve_funcs(n)` being trivial
wrappers around `Vec::reserve_exact`. A second-stage variant that skips the per-push StoreLimits
check by re-running it once over `n` (since limits are static per Store) is a small follow-on.

## Evidence

1. **Tracy hot-zone share**: `Vm::instantiate_wasmi - instantiate` is **25.2% of `applyLedger`** in
   the current accepted trace. Even halving the per-Store arena work would clear the Medium
   threshold (3% real apply time ≈ 8 ms, and this zone contributes ~68 ms of real apply per
   benchmark ledger by the Tracy proportion).
2. **The forked wasmi already has the count available**: `Module::len_internal_funcs` /
   `internal_funcs()` (`module/mod.rs:225`) iterate over a slice whose length is known at parse
   time and stored in the `Module`. There is no engine-side ambiguity preventing reservation.
3. **Prior wins on identical micro-patterns**: success #001 (InMemory bucket scan polymorphic
   wrapper) and the historical `HostObject::Vec` growth fix both targeted exactly this
   per-element-Vec-push pattern in hot loops and produced multi-percent savings on the same
   benchmark.
4. **Determinism preserved**: the change is a pure capacity-hint optimisation; the iteration
   order, the resulting `Func` handle values, the `Instance` layout, and the Store byte-for-byte
   contents after instantiation are all unchanged. No protocol observable changes.
5. **Distinct from fail entries**: fail #008 (InstancePre store-bound), fail #016 (mmap memory
   pages — too risky in the fork), fail #057 (minimal linkers), and fail #029 (Store::reset)
   each attack the *cross*-instantiation reuse problem. None addresses the *intra*-instantiation
   per-element Vec growth investigated here.

## Anti-Evidence

- Fail meta-pattern #6 ("wasmi-internal optimisations targeted at `Vm::instantiate_wasmi` should
  not be proposed without a per-zone breakdown"). A PoC must add a Tracy sub-zone around
  `extract_functions` (and the others) to confirm it is a non-trivial fraction of the parent
  64 µs/call; if `extract_functions` is below ~5 µs/call the projected saving will not clear
  Medium and this should be self-rejected at PoC.
- Vec capacity-doubling already amortises individual pushes to O(1); the saving is from
  eliminating realloc copies and the per-push `StoreLimits` recheck, not from saving each push
  outright. The gain is real but the magnitude must be measured before claiming Medium.
- Modifying our wasmi fork carries protocol risk: the public `Func` handle values (token
  identity within a `Store`) must remain identical to today. A bulk allocator that issues
  contiguous handle ranges in the same iteration order satisfies this, but a PoC must include
  the existing wasmi unit tests on the fork plus the full stellar-core suite.
- This change does not address sub-call instantiations that have very small contracts (e.g., the
  inner SAC dispatch); for those the absolute saving per instantiation is small. The win
  concentrates on the soroswap pair contract.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in the retained `fail/soroban` or `success/soroban` records; cross-subsystem fail/success directories are absent
**Failed At**: reviewer

### Trace Summary

The apply path reaches the target through p26 `e2e_invoke`, `Host::invoke_function`, `Host::call_contract_fn`, `Host::instantiate_vm`, `Vm::from_parsed_module_and_wasmi_linker`, and `Vm::instantiate_wasmi`, which calls `wasmi_linker.instantiate` and then wasmi `Module::instantiate`. Inside `Module::instantiate`, `extract_functions` iterates `Module::internal_funcs()` and allocates one `FuncEntity` per internal function into `StoreInner.funcs`, whose `wasmi_arena::Arena` is a raw `Vec` starting empty for each fresh store. However, two central mechanism claims are false: `InstanceEntityBuilder::new` already reserves exact capacity for all functions/tables/memories/globals, and `StoreInner::alloc_func` does not perform a per-function `StoreLimits` check. The remaining removable work is therefore only amortized growth/reallocation of one small store-side function arena per VM instantiation, with no sub-zone measurement showing this slice can clear the objective's Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:475-480` — installs the module cache when present and enters the `Host::invoke_function` Tracy zone.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1148` — top-level `InvokeContract` host functions convert arguments and call into contract execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-775` — Wasm contract calls instantiate a `Vm` before pushing the `ContractVM` frame and invoking the exported function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cached modules use `Vm::from_parsed_module_and_wasmi_linker`, so parsed-module caching does not avoid per-call store/instance construction.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` creates a fresh `wasmi::Store`, installs the limiter, charges instantiation cost, and calls `wasmi_linker.instantiate`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-217` — `from_parsed_module_and_wasmi_linker` wraps the resulting store and instance in the `Vm`.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/mod.rs:49-77` — `Module::instantiate` allocates the instance handle, builds an `InstanceEntityBuilder`, extracts imports/functions/tables/memories/globals, and returns `InstancePre`.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/mod.rs:167-181` — `extract_functions` allocates one `WasmFuncEntity` into the store and pushes the resulting handle into the builder for each internal function.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/module/mod.rs:225-235` — `internal_funcs()` iterates a fixed slice of non-imported function definitions paired with compiled functions, so the function count is knowable before the loop.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/instance/builder.rs:31-69` — `InstanceEntityBuilder::new` already uses `reserve_exact` for total functions, globals, tables, and memories including imports, invalidating the claimed builder-side Vec growth.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/store.rs:267-283` — each fresh `StoreInner` creates empty arenas, including the function arena that could in principle be reserved.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/store.rs:710-714` — `alloc_func` simply calls `self.funcs.alloc(func)` and wraps the returned index; there is no resource-limiter check here.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/store.rs:771-807` — resource-limiter checks exist for new instances, memories, and tables, but no analogous per-function limit check is present.
- `wasmi_arena-0.4.1/src/lib.rs:80-87,132-137` — `Arena::new` uses `Vec::new`, and `Arena::alloc` computes the next index then performs a single `Vec::push`.

### Why It Failed

The hypothesis overstates both the waste and the projected fix. There is a real store-side capacity hint opportunity, but it is not "millions of per-push limit checks" and not two growing vectors: the builder vector is already exact-capacity, and function allocation does not check `StoreLimits`. A reserve-only store-arena patch would remove at most the logarithmic number of reallocations and copies caused by `Vec` growth for one fresh function arena per instantiation, while preserving every per-function `WasmFuncEntity` construction, handle wrapping, builder push, import/type-check path, table/memory/global extraction, element/data initialization, linker work, and store creation. Without a Tracy sub-zone proving `extract_functions` itself is a large fraction of the 64 us parent instantiate zone, the remaining optimization projects below the optimize-soroswap Medium threshold; the objective explicitly rejects Low/sub-noise wasmi-internal micro-optimizations.

### Lesson Learned

For wasmi-internal instantiation hypotheses, read both the embedder path and the forked wasmi internals before assigning broad `Vm::instantiate_wasmi` time to a micro-operation. Capacity growth in one arena can be real, but existing exact-capacity builders and absent limiter checks can reduce the removable slice from "dominant phase" to a small allocation cleanup that needs direct sub-zone evidence before review.
