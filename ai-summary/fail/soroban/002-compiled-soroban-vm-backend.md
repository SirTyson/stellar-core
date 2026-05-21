# H002: Protocol-Gated Compiled Soroban VM Backend for Cached Modules

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: High
**Impact**: >10% soroswap or max-sac apply-time reduction by replacing interpreter-heavy wasmi execution for cached contract modules with a deterministic compiled backend
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Cached Soroban contract modules should retain fresh per-invocation host state, storage rollback, budget accounting, PRNG seeding, events, and deterministic results, but the hot execution engine should not have to interpret the same router/pair Wasm bytecode thousands of times per run. For next protocol only, `ModuleCache` should be able to store a deterministic compiled execution artifact alongside `ParsedModule`; `Vm::from_parsed_module_and_wasmi_linker` should instantiate a fresh execution context from that artifact and charge the protocol-defined compiled-backend budget while producing byte-identical ledger effects for supported contracts.

## Mechanism

The current `ModuleCache` caches parsed `wasmi::Module`s and a maximal linker, but every call still constructs a fresh `wasmi::Store`, instantiates the module, performs wasmi export lookup, and runs the function through the interpreter/import-dispatch loop. In the current soroswap trace, the apply subtree spends `12,842,366,133 ns` total in `Vm::invoke_function_raw`, `9,353,235,883 ns` in generated host-function dispatch `call`, `1,648,211,481 ns` in `Vm::instantiate_wasmi`, and `1,317,542,205 ns` specifically in `Vm::instantiate_wasmi - instantiate`. A compiled backend that is populated when `ModuleCache::parse_and_cache_module` parses the contract would attack the dominant repeated execution path while preserving transaction-local `Host`, `Budget`, storage, events, and rollback objects that prior reusable-instance ideas could not safely share.

## Trigger

Use the current soroswap diagnostic trace and benchmark configuration from `ai-summary/CURRENT_STATE.md`. The workload repeatedly executes the same small set of cached router/pair modules across `6,776` invoke-host-function calls and `20,389` VM instantiations in the trace. A PoC would add a next-protocol compiled backend for cached p26 modules, run the same `soroswap, TX=2000, T=8` matrix, and compare top-line apply time plus Tracy movement in `Vm::invoke_function_raw`, `Vm::instantiate_wasmi`, and generated dispatch `call`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` currently stores parsed modules and shared wasmi engine/linker, but no compiled executable artifact.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-180` — `parse_and_cache_module` is the eager cache-population point where a compiled artifact can be built once per contract hash/protocol.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` is the current per-call interpreter-instance construction path.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-217` — `from_parsed_module_and_wasmi_linker` constructs the per-call `Vm`; it can select the compiled backend for next protocol while preserving p26 behavior.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:271-345` — `metered_func_call` performs export lookup, fuel transfer, and `wasmi::Func::call`; the compiled backend must provide equivalent fuel/budget boundaries.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:81-120` — instantiation cost inputs show where next-protocol compiled-backend metering would need a protocol-defined replacement or compatibility charge.

## Evidence

The top current soroswap apply worker costs are dominated by repeated VM execution under `applyLedger`, while the retained failure history has already ruled out narrower wasmi micro-optimizations such as reusable `InstancePre`, active-element caching, import-table trimming, pristine instance snapshots through the pinned wasmi API, and export-handle caching. This hypothesis is deliberately different: it does not try to reset or share mutable wasmi instances across transactions. It keeps fresh transaction-local state and changes the cached module's execution representation, which is the scale of redesign required to move a dominant phase rather than another sub-1% instantiation cleanup.

## Anti-Evidence

The implementation risk is high. A compiled backend must provide deterministic behavior across supported CPU architectures, exact traps/errors, reproducible fuel/budget accounting, host-call ordering, memory limits, and debug/diagnostic behavior. If the only available compiled engine cannot reproduce Soroban's wasmi semantics or introduces nondeterministic floating-point/host behavior, the hypothesis fails despite the attractive hotspot size. The PoC should start with a next-protocol gate and a very small supported-contract subset before attempting a general backend replacement.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The code path and broad opportunity are real, but the current hypothesis is not concrete enough to validate as a correctness-preserving optimization. The checked-out Soroban host links only the Stellar fork of `wasmi`; `ModuleCache` stores `Arc<ParsedModule>` plus a shared `wasmi::Engine`/`Linker`, and `Host::instantiate_vm` always returns a `Vm` backed by a fresh `wasmi::Store` and `wasmi::Instance` when the cache hits. There is no existing compiled-execution backend, backend trait, native code cache, or dependency that can be evaluated for determinism, fuel accounting, memory limits, trap mapping, or host-call ABI compatibility.

The severity projection also uses nested aggregate Tracy zones as if they were fully removable. `Vm::invoke_function_raw` descends into `metered_func_call`, and generated `vm/dispatch.rs` host-function dispatch drains/refills fuel, performs relative/absolute object conversion, charges dispatch, calls the actual host function, augments errors, and refills VM fuel. A compiled backend would still need the host function bodies, storage, auth, events, rollback, diagnostics, and output extraction. Prior retained failures around export caching, arg marshalling, fuel synchronization, host dispatch trampoline overhead, and instantiation subcomponents show that many visible VM-adjacent slices are sub-threshold once mandatory work and 8-way parallel-worker normalization are applied.

Finally, "protocol-defined compiled-backend budget" is a requirement, not a design. A next-protocol backend may legitimately define new metering, but the hypothesis must specify where budget observability changes, how fuel is synchronized around imported host calls, how traps and recoverable contract errors map to existing `HostError` behavior, and which compiled engine or implementation can enforce Soroban's deterministic subset. Without that, a PoC cannot tell whether a benchmark change is a valid protocol optimization or an unreviewable semantic change.

### Alternative Angle

Refine this into a concrete next-protocol Wasm-backend proposal rather than a generic "compiled backend" placeholder. The refined hypothesis should name the backend implementation, justify deterministic behavior on all supported platforms, define the supported Wasm subset and fallback policy, and map the new backend's call/memory/trap/fuel APIs onto Soroban's `Host`, `Budget`, relative-object handles, diagnostics, and `with_frame` rollback model. It should also define an exact new-protocol metering schedule and explicitly preserve p26 behavior.

Before PoC handoff, add measurement that isolates only removable VM-engine work: per-call `wasmi::Func::call` interpreter time excluding generated dispatch host-function bodies, plus per-call instantiation work that a compiled backend truly removes. Normalize aggregate worker totals by the configured cluster count and compare the remaining wall-time ceiling to the current non-Tracy soroswap baseline in `ai-summary/CURRENT_STATE.md`. If that isolated ceiling is still at least 3%, the refined backend-specific proposal can be reviewed as Medium/High.

### Additional Code Paths

- `src/rust/src/soroban_module_cache.rs:22-49` — outer cache dispatches protocol 26 and next protocol 27 to the same p26 protocol-specific cache; any new backend must remain protocol-gated without perturbing released p26.
- `src/rust/soroban/p26/Cargo.toml:46-50` — the current p26 workspace depends on the Stellar fork of `soroban-wasmi`, with no compiled-runtime dependency to validate.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` stores only `wasmi::Engine`, `wasmi::Linker<Host>`, and parsed modules.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-183` — cache population parses into `ParsedModule` and inserts the parsed artifact; there is no backend compilation step.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-901` — `Host::instantiate_vm` checks storage, reads `ModuleCache::get_module`, and always constructs a wasmi-backed `Vm` on cache hits or misses.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-217` — `Vm::instantiate_wasmi` builds a fresh `Store`, charges cached-instantiation costs, checks imports, instantiates the module, and stores the instance/memory in `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:271-391` — `metered_func_call` handles export lookup, input limits, fuel transfer into and out of wasmi, `Func::call`, trap mapping, and relative-to-absolute result conversion.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — every Wasm host import must drain VM fuel to the host budget, charge dispatch, marshal args, call the host function, map errors, convert the result, and refill VM fuel.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:401-562` — `with_frame` is the rollback/error/instance-storage boundary that must remain identical for any replacement execution engine.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — per-transaction host construction, storage setup, `Host::invoke_function`, `Host::try_finish`, ledger-change extraction, and event/result encoding remain outside the VM-engine replacement.
