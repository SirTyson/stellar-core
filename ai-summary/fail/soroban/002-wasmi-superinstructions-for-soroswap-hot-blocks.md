# H002: wasmi Superinstructions for Soroswap Router and Pool Hot Blocks

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: High
**Impact**: reduce the dominant Soroswap VM execution phase without native-contract semantics or nondeterministic JIT compilation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap router and pool Wasm should execute with exactly the same WebAssembly semantics, host-function import behavior, fuel accounting schedule selected for the new protocol, traps, and observable ledger outputs. The host should not need to dispatch every translated wasmi instruction through the generic `match Instruction` loop when a cached module contains repeated straight-line instruction sequences that can be represented as deterministic fused interpreter operations.

## Mechanism

The pinned Soroban wasmi backend translates Wasm into an internal `Instruction` enum and interprets it with a large `match` in `Executor::execute`. Soroswap repeatedly invokes the same cached router and pool modules thousands of times per benchmark run, so any hot straight-line sequence in those modules pays the same enum-dispatch, instruction-pointer update, and small helper-call overhead on every swap. A protocol-gated wasmi extension could add validated superinstructions for common sequences observed in the Soroswap artifacts (for example local-get/local-set/arithmetic/load/store chains and constant-offset memory operations), produced at `ParsedModule`/wasmi translation time and executed by new `Instruction` variants; this preserves deterministic interpretation while reducing dispatch overhead in the dominant VM phase.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the current soroswap scenario. The workload uses fixed vendored Wasms at `src/rust/apply-load-wasm/soroswap_router.wasm` and `src/rust/apply-load-wasm/soroswap_pool.wasm`; `wasm-tools print` shows the router exports `swap_exact_tokens_for_tokens` and amount/reserve helper exports, while the pool exports `swap`, `get_reserves`, `token_0`, `token_1`, and token-like transfer/balance functions. Those same modules are invoked through the module cache on every successful swap.

## Target Code

- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/bytecode/mod.rs:28-180` - internal `Instruction` enum where fused Soroswap-safe superinstructions would be represented.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:222-444` - interpreter dispatch loop currently matching one instruction at a time.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:448-520` - load/store/unary/binary helpers that can be fused for common straight-line patterns.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/func_builder/translator.rs:85-180` - translation stage where repeated instruction windows could be identified and emitted as fused bytecode.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:138-227` - Soroban parsed-module construction point that can store validation metadata or enable the superinstruction translation mode for next protocol.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` - hot Soroban VM invocation surface affected by the change.

## Evidence

The current soroswap trace's apply-contained VM zones are large enough for a dominant-phase redesign: `Vm::invoke_function_raw` accounts for 12,842,366,133 ns across 20,313 calls and `call` accounts for 9,353,235,883 ns across 40,605 calls, all contained within `applyLedger`. `wasm-tools print` confirms the benchmark reuses a small fixed set of local Wasms rather than arbitrary user-provided code paths, and `ParsedModule` already caches the wasmi-translated module, making translation-time specialization amortizable across every invocation in the ledger.

This is distinct from previously rejected native Soroswap precompile and compiled-backend records. It does not replace router/pool semantics with hand-written Rust, does not require Cranelift/Wasmtime/JIT determinism, and does not depend on reusable wasmi `Store`/`Instance` state. It is a deterministic interpreter-bytecode optimization inside the existing pinned wasmi engine.

## Anti-Evidence

The proposal must first profile actual instruction-frequency and basic-block patterns in the router/pool modules; if hot time is dominated by host calls, storage, or unavoidable memory copies rather than interpreter dispatch, superinstructions will not clear Medium. Adding new fused instructions to wasmi is invasive and must preserve fuel accounting, trap ordering, stack-height validation, call/return behavior, and memory bounds checks exactly for p26 or via an explicit next-protocol schedule. Rust `match` dispatch may already compile efficiently, so a function-pointer or direct-threaded rewrite could regress; the PoC should start with a small set of mechanically generated fused enum variants validated against wasmi's existing tests and the Soroswap benchmark.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - no duplicate superinstruction/fused-bytecode investigation found in soroban fail/success records
**Failed At**: reviewer

### What's Wrong

The traced hot path is real: `closeLedger` reaches Soroban parallel apply, crosses the C++/Rust bridge, constructs a `Host`, resolves Wasm contracts through the module cache, instantiates a fresh `Vm`, and executes exports through `Vm::invoke_function_raw` and wasmi's generic `Executor::execute` match loop. The pinned wasmi bytecode also really has no local/load/store/arithmetic superinstruction variants beyond existing single-op bytecode and internal-call specialization, and a static scan of the vendored router/pool Wasms shows repeated opcode patterns such as `local.get local.get`, `local.get i32.const i32.add`, and `local.get i64.load local.set`.

The hypothesis is still not ready for PoC because it treats broad VM aggregate zones as removable interpreter-dispatch time. `Func::call` includes mandatory host calls, storage/auth work, fuel transfers at VM/host boundaries, traps, and output conversion; existing fail records already show several subpaths under `Vm::invoke_function_raw`, host dispatch, and wasmi instantiation normalize below Medium when divided by Soroswap's parallel clusters and apply windows. Without dynamic basic-block/opcode counts or a measured share of `Func::call` spent specifically in per-instruction dispatch/helper overhead, the proposed fused-instruction set has no defensible 3%+ apply-time projection.

The correctness contract is also under-specified. A viable superinstruction proposal must name the exact fused bytecode windows, define their stack-height validation, memory-bounds checks, trap ordering, instruction-pointer effects, and interaction with existing block `ConsumeFuel` accounting, and explain whether the behavior is a next-protocol physical-execution change or preserves p26 metering exactly.

### Alternative Angle

Refine this into a measurement-backed next-protocol wasmi bytecode proposal. First add temporary instrumentation around the pinned wasmi translator/executor to collect dynamic opcode and basic-block n-gram counts for the Soroswap router and pool inside `applyLedger`, plus an isolated estimate of dispatch/helper overhead excluding host import bodies and VM/host fuel synchronization. Then propose only the top few mechanically checkable fusions, compute `removed_dispatches * per_dispatch_cost / NUM_CLUSTERS / ledgers`, and require a projected Medium-tier apply-time saving before PoC.

### Additional Code Paths

- `src/ledger/LedgerManagerImpl.cpp:1655-1688,2784-3029` - ledger close applies transactions, separates parallel Soroban phases, and invokes `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2575,2623-2670` - parallel workers run `TransactionFrame::parallelApply` inside stage/cluster execution and join before deterministic commit.
- `src/transactions/TransactionFrame.cpp:2385-2430` and `src/transactions/OperationFrame.cpp:175-188` - transaction parallel apply dispatches the single Soroban operation to `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1378` - `InvokeHostFunctionOpFrame` calls `rust_bridge::invoke_host_function` with resources, auth, ledger entries, PRNG seed, and shared module cache.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:310-450` - Rust selects the protocol-specific host module, builds the budget, times e2e invocation, and catches panics.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` - host storage/auth/ledger context is constructed, module cache is installed, and `Host::invoke_function` is executed.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-805` - Wasm contract calls retrieve the instance, instantiate `Vm` from the cached parsed module when possible, push a contract frame, and call `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,160-195` and `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:146-227` - the shared cache stores `Arc<ParsedModule>` values built from the pinned wasmi engine, so translation-time specialization is architecturally possible.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218,300-411` - each invocation still creates a fresh wasmi store/instance, transfers fuel, calls the wasmi export, returns fuel, and converts the result.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-275` and `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` - host imports transfer fuel back to the host, charge dispatch, marshal relative/absolute object handles, call host functions, and transfer remaining budget back to VM fuel.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/bytecode/mod.rs:28-180,365-423` - wasmi `Instruction` has one-op bytecode variants and block fuel records, but no Soroswap-style fused local/load/store/arithmetic variants.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:222-444,462-524,955-1045,1380-1435,1570-1590` - executor dispatches one `Instruction` per loop iteration and delegates to small local/load/store/arithmetic/call helpers.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/func_builder/translator.rs:144-248,491-540,625-675,1276-1320,1381-1445,1959-1961` - translator emits current bytecode, coalesces fuel into block `ConsumeFuel` records, and would be the right place to emit any proven fused windows.
- `src/rust/soroban/p26/Cargo.toml:46-57` - stellar-core uses the pinned `soroban-wasmi` git dependency, so a production implementation would require an explicit dependency/fork update rather than only local soroban-env-host changes.
