# H001: Deterministic AOT Wasm execution tier for cached Soroswap modules

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban VM execution
**Severity**: High
**Impact**: Soroswap apply-time reduction by replacing the dominant wasmi interpreter path for cached Wasm contracts with a deterministic compiled execution tier
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Soroban transaction invokes a cached Wasm contract during `closeLedger`, Core should execute the contract with the same deterministic storage accesses, authorization checks, events, diagnostics, return values, traps, and resource accounting as the current wasmi path. The execution backend choice must depend only on protocol version, contract code bytes/hash, and ledger state, not on node-local timing or worker scheduling. If the compiled backend charges different CPU/memory costs, the change must be protocol-gated so budget expectations and resource-limit behavior are intentionally redefined for that protocol.

## Mechanism

The current p26 `ModuleCache` stores a parsed `wasmi::Module` and every production `ContractExecutable::Wasm` call instantiates a wasmi `Vm`, marshals arguments, interprets bytecode, crosses generated VM dispatch imports, and returns fuel to the host. Soroswap repeatedly invokes the same router and pair Wasms on the measured parallel apply path; the accepted trace shows the interpreter/VM envelope is still the dominant worker phase after the accepted storage and SAC fast paths.

Add a protocol-gated compiled execution tier to the module cache, built eagerly alongside `ParsedModule` for cached modules and used by `call_contract_fn` before falling back to wasmi. A deterministic AOT tier that preserves the same import ABI, memory limits, fuel/budget synchronization points, and trap mapping would remove the interpreter dispatch loop for router/pair Wasm execution without changing cluster scheduling or ledger-effect ordering. This is broader than prior rejected wasmi instantiation, export-cache, or code-hash-native-precompile ideas: it does not require hand-writing Soroswap semantics and attacks guest instruction execution for all cached Wasm contracts.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark from `ai-summary/CURRENT_STATE.md` using the accepted trace:

`/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`

Every successful swap invokes the router Wasm and then the pair Wasm from `InvokeHostFunctionOpFrame::doParallelApply`; those calls should dispatch through the compiled tier when the module is present in `ModuleCache`, while uncached/newly-uploaded modules and unsupported protocols should stay on the existing wasmi path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` currently stores a shared wasmi engine/linker and parsed modules only.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-182` — `parse_and_cache_module` is the eager point where a deterministic compiled artifact could be built once per ledger/module.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:146-153` — `ParsedModule` holds `wasmi::Module`, protocol version, and cost inputs; it has no compiled execution artifact today.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — production `call_contract_fn` sends every `ContractExecutable::Wasm` through `instantiate_vm` and `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-186` — each call instantiates wasmi components from the cached module and linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345` — `metered_func_call` resolves exports, synchronizes fuel, calls wasmi, returns consumed fuel, and maps traps.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` marshals arguments and enters the wasmi call path.
- `src/simulation/ApplyLoad.cpp:2855-2913` and `src/simulation/ApplyLoad.cpp:3381-3505` — the benchmark uploads stable router/pair Wasms and invokes `swap_exact_tokens_for_tokens` with router and pair code in every swap footprint.

## Evidence

- Timestamp filtering against the 70 `applyLedger` windows in the accepted soroswap trace confirms this is measured apply-path work, not TX-set construction: `Vm::invoke_function_raw` totals **11,517,335,816 ns** over **15,229** in-window events, `call` totals **8,093,455,003 ns** over **30,534** events, `Host::invoke_function` totals **8,863,051,800 ns**, and `InvokeHostFunctionOpFrame doParallelApply` totals **11,026,377,370 ns**.
- Normalizing the `Vm::invoke_function_raw` aggregate by eight configured clusters and 70 apply windows gives roughly **20.6 ms/ledger** of critical-worker VM-call envelope before counting additional interpreter-adjacent `call` dispatch time. A compiled tier that removes a substantial fraction of interpreter dispatch for router/pair Wasm can plausibly exceed the current Medium floor (~8.4 ms) and may approach High if it materially restructures the dominant Soroban execution phase.
- The source has a clear backend boundary: cached modules are already built eagerly in `ModuleCache`, and production dispatch funnels all Wasm calls through `call_contract_fn` -> `instantiate_vm` -> `invoke_function_raw`. Adding a compiled artifact beside `ParsedModule` changes the execution tier without changing transaction clustering, C++ apply ordering, or footprint construction.
- This is not the prior code-hash native Soroswap-precompile hypothesis. That approach required handwritten router/pair implementations and failed at PoC due to missing audited contract source and equivalence harnesses. This proposal compiles the existing ledger Wasm bytes and therefore applies to any cached Wasm module with the same deterministic ABI.

## Anti-Evidence

- This is a major VM/backend redesign. A compiled tier must prove deterministic execution across platforms or restrict itself to a deterministic portable backend; uncontrolled native JIT behavior would be consensus-unsafe.
- Budget accounting is protocol-visible. If compiled execution changes `WasmInsnExec`, memory, dispatch, or trap-at-instruction behavior, the optimization must be protocol-gated and update exact budget/resource tests rather than silently changing p26 semantics.
- Host import dispatch, storage work, SAC native calls, authorization, events, and ledger-change extraction remain mandatory. A PoC must use Tracy and non-Tracy benchmarks to show the compiled tier removes enough guest-execution time after those remaining costs are subtracted.

---

## Review

**Verdict**: VIABLE
**Severity**: High
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in fail/success records; related records cover export-function caching, lazy wasmi fuel accounting, and hash-specific native precompiles, not a generic deterministic compiled backend for cached ledger Wasms

### Trace Summary

The close-ledger Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge into the p26 host, builds an enforcing host with the shared module cache, and calls `Host::invoke_function`. For `ContractExecutable::Wasm`, production dispatch has no native or compiled backend choice: `call_contract_fn` always instantiates a `Vm` from the cached `ParsedModule` and shared wasmi linker, then `Vm::invoke_function_raw` marshals arguments, enters `metered_func_call`, runs wasmi, synchronizes fuel, and maps traps/returns. The apply-load soroswap setup uploads stable factory/pair/router Wasms and every generated swap invokes the router while including router and pair code in the footprint, so a deterministic compiled tier attached to the module cache would run on the measured parallel apply path without changing transaction clustering or ledger-effect ordering.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — per-operation apply serializes host-function inputs and calls `rust_bridge::invoke_host_function` with the shared `SorobanModuleCache`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban operations execute through `InvokeHostFunctionOpFrame::doParallelApply` inside the parallel apply phase.
- `src/rust/src/soroban_invoke.rs:7-38` — the C++ bridge selects the protocol host module and passes the module cache into p26 invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:440-481` — p26 invocation builds enforcing storage, installs auth/ledger/module-cache state, and calls `Host::invoke_function` in the measured host invocation span.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:950-1121` — `call_n_internal` enforces reentry and reserved-name rules, then delegates production calls to `call_contract_fn`; the only compiled-in native contract path here is test-only.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `ContractExecutable::Wasm` always takes the wasmi path through `instantiate_vm` and `vm.invoke_function_raw`, while only `ContractExecutable::StellarAsset` has a production native fast path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-804` — cached Wasm calls verify the code entry exists in storage, fetch `ParsedModule` from `ModuleCache`, and instantiate a `Vm` from the cached module and shared linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-217` — `Vm::from_parsed_module_and_wasmi_linker` constructs a wasmi store, charges instantiation, checks imports, instantiates via the linker, and captures memory.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345,393-412` — each Wasm function call converts args to relative `wasmi::Value`s, resolves the export, supplies fuel to wasmi, performs `func.call`, returns consumed fuel to the host budget, maps traps, and translates the result back.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — every Wasm-to-host import returns fuel to the host, charges dispatch, converts relative ABI values, invokes the generated host method, converts the return value, and refills VM fuel.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,160-182` — the cache stores a wasmi engine/linker plus `Arc<ParsedModule>` entries only; `parse_and_cache_module` is the eager compilation point.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:146-153` — `ParsedModule` contains only `wasmi::Module`, protocol version, and cost inputs.
- `src/ledger/SharedModuleCacheCompiler.cpp:98-115,138-194` — ledger setup/rebuild scans live contract code and calls `SorobanModuleCache::compile` from background compiler threads.
- `src/rust/src/soroban_module_cache.rs:22-60` and `src/rust/src/soroban_proto_any.rs:723-736` — the cross-protocol cache delegates compile to `ProtocolSpecificModuleCache`, which currently calls `parse_and_cache_module_simple`; "compile" means parse/cache a wasmi module, not generate executable native/AOT code.
- `src/simulation/ApplyLoad.cpp:2855-2913,3381-3505` — the soroswap benchmark uploads fixed factory/pair/router Wasms and constructs every swap as a router `InvokeContract` with router and pair code keys in the footprint.

### Findings

The inefficiency is real and hot: cached contract code is already parsed eagerly, but every production Wasm invocation still executes through wasmi's interpreted VM path on the parallel `closeLedger` path. Existing optimizations do not cover this mechanism: the current module cache avoids reparsing and shares the wasmi engine/linker, but it has no compiled execution artifact, no production backend switch, and no generic native dispatch for arbitrary `ContractExecutable::Wasm` code.

The prior fail/success records are not duplicates. The export-function cache investigated a tiny lookup inside `Vm::metered_func_call`; lazy fuel accounting targeted wasmi's fuel mode and failed because it did not remove ordinary instruction interpretation; the code-hash native precompile proposal bypassed specific soroswap Wasm hashes with hand-written implementations. This hypothesis instead compiles the actual ledger Wasm bytes into a deterministic backend for any cached module and preserves the host import ABI, so it attacks a broader and different component of the VM envelope.

The projected severity remains High for review purposes because this is a backend redesign of the dominant Soroban Wasm execution tier, not a micro-cache. The PoC must not count the entire inclusive `Vm::invoke_function_raw` or generated `call` time as removable: host imports, storage work, SAC calls, auth, events, frame rollback, and ledger-change extraction remain mandatory. However, the measured VM envelope is large enough that removing a substantial guest-interpreter dispatch share can clear the objective's Medium floor, and a successful generic compiled tier would materially restructure the dominant phase of soroswap `closeLedger` execution.

Correctness is the gating risk. A native JIT/AOT that depends on node-local CPU features, nondeterministic compiler choices, or un-gated metering changes would be consensus-unsafe. A viable PoC must either preserve p26-visible behavior exactly or introduce the compiled tier behind a future protocol gate with explicit budget/trap semantics, deterministic backend configuration, and fallback to wasmi for unsupported modules/protocols.

### PoC Guidance

- **Target code**: Extend `ParsedModule` / `ModuleCache` in `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` and `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs` with a protocol-gated compiled artifact built from the same Wasm bytes during `parse_and_cache_module`; wire `src/rust/src/soroban_proto_any.rs:723-736` and `src/ledger/SharedModuleCacheCompiler.cpp:98-115` so background module-cache compilation builds the artifact for live contracts.
- **Target dispatch**: Add a backend branch in `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-804` before `Vm::from_parsed_module_and_wasmi_linker`; only use the compiled tier when the module is cached, protocol-supported, and the backend can provide the same import/memory/fuel/trap contract. Keep the existing wasmi path as the fallback.
- **Change description**: Introduce a deterministic compiled execution backend for cached Wasm modules that reuses the existing host import ABI and frame/storage/auth machinery while eliminating wasmi interpreter dispatch for successful router/pair Wasm calls. Do not hand-write soroswap semantics and do not key behavior on node-local timing or scheduling.
- **Correctness check**: Preserve or explicitly protocol-gate `WasmInsnExec`, memory charging, trap mapping, missing-function handling, host import dispatch ordering, relative/absolute object handle translation, diagnostic/event ordering, reentry behavior, and rollback semantics. Existing Soroban invoke-host-function tests, VM tests, auth tests, and budget/resource-limit tests should cover the behavior surface; exact budget-number updates are acceptable only under a protocol-gated semantic change.
- **Benchmark focus**: Compare soroswap `TX=2000,T=8` and max-SAC apply-load runs with and without the compiled tier over multiple runs. Attribute the win to guest execution by separating compiled-tier time from mandatory host import/storage/SAC work; the top-line apply-time target is at least Medium (3-10%) and this should be treated as High only if the backend materially reduces the VM worker envelope across repeated runs.

---

## PoC Attempt

**Result**: POC_FAIL
**Date**: 2026-05-02
**PoC by**: claude-opus-4.7, high
**Failed At**: poc
**Iterations**: 0 (declared infeasible before any build-test cycle)

### Failure Reason

The hypothesis itself classifies this as "a major VM/backend redesign" of the
Soroban Wasm execution tier. To implement even a minimum viable deterministic
compiled tier inside `soroban-env-host` (p26) and demonstrate it against the
existing soroban test surface, a PoC must, at minimum:

1. Introduce a non-wasmi compiled execution backend into the
   `soroban-env-host` workspace. The current dependency closure contains only
   `wasmi 0.31.1-soroban` (a pure interpreter); there is no in-tree
   compiled/AOT backend to switch on. Every realistic candidate
   (wasmtime+Cranelift, wasmer singlepass, a custom mini-compiler) is either
   not deterministic across CPU vendors/microarchitectures, or is months of
   integration work, or both.
2. Re-implement the entire Soroban host-import surface against the new
   backend's `Linker`/equivalent — every `dispatch.rs`-generated import must
   exist on the new backend with identical relative/absolute object handle
   translation, fuel return/refill semantics, and trap mapping.
3. Bridge fuel/budget accounting so per-instruction `WasmInsnExec` charging,
   memory growth charging, and dispatch charging match wasmi exactly — or
   formally protocol-gate every divergence and update the corresponding
   budget/resource-limit unit tests under that new gate.
4. Preserve trap mapping, missing-function handling, reentry behavior,
   diagnostic/event ordering, frame rollback, and storage/auth interaction so
   `make check` continues to pass without weakening any test.
5. Wire the new artifact through `ParsedModule`/`ModuleCache`,
   `SharedModuleCacheCompiler`, and the C++/Rust bridge protocol-cache plumbing
   (`soroban_proto_any.rs`, `soroban_module_cache.rs`,
   `SharedModuleCacheCompiler.cpp`) without breaking shallow_clone semantics
   shared across protocols.
6. Prove deterministic output across hardware (CPU vendor, ISA extensions,
   pointer width), since any divergence is a consensus bug. None of the
   off-the-shelf production Wasm compilers provides this guarantee out of the
   box for arbitrary guest Wasm.

The PoC budget for this objective is 10 build-test cycles, where each cycle
includes a full `make -j30` rebuild of stellar-core (tens of minutes after a
cold cache hit on a new dep tree) and an `env NUM_PARTITIONS=30 make check`
run (substantially longer). Adding a new compiled-Wasm backend dependency to
the locked `soroban-env-host` workspace alone routinely requires multiple
iterations to even compile, before any of items (2)–(6) can begin. There is
no plausible path from the current baseline to a passing `make check` with a
deterministic compiled execution tier replacing or shadowing the wasmi
dispatch path within that budget.

The reviewer's own anti-evidence and correctness section already acknowledge
this: the optimization is gated on (a) cross-platform deterministic execution
of compiled Wasm and (b) byte-for-byte preservation of p26 budget/trap
semantics or an explicit new protocol gate with redefined semantics. Neither
sub-problem has a "small surgical change" form, and a partial backend (e.g.,
compiling only soroswap router/pair Wasms) collapses back into the previously
rejected "code-hash native precompile" hypothesis class.

### Changes Attempted

No source code changes were made. After reading the hypothesis file,
re-reading the reviewer's PoC Guidance, and inspecting
`src/rust/soroban/p26/soroban-env-host/Cargo.toml`,
`src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs`, and
`src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` to confirm
that the current backend is wasmi-only with no latent compiled-tier hook,
the work was abandoned without modifying any source files. The p26 submodule
was initialized at the recorded baseline SHA (`a417a96`) but no commits were
made on either the outer or submodule repository.

Recommendation: this hypothesis should not be re-attempted in PoC form
without first scoping out the deterministic compiled backend as its own
research project (likely a multi-month engineering effort: pick or build a
deterministic compiler, port the host import ABI, prove cross-platform
determinism), rather than as a single PoC iteration.
