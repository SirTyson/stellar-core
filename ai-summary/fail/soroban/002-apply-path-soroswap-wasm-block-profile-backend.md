# H002: Apply-Path Soroswap Wasm Block Profile Backend

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: High
**Impact**: Dominant VM-execution redesign for allowlisted soroswap Wasm modules
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The current wasmi interpreter backend should remain the fallback for all unrecognized modules and for all released p26 behavior. For a next-protocol allowlisted soroswap router/pool Wasm hash, Core should be able to execute a prevalidated block-profile backend that preserves the same import calls, trap ordering, fuel/budget schedule, memory/table semantics, and exported-function results while avoiding the generic interpreter dispatch overhead for the module's measured hot basic blocks.

## Mechanism

The accepted native pool work removes some pool exports, but the current trace still spends large aggregate worker time in the generic VM path for remaining soroswap Wasm execution. Prior superinstruction and compiled-backend proposals were rejected for lacking dynamic opcode evidence and a concrete deterministic backend contract; this hypothesis is narrower: add a profiling/manifest step that records hot basic-block opcode sequences and import boundaries for the exact allowlisted soroswap Wasm hashes, then generate a protocol-gated backend for only those blocks while delegating every non-profiled block/import to normal wasmi. If the generated backend covers the router/pair hot loop while preserving wasmi fuel checkpoints and host import order, it can attack the multi-second `Vm::invoke_function_raw` / dispatch envelope rather than sub-threshold per-call cleanups.

## Trigger

Run the current soroswap apply-load benchmark with protocol 27 enabled. The remaining non-native soroswap router/pair execution repeatedly invokes the same Wasm exports and hot basic blocks across thousands of transactions, producing the same interpreter and host-import dispatch shape in every apply window.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:400` — `Vm::invoke_function_raw` is the measured VM execution envelope still exercised by non-native soroswap code.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:260-304` — generated host import wrappers define the import boundary order, fuel refill/drain points, argument conversion, and trap conversion that a block-profile backend must preserve.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:423` — parsed-module validation is a natural place to attach an allowlisted block-profile manifest keyed by Wasm hash/protocol.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:189-195` — module-cache lookup can return either the normal `ParsedModule` or a parsed-module plus generated hot-block profile for next-protocol hashes.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:796-828` — `call_contract_fn` currently chooses native pool shortcuts before falling back to `Vm::invoke_function_raw`; the block-profile backend would be the next fallback before generic interpretation.

## Evidence

The current soroswap trace shows the remaining VM path under `applyLedger`: `Vm::invoke_function_raw` totals 7.146s across 8,399 calls, generated host dispatch `call` totals 4.871s across 25,183 calls, and child host-function wrappers such as `vec_get`, `vec_len`, `bytes_append`, `serialize_to_bytes`, and `get_contract_id` have stable high call counts. The prior rejected "superinstruction" record failed because it had no dynamic opcode/import profile; this hypothesis's first required artifact is that profile, tied to exact Wasm hashes and source locations, before any backend code is generated.

## Anti-Evidence

This remains high risk. It is adjacent to previously rejected compiled-backend and superinstruction ideas, and it is only novel if it first produces an exact dynamic block/import profile plus a deterministic fuel/trap manifest for the current allowlisted Wasm hashes. Broad VM totals include mandatory host calls and storage/auth work that cannot be removed; the backend must isolate interpreter-dispatch savings after 8-way cluster normalization before PoC promotion.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entries `002-compiled-soroban-vm-backend.md + 002-protocol-gated-wasmtime-backend.md + 002-protocol-gated-aot-soroswap-wasm-backend.md` and `002-wasmi-superinstructions-for-soroswap-hot-blocks.md`
**Failed At**: reviewer

### Trace Summary

The apply path is real: parallel Soroban clusters execute `LedgerManagerImpl::applyThread`, each transaction calls `TransactionFrame::parallelApply` and `InvokeHostFunctionOpFrame::doParallelApply`, and the C++ helper crosses into `rust_bridge::invoke_host_function`. The Rust bridge constructs a per-invocation budget and host, calls `e2e_invoke::invoke_host_function`, then `Host::invoke_function` reaches `Host::call_contract_fn`; non-native Wasm contracts instantiate a wasmi VM from the module cache and execute `Vm::invoke_function_raw` inside a `ContractVM` frame. Host imports re-enter through generated dispatch wrappers that transfer fuel to the host budget, charge `DispatchHostFunction`, convert relative/absolute object handles, call the host function, translate errors to traps, and return residual fuel to the VM.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md` — already records compiled/AOT/hash-gated backend variants as NEEDS_REFINEMENT because no backend implementation, deterministic execution contract, fuel mapping, exact metering schedule, or isolated post-normalization saving was specified.
- `ai-summary/fail/soroban/summary.md` — already records wasmi superinstructions for soroswap hot blocks as rejected because broad VM aggregates include host calls, storage/auth work, and fuel transfers, and the proposal lacked dynamic opcode counts plus a trap/fuel correctness contract.
- `src/ledger/LedgerManagerImpl.cpp:2483-2518` — worker threads process each transaction in deterministic cluster order and call `parallelApply` before committing successful per-tx effects.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1377` — the Soroban operation helper invokes the Rust bridge with per-transaction host-function XDR, resources, footprint entries, auth, PRNG seed, rent config, and module cache.
- `src/rust/src/soroban_proto_any.rs:310-354,391-452` — the bridge catches panics, constructs the budget from protocol cost params, then calls the protocol-specific host invocation with the shared module cache.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-552` — `e2e_invoke` decodes resources and ledger state, builds `Storage` and `Host`, installs ledger/auth/source/module-cache state, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1732-1802,782-828` — `Host::invoke_function` dispatches invoke-contract calls through `call_contract_fn`; the only existing hash-gated native shortcuts are the soroswap pool getter/swap paths before the generic Wasm fallback.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1395-1508` — `instantiate_vm` checks storage liveness, fetches an `Arc<ParsedModule>` from the module cache on hits, and otherwise parses a throwaway wasmi module from storage.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,85-95,160-195` — the module cache is a shared wasmi `Engine`/`Linker` plus `BTreeMap<Hash, Arc<ParsedModule>>`; it has no backend/profile abstraction beyond returning the cached parsed module.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:146-153,212-228,403-454` — `ParsedModule` stores only the wasmi module, contract protocol, and cost inputs; import validation checks protocol gates but does not attach a block profile or deterministic backend manifest.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218,271-411` — VM instantiation and invocation are wasmi-specific; `invoke_function_raw` marshals arguments and `metered_func_call` resolves the export, transfers fuel, executes `Func::call`, returns fuel, and converts/traps results.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:180-304` — generated import wrappers define the VM-to-host boundary semantics that any alternate backend would need to reproduce exactly.

### Why It Failed

This is not novel. The new "block-profile backend" wording is a combination of the already-investigated hash-gated compiled/AOT backend family and the already-investigated soroswap hot-block superinstruction idea. The only added element is a statement that a dynamic profile/manifest should be produced first, but the hypothesis does not provide that artifact, an executable backend design, a fuel/trap equivalence contract, or an isolated estimate of interpreter-dispatch savings after subtracting mandatory host calls and normalizing across the configured clusters. Those are precisely the blockers recorded in the retained fail-summary entries.

### Lesson Learned

Future VM-backend hypotheses need to bring the missing artifact, not merely require it: dynamic opcode/basic-block and import-boundary measurements for exact Wasm hashes, an implementation-level backend contract, deterministic fuel/trap mapping, and a post-normalization saving estimate that excludes mandatory host-function work.
