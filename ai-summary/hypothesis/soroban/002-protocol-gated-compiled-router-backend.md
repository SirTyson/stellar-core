# H002: Protocol-Gated Compiled Backend for Soroswap Router Wasm

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: High
**Impact**: Soroswap apply-time reduction by replacing interpreter execution of the hot router contract with deterministic compiled execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The Soroswap router contract should execute deterministically with the same ABI, host-function import behavior, error/trap mapping, fuel/budget accounting, memory semantics, and emitted side effects as the current wasmi interpreter. For an allowlisted router Wasm hash and protocol version, the apply path should be able to use a compiled backend if it provides the same observable results and a protocol-gated metering schedule.

Unlike wasmi `Store`/`Instance` reuse or `InstancePre` caching, this does not attempt to reuse mutable VM state. Each invocation still gets fresh execution state; the optimization is replacing the interpreter loop for a known hot contract with compiled deterministic code.

## Mechanism

The accepted stack has already native-optimized the pair `swap` and several pool getters, but every benchmark tx still enters the router Wasm for `swap_exact_tokens_for_tokens`. In the current trace, `Host::invoke_function` totals 8.263s across worker threads, `Vm::invoke_function_raw` contributes 0.505s self, and the dispatch `call` zone at `soroban-env-host/src/vm/dispatch.rs:304` contributes 1.166s self over 24,174 host calls. These zones are descendants of the measured `applyLedger` worker envelope, while TX-set construction zones are out of scope.

A router-hash-gated compiled backend can attack the remaining interpreter overhead without depending on unavailable wasmi reset/prelink APIs. It would be selected from `Host::call_contract_fn` only for the known router hash/function shape, would call the same host functions at the same import boundaries, and would flush/check budget at the same public observation points. This is a refinement of prior compiled-backend ideas: start with one allowlisted router module and one benchmark-hot export, not a general VM replacement.

## Trigger

Run the current accepted Soroswap Tracy benchmark and inspect the remaining router/VM zones:

```sh
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
./lib/tracy/csvexport/build/unix/csvexport-release -e /mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy
```

The target workload is the generated two-token `swap_exact_tokens_for_tokens` path. A PoC would route only the apply-load router Wasm hash to the compiled backend and compare three non-Tracy Soroswap runs plus full tests against the current baseline.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-821` — `call_contract_fn` selects native Soroswap pair fast paths and otherwise instantiates/interprets Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` marshals args and enters the interpreter.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` — host-function dispatch boundary used by router execution.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — natural place to attach an allowlisted compiled artifact beside the parsed module and engine.
- `src/simulation/ApplyLoad.cpp:2896-2902` and `:3427-3439` — uploaded router Wasm hash and benchmark-hot export/argument shape.

## Evidence

The remaining router execution is still a dominant parallel-worker envelope after pool-native wins. `Host::invoke_function` totals 8.263s, `parallelApply` totals 11.586s, and `call`/`Vm::invoke_function_raw`/VM instantiation self-time together show that a large fraction of apply worker time remains in VM dispatch/interpreter machinery rather than BucketList or TX-set construction.

Prior failures rejected `InstancePre`, store reset, and pristine snapshots because the pinned wasmi API cannot safely reset mutable VM state. This hypothesis avoids that failed mechanism. Prior compiled-backend hypotheses were too broad; constraining the backend to the known router hash/export gives a concrete first target with an exact benchmark trigger and a fallback to wasmi for every other module/function.

## Anti-Evidence

This is a major protocol-risk change. A compiled backend must have deterministic behavior across platforms, a precise fuel/budget mapping, safe memory/table/global initialization, and byte-for-byte-equivalent traps and host-call ordering. If implementing a backend requires a general Wasm compiler integration rather than a narrow router artifact, the scope may exceed the optimization arc. The reviewer should reject any PoC that only speeds up native host calls or wasmi instantiation while leaving interpreter execution unchanged; those narrower surfaces are already failed as sub-threshold or impossible with the pinned wasmi API.
