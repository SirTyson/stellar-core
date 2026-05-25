# H002: Footprint-Resolved Native Soroswap Router Swap Without Pair-ID Hash Rebuild

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: High
**Impact**: Soroswap apply-time reduction by removing the remaining top-level router Wasm frame in the exact benchmark route
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the next-protocol apply-load Soroswap benchmark, a top-level router `swap_exact_tokens_for_tokens` invocation over the fixed two-token route should produce the same token transfers, pair reserve update, pair swap event, router return value, auth use, TTL effects, and fallback errors as the current Wasm router path. Released p26 ledgers, non-matching router code hashes, non-two-token paths, malformed arguments, missing footprint entries, non-SAC tokens, and non-matching pair layouts should continue through normal Wasm execution.

## Mechanism

After the accepted native pool getter, native pair swap, direct SAC balance, raw instance-storage, and sparse ledger-change optimizations, the trace still shows roughly one remaining Wasm VM instantiation per applied soroswap transaction. The current generic router path pays `Vm::instantiate_wasmi`, `Vm::invoke_function_raw`, generated host dispatch, and router bytecode execution to compute a fixed-route amount and call the already-native pair path. A new exact-shape router fast path could avoid the previously-regressing pair-id SHA/XDR rebuild by resolving the pair contract id from the transaction footprint / already-loaded pair instance rather than recomputing it, then directly enter the existing native pair swap helper and construct the router return vector from the resulting amounts.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current next-protocol branch and inspect the soroswap apply trace. Each top-level soroswap transaction still invokes the router Wasm once, even though its downstream pool getter and pair `swap` calls are now native for the benchmark's exact pair code hash and storage layout.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-826` — `call_contract_fn` only recognizes native pool getter/swap calls after loading a contract instance; router Wasm calls fall through to `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1375` — existing native pair `swap` helper that a router exact-shape path could reuse after resolving the pair id without re-hashing.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1530-1545` — cached-module path still constructs a fresh wasmi store/instance for each non-native router invocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-186,191-215` — per-invocation wasmi store and instance construction that remains hot for router frames.

## Evidence

The current Tracy trace confirms the remaining VM/router cost is inside `applyLedger`: `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` has 8,775 calls, 506,902,410 ns total, with unwrap containment showing 8,749 events and 503,544,865 ns inside `applyLedger`; the broader `Vm::instantiate_wasmi` family has 26,247 in-apply events and 1,154,380,961 ns total. `Vm::invoke_function_raw` at `soroban-env-host/src/vm.rs:400` totals 7,960,942,695 ns, while the generated VM host `call` wrapper at `soroban-env-host/src/vm/dispatch.rs:304` has 26,079 in-apply events and 5,428,387,766 ns total. These zones remain descendants of the measured apply path, not TX-set construction.

This hypothesis deliberately differs from the earlier native-router attempt that rebuilt pair ids through new XDR/SHA256 work and retained expensive subcall scaffolding. The proposed trigger is narrower: use the current footprint-loaded state to identify the already-present pair contract and reuse the accepted native pair path, so the router fast path removes the last top-level router VM frame without adding a competing hash/serialization phase.

## Anti-Evidence

Native router work is a known danger zone: a previous router fast path regressed because new native-side metered XDR, SHA256 pair derivation, host-object allocations, and retained subcall machinery outweighed the removed frame. This hypothesis is only viable if the pair id is resolved without recomputing the Soroswap salt hash, observable execution order remains deterministic, all non-exact routes fall back to Wasm, and the direct path avoids introducing new work comparable to the router frame it removes. The reviewer should require focused instrumentation showing most remaining top-level router instantiations are exact-route matches before approving a PoC.
