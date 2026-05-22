# H001: Router-Only Native Trampoline for Fixed Two-Hop Soroswap Swaps

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce soroswap apply time by bypassing the top-level router Wasm while preserving pool Wasm and SAC semantics
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the apply-load soroswap shape, a transaction invoking the known router code hash with `swap_exact_tokens_for_tokens(amount_in=100, amount_out_min=0, path=[token_in, token_out], to=source, deadline=u64::MAX)` should produce the same auth checks, nested SAC transfer, pair `swap` call, router swap event, return `Vec<i128>`, diagnostic behavior, and ledger writes as the generic router Wasm path. The host should not need to instantiate and interpret the router Wasm just to execute this fixed control-flow wrapper around existing host calls to SAC and the pair contract.

## Mechanism

The current path treats the top-level router exactly like arbitrary Wasm: `Host::call_contract_fn` retrieves the instance, constructs a fresh `Vm`, pushes a `ContractVM` frame, and runs `Vm::invoke_function_raw`. For the benchmark trigger, the router source shows a narrow deterministic path: validate initialization/deadline/nonnegative args, compute one `get_amount_out`, transfer the input SAC amount to the pair, call the pair's `swap`, publish one router `swap` event, and return the two-element amounts vector. A next-protocol code-hash/function trampoline can perform only the router wrapper natively while still entering the existing SAC native transfer and existing pair Wasm `swap`, removing one of the three per-swap Wasm invocations without needing to specify or reimplement pair storage semantics.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) with the next-protocol baseline. Every generated transaction calls the same router contract/function with a two-address path and fixed amount/deadline shape in `ApplyLoad::generateSoroswapSwaps`; the trampoline should reject any different function name, argument count/type, path length, code hash, protocol, or auth shape and fall back to the generic Wasm path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` - branch point in `Host::call_contract_fn` before `instantiate_vm` for a code-hash/function-specific router trampoline.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-805` - current module-cache path still instantiates Wasm even for cached router modules.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` - per-router-call `wasmi::Store`/`Instance` construction avoided by the trampoline.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` - per-router-call argument marshalling and raw Wasm function invocation avoided by the trampoline.
- `src/simulation/ApplyLoad.cpp:3382-3505` - benchmark generator fixes the router function, path length, amount/deadline, footprint, and source-account auth tree.
- External semantic reference: `soroswap/core@bb90a655/contracts/router/src/lib.rs:577-620` and `:133-166` - exact router `swap_exact_tokens_for_tokens` and one-hop `swap` control flow.

## Evidence

The current trace from `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports apply-contained `Vm::invoke_function_raw` self-time of 696,879,003 ns across 20,313 calls, `Vm::instantiate_wasmi - instantiate` self-time of 1,315,387,452 ns across 20,389 calls, and `call` self-time of 922,554,179 ns across 40,605 host imports; unwrap containment confirmed all events for these zones are descendants of `applyLedger`. The call counts line up with roughly three Wasm invocations per swap (router plus pair `get_reserves`/`swap`), so removing only the router invocation targets about one third of the residual VM instantiation/interpreter surface while preserving the existing pair and SAC execution paths.

This refines, rather than duplicates, the prior under-specified full router/pair native bypass: the proposed branch does not reimplement pool reserve storage, pool events, or SAC token accounting. The external router source gives a concrete wrapper specification, and the current apply-load source gives a tight trigger that can be validated cheaply before taking the fast path.

## Anti-Evidence

The trampoline must still reproduce router metering, event XDR shape, recoverable contract errors, auth exhaustion, and return-value conversion for a new protocol; p26 exact Wasm metering cannot change. The projected Medium impact depends on router Wasm being close to one third of the remaining VM cost; a PoC should add temporary per-contract-code counters for `Vm::instantiate_wasmi`, `Vm::invoke_function_raw`, and host-call counts to confirm router-specific time before implementation. If router-specific VM time is materially smaller than the even-split estimate, the idea should be rejected below the 3% objective threshold.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to prior native Soroswap records, but narrower than the rejected full router/pair and pool-only precompile hypotheses
**Failed At**: reviewer

### What's Wrong

The router-only branch point is real and the apply-load workload does invoke a fixed two-address `swap_exact_tokens_for_tokens` shape, but the hypothesis still does not isolate enough router-specific cost to clear the objective's Medium floor. The Tracy evidence is aggregate VM/import self-time across router, pair `get_reserves`, pair `swap`, setup residue, and all worker contexts; the claimed one-third split is an assumption, not a traced per-code-hash measurement.

The correctness specification is also still incomplete for a native handoff. A native router frame would need to preserve `require_auth()`'s current-frame argument behavior, router contract IDs on events and TTL/storage access, exact `CombinedRouterError` codes, `pair_for` salt/hash semantics, `get_amount_out` overflow/trap behavior, contract event XDR encoding for `SwapEvent`, rollback/error mapping, and a next-protocol metering schedule. The vendored router Wasm is a mainnet artifact (`4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07`), while the source is only a reference, so equivalence must be specified or measured against the actual Wasm artifact before PoC.

### Alternative Angle

First add diagnostic-only attribution around `Host::call_contract_fn`, `Vm::instantiate_wasmi`, `Vm::invoke_function_raw`, and host import dispatch keyed by contract code hash / function name, then normalize by apply-stage parallelism and compare the router-only portion against top-line apply time. If the isolated router wrapper cost reproducibly exceeds the 3% apply-time floor, refine this into an explicit next-protocol native-contract specification with a new production frame variant (or equivalent) that supplies router contract context while delegating SAC transfer and pair Wasm calls through the existing `call_n_internal` path.

### Additional Code Paths

- `ai-summary/fail/soroban/summary.md` — prior native Soroswap records reject full router/pair and pool-only precompile proposals as under-specified; this router-only version is distinct but must still solve the same semantic/metering-spec problem.
- `src/simulation/ApplyLoad.cpp:3382-3505` — confirms the benchmark generates fixed router args, two-token path, source-account auth with a nested SAC transfer sub-invocation, and a footprint that keeps pair code and SAC instances available.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — current Wasm branch always instantiates a `Vm` and enters `Frame::ContractVM`; a native trampoline would need an equivalent contract frame for auth, events, instance storage, and rollback.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3605-3631` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` — `require_auth()` derives authorized arguments from the current contract frame, so a router trampoline cannot run as a bare host-function helper.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — router events derive their contract ID from the current frame; native event emission must preserve this context and exact XDR shape.
- `soroswap/core@bb90a655 contracts/router/src/lib.rs:577-620`, `contracts/library/src/quotes.rs`, `contracts/library/src/tokens.rs`, and `contracts/router/src/error.rs` — define the source-level swap flow, arithmetic/error codes, pair-address derivation, and event/error surfaces that still need an exact artifact-backed spec.
