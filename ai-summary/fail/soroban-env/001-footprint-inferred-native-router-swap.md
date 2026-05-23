# H001: Footprint-Inferred Native Router Swap Trampoline

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: High
**Impact**: >10% soroswap apply-time reduction if the remaining per-transaction router Wasm frame is removed without reintroducing the failed native-router SHA and allocation overheads
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the current next-protocol soroswap workload, a top-level two-token router `swap_exact_tokens_for_tokens` invocation should produce the same SAC transfer, pair swap, authorization, TTL, storage, event, and error behavior as the router Wasm path. The host should not need to instantiate and run the fixed router Wasm frame when the route, footprint, and pair instance already identify the single vendored pool that the router will call.

## Mechanism

The accepted native pool getter and pair `swap` fast paths removed the inner pair Wasm frames, but every successful transaction still appears to instantiate and execute one Wasm contract frame, matching the router call. A previous native-router attempt regressed because it recomputed the pair contract id with new metered XDR/SHA work and retained expensive native-side scaffolding; a narrower trampoline can instead validate a two-token route, scan the enforcing footprint/storage map for the unique vendored Soroswap pool instance whose token fields match that route, and then delegate to the already-accepted native pair swap/SAC transfer path in deterministic order. This avoids the remaining router VM instantiation, router linear-memory host calls, and pair-id hash construction while preserving observable ledger output through the existing native pair mechanics.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on the current next-protocol soroswap workload (`soroswap, TX=2000, T=8`). Each accepted router transaction with a two-token path currently falls through `Host::call_contract_fn` to `instantiate_vm` for the router Wasm, then performs router host calls to build/serialize/hash the pair key before entering the native pair path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:785-820` — `call_contract_fn` only has native fast paths for the pool Wasm hash; non-pool router Wasm still falls through to `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1379` — existing native pool `swap`, SAC transfer, and direct SAC balance helpers to reuse after the router trampoline validates the exact pair.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:180-320` — enforcing storage contains the declared footprint and accepted side indices that can be scanned/queried deterministically for candidate pair contract instances.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-206,393-411` — remaining Wasm instantiation and raw VM invocation costs avoided by matching router calls.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:250-304` — router host-function dispatch wrapper and fuel handoff avoided for the matched route.

## Evidence

The current accepted soroswap trace shows `applyLedger` total time of 4,475,605,676 ns across 71 ledgers. `Vm::instantiate_wasmi - instantiate` has 459,741,743 ns self-time across 7,956 calls, with unwrap containment showing 7,910 of those calls inside `applyLedger`; this is approximately one remaining Wasm instantiation per applied router transaction after the pool getter and pair Wasm frames were natively handled. Router-shaped dispatch work is still visible inside apply: `call` at `vm/dispatch.rs:304` has 1,216,408,561 ns self-time, while `vec_get`, `vec_len`, `bytes_append`, `serialize_to_bytes`, `get_contract_id`, and `compute_hash_sha256` together account for hundreds of milliseconds of self-time in the same dispatch wrapper. Source inspection shows the accepted native pair path is already gated by exact pool Wasm hash and instance token/reserve layout, so a router trampoline can validate the route against actual footprint/storage entries instead of recomputing the pair id through the router's Wasm bytecode.

## Anti-Evidence

This is adjacent to the rejected native-router family, so the PoC must explicitly avoid the prior failure mode: no new pair-id SHA/XDR derivation on the hot path, no broad native reimplementation that duplicates existing pair logic, and no nondeterministic footprint search. The enforcing footprint may contain more than one candidate pool in future workloads; the trampoline must require a unique exact vendored-pool match for the two-token route and fall back to Wasm otherwise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate/refinement of `ai-summary/fail/soroban-env/summary.md` entries `001-native-soroswap-router-swap.md` and `024-cache-router-pair-salt-sha256.md`
**Failed At**: reviewer

### Trace Summary

The current accepted apply-load source invokes `swap_exact_tokens_for_tokens` on the router contract, and `Host::call_contract_fn` only bypasses Wasm for contracts whose executable hash is the vendored Soroswap pool hash. Router calls therefore still instantiate a VM, but a native replacement must reproduce the same router-level authorization root, input SAC transfer, amount-out calculation, pair invocation, frame rollback, and event/storage side effects. The proposed footprint scan can recover the pair contract id from the declared read-write pair instance and avoid the failed pair-id XDR/SHA derivation, but it does not remove the remaining native-side subcall scaffolding that already made the previous native-router PoC regress in all authoritative benchmark runs.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3427-3496` — the benchmark builds a router `swap_exact_tokens_for_tokens` invocation with 5 args; the footprint includes router instance/code, token SAC instances, pair code, token trustlines, pair SAC balances, and the pair instance, and the auth tree roots at the router call with a token-in `transfer` subinvocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — `call_contract_fn` retrieves the target instance, dispatches native fast paths only for the pool Wasm hash, and otherwise calls `instantiate_vm`; a router trampoline would be another native contract-frame replacement before this fallback.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — the accepted native pair `swap` path requires a concrete pair `ContractId`, still performs output SAC transfer, direct/indirect balance reads, reserve updates, K-invariant checks, and event construction inside a normal frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1366` — native pair helpers still invoke SAC `transfer` through `call_n_internal` and only optimize SAC `balance` reads; a router trampoline would still need the input-side SAC transfer and pair call mechanics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1531-1729` — `call_n_internal` enforces reserved-function checks, reentry policy, diagnostics, auth frame advancement, and then calls `call_contract_fn`; these costs remain for behavior-preserving native subcalls.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:242-267,283-353` — enforcing storage/footprint side indices make deterministic key lookup feasible, but scanning them only removes pair-id discovery work, not the mandatory router semantics.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-206,393-411` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:240-304` — these are the router VM instantiation/raw invocation/host-dispatch costs the replacement targets.

### Why It Failed

This is substantially the same optimization class as the failed native router fast path: replacing the router Wasm frame for `swap_exact_tokens_for_tokens`. The one meaningful refinement here is to infer the pair from the footprint/storage map instead of recomputing the pair contract id, but that subproblem has also been investigated: the whole apply-contained `compute_hash_sha256` upper bound was recorded as about 1.7% of apply time, with the pair-salt subset smaller and below the objective's Medium threshold. Removing that SHA/XDR overhead from the already-regressing native-router PoC does not address the remaining required costs called out in the prior failure — host-object construction, router-frame/auth behavior, input SAC `transfer`, native pair `swap` subcall machinery, storage/event materialization, and exact rollback behavior. Under the objective rules, this remains below the Medium/High bar and should not proceed as a new PoC.

### Lesson Learned

For router-level Soroswap shortcuts, recovering the pair id cheaply is not enough. A viable future variant must remove a larger mandatory phase than pair-id derivation and must quantify net savings after preserving the router auth tree, SAC transfer, pair swap frame, storage writes, events, and rollback semantics; otherwise it is the same native-Wasm-frame replacement trap already rejected by benchmark results.
