# H001: Inline Native Router-to-Pool Swap Handoff

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing a generic host-call frame from the native router/pool path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the post-p26 allowlisted Soroswap router fast path, the router should compute the pair id, amount out, pair reserve update, pair transfer, pair swap event, router swap event, auth consumption, TTL extension, and storage writes in the same deterministic order as the existing router -> pair -> SAC call chain. The implementation should not need to re-enter the generic `call_n_internal` path for `pair.swap` once the native router has already identified the exact allowlisted pair id and read the pair instance storage needed for the same swap.

## Mechanism

The current native router helper still hands off to the native pool by constructing two `Val` amounts, allocating the `swap` symbol, and calling `call_n_internal(&pair_id, ...)`, which pushes another frame, revalidates native-pool matching, reloads/scans pair instance storage, and pays generic host-call dispatch/rollback/auth bookkeeping. A post-p26 inline helper can reuse the router's already-derived `pair_id`, sorted token order, reserves, and recipient to call the native pool swap body directly while preserving the same subcall/event order. This removes one generic `call` layer per swap without adding parallelism or changing observable ledger ordering.

## Trigger

Run the current soroswap apply-load Tracy trace from `ai-summary/CURRENT_STATE.md`:

`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`

The apply-window intersection shows the relevant descendants of `applyLedger` are hot:

- `call` (`soroban-env-host/src/vm/dispatch.rs:304`) — 4.937728356 s inside `applyLedger` across 24,078 calls.
- `Vm::invoke_function_raw` (`soroban-env-host/src/vm.rs:400`) — 7.231631147 s inside `applyLedger` across 8,034 calls.
- `push context` (`soroban-env-host/src/host/frame.rs:223`) — 488.248109 ms inside `applyLedger` across 48,185 calls.
- `storage get` (`soroban-env-host/src/storage.rs:329`) — 718.936767 ms inside `applyLedger` across 328,819 calls.

Prototype a post-p26-only inline router-to-pool handoff and rerun three non-Tracy `scripts/run_apply_load_matrix.py` soroswap runs. A successful PoC should reduce both top-line soroswap medians and diagnostic `call` / pair-frame storage-load counts.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1704-1878` — `call_native_soroswap_router_swap` computes pair id/reserves, then calls `pair.swap` via `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1843-1851` — generic pair `swap` handoff that can be replaced by an inline native-pool helper for the recognized pair.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1218-1415` — `call_native_soroswap_pool_swap` contains the native pool semantics to refactor into a direct helper that accepts precomputed pair context.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1750-1778` — router already derives token order, pair id, and reserves before the second frame is entered.

## Evidence

The source now has both native router and native pool paths, but still composes them through the generic host call boundary. This is narrower than proposing a new native Soroswap precompile from scratch: the hash gates, argument parsing, auth-root consumption, deadline check, pair-id derivation, reserve math, native pool storage schema, and event construction are already present in the same file. The trace confirms the generic host `call` layer remains a large apply-window cost, and the proposed handoff removes one such layer on the headline router -> pair swap path while keeping the two SAC side effects in their original order.

## Anti-Evidence

Prior native-bypass variants failed when they were under-specified or tried to replace the entire router/pair/SAC stack. This hypothesis is only viable if it is limited to the already-recognized post-p26 router and pair paths and if the refactor preserves pair-frame rollback, diagnostic event behavior, auth-tree matching, TTL extension ordering, and the exact next-protocol metering schedule. If the remaining generic `call` self-time is mostly SAC calls rather than the router -> pair handoff, the isolated saving may fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entries for router-only native Soroswap trampoline / exact router swap fast path, native Soroswap router-pair fast path, native-pool call-host-function fast path, and the retained "All Native Soroswap Bypass Variants" blocker
**Failed At**: reviewer

### Trace Summary

The apply-load workload invokes the Soroswap router Wasm directly via `HostFunction::InvokeContract`; there is no native router fast path in the current p26 host source. Router-to-pool calls made by the Wasm router enter the generic `Host::call` import, then `call_n_internal`, and only at `call_contract_fn` can the callee pair match the allowlisted pool hash and switch to `Frame::NativeContract`. Therefore the proposed inline handoff has no existing native-router frame or precomputed router context to reuse, and it reopens the previously rejected native-router/native-bypass class without resolving its semantic and metering blockers.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3427-3479` — soroswap swap transactions target `mSoroswapState.routerContractID` and function `swap_exact_tokens_for_tokens`; the benchmark begins at the router Wasm, not a native router helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:42-49` — the p26 host has an allowlisted Soroswap pool hash only; no router hash or native router constants are present.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` only recognizes native Soroswap pool getters and `swap`; otherwise Wasm contracts are instantiated and executed through `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2592-2624` — Wasm `call` imports unpack args and always call `call_n_internal`, preserving the generic host-call boundary before the callee is identified.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1185` — native pool `swap` matching validates the callee pool hash, function, argument shape, and pool storage layout only after the generic call reaches the pair contract.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — `call_native_soroswap_pool_swap` contains native pair semantics, SAC transfer/balance subcalls, reserve update, and event emission, but it depends on being inside a native pool frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1865` — `call_n_internal` performs reserved-function checks, reentry handling, diagnostics, and then dispatches to `call_contract_fn`; the cited line range is not a native router helper.
- `ai-summary/fail/soroban/summary.md:109,131,181,222` — prior investigations already rejected native router/pair, router-only, native-pool host-call shortcut, and general native Soroswap bypass variants unless a complete binary-derived semantic and next-protocol metering specification is supplied.

### Why It Failed

This is both non-novel and mechanically false in the checked source. The claimed `call_native_soroswap_router_swap` and "already-derived" native router pair context do not exist, and the current optimization surface is the same native Soroswap bypass family already failed for incomplete router semantics, auth-tree behavior, event ordering, exact artifact equivalence, and protocol metering specification.

### Lesson Learned

Do not size or propose router-to-pool inlining from aggregate `call` or VM zones unless the source actually contains a native router frame/helper with reusable state. A viable future router optimization must first provide per-router attribution plus a complete next-protocol native-router specification; narrowing the fusion boundary to the pool handoff does not avoid those prerequisites.
