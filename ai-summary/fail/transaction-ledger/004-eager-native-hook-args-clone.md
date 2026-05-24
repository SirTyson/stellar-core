# H004: Delay native Soroswap hook argument cloning in `call_contract_fn`

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / Soroban host call dispatch
**Severity**: Low
**Impact**: Remove eager small-vector clones before native Soroswap hook hash/function checks
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`Host::call_contract_fn` should preserve the exact `Frame::ContractVM`, `Frame::NativeContract`, and `Frame::StellarAssetContract` argument vectors observed by authorization, diagnostics, and rollback. Calls that do not match the native Soroswap pool hash or function should not pay extra argument-vector cloning solely to discover that the native hook does not apply.

## Mechanism

`call_contract_fn` creates `args_vec = args.to_vec()` once, then passes `args_vec.clone()` into `try_call_native_soroswap_pool_getter` and again into `try_call_native_soroswap_pool_swap` before either helper has checked the pool Wasm hash, symbol, or argument shape. Router Wasm calls and other non-pool Wasm calls therefore clone their argument vector for native hooks that immediately return `Ok(None)`. Passing `&[Val]` or `&Vec<Val>` into the probes and cloning only after the hash/symbol checks pass would remove those wasted small clones.

## Trigger

Run the current soroswap apply-load benchmark. Each router Wasm call reaches `call_contract_fn` with five arguments and a non-pool Wasm hash; the current source still eagerly evaluates both `args_vec.clone()` arguments before the getter and swap probes return `Ok(None)`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-828` — `call_contract_fn` constructs `args_vec` and eagerly clones it into both native Soroswap probes.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-872` — getter probe only needs an owned vector after protocol/hash/symbol/layout checks pass.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1074` — swap probe only needs an owned vector after protocol/hash/symbol/argument/layout checks pass.

## Evidence

The structural inefficiency is real: Rust evaluates function-call arguments eagerly, so the clone happens even when `wasm_hash.0.as_slice() != SOROSWAP_POOL_WASM_HASH`. The current long-window trace shows `call` at **955.329 ms aggregate** across **4,365** in-window host calls and `Vm::invoke_function_raw` at **1,350.371 ms aggregate**, confirming that non-native router Wasm still runs in the measured apply path.

## Anti-Evidence

The cloned vectors are tiny: the router call has five `Val`s, pool swap has three, and getters have zero. Even if all non-matching router clones were removed, the absolute saving is a handful of word copies per transaction plus a small allocation that the Rust allocator likely serves cheaply. This is a cleanup candidate, not a Medium soroswap optimization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as an eager-clone micro-optimization

### Why It Failed

The candidate removes only two small `Vec<Val>` clones from non-pool Wasm calls and one small clone from matching native hook calls. The per-call vector lengths are 0, 3, or 5, and the visible hot zones are dominated by VM execution, host imports, SAC transfer, storage, budget charging, and frame semantics rather than copying these few `Val`s. The maximum plausible saving is far below the objective's 3% Medium threshold and likely below the 1% noise floor.

### Lesson Learned

Eager argument evaluation can expose real local waste, but small `Val` vector clones at call-dispatch boundaries are not performance targets unless narrow allocation counters show allocator pressure at benchmark scale. Native-hook dispatch refinements must target a larger removable envelope than argument ownership cleanup.
