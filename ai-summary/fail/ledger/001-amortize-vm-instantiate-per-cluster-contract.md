# H001: Amortize `Vm::instantiate` across same-contract invocations within a Soroban cluster

**Date**: 2026-05-26
**Subsystem**: ledger (Soroban worker path)
**Severity**: Low (below objective floor)
**Impact**: per-worker apply time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

On a soroswap workload where every invocation in a cluster targets the same 2–3
contracts (Soroswap router/pair + SAC), `Vm` runtime instantiation work
(linker setup, memory allocation, table population) should be paid roughly
once per distinct contract per worker rather than once per `InvokeHostFunctionOp`.
The compiled-module cache already amortizes Wasm compilation, but each
invocation still constructs a fresh `Vm` runtime instance via
`Vm::instantiate` / `Vm::instantiate_wasmi - instantiate`. If a cluster
runs 100+ swap invocations sequentially on the same pair contract, the
runtime instantiation cost should fold into a single setup at cluster
start (or be cached per-worker and rebuilt only when the contract code
ledger entry mutates), not paid 100+ times.

## Mechanism

`Vm::instantiate` is invoked once per `invokeHostFunction` call.
Tracy (diagnostic trace `9e61f0301cf2-…-02-soroswap-tx-2000-t-8.tracy`) shows
`Vm::instantiate` is 13.62% worker-aggregate of `applyLedger` (~600 ms across
71 ledgers, 8079 calls). Divided by `NUM_CLUSTERS=8` parallel workers this
is 1.70% per-worker = ~1058 µs/worker/ledger. Even an ideal cache that
instantiates each unique contract exactly once per worker per ledger
(~2–3 contracts on the soroswap benchmark) would leave ~80–150 µs of
unavoidable instantiation work per worker per ledger, recovering at most
~880 µs/worker = ~1.4% applyLedger wall-time. The Rust-side `Vm` carries
mutable engine + linker state per invocation and the host requires a fresh
`VmCaller` context per call, so any caching must invalidate aggressively
when the contract's CONTRACT_CODE entry changes within the same ledger
(common for upload+invoke patterns but not for soroswap steady-state).

## Trigger

Apply-load soroswap benchmark with `T=8` clusters; 8079 `InvokeHostFunctionOp`
applies hit ~3 distinct contracts. Each invocation reconstructs a `Vm`
runtime from scratch even though the compiled module is cached.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs` — `Vm::instantiate` /
  `Vm::instantiate_wasmi - instantiate`
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-638` —
  `invokeHostFunction` Rust bridge entry, calls Rust which constructs a
  new `Vm` per invocation
- `src/ledger/LedgerManagerImpl.cpp:2484-2521` — `applyThread`: drives
  sequential per-cluster invocations where the cache would apply

## Evidence

- Apply-window overlap analysis on
  `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`:
  - `Vm::instantiate` = 13.62% worker-aggregate (600,942,636 ns / 71 ledgers / 8 workers ≈ 1058 µs/worker/ledger)
  - `Vm::instantiate_wasmi - instantiate` = 10.53% worker-aggregate (mostly inside the outer zone)
  - 8079 instantiations across 71 ledgers = ~14 per worker per ledger
- Soroswap benchmark uses only the router/pair Wasm + SAC = at most ~3 distinct contracts
- Compiled-module cache (`SharedModuleCacheCompiler`) already amortizes
  compilation cost but NOT runtime instance construction

## Anti-Evidence

- `Vm` runtime carries per-invocation mutable state (linker, memory, fuel)
  and is consumed by the host invocation context; a "reusable" `Vm` would
  need a reset/clone path that does not currently exist
- Even with ideal per-worker per-contract caching, projected savings are
  ~880 µs/worker/ledger = ~1.4% applyLedger — below the objective's 3%
  Medium floor
- Per-worker cost projection assumes the slowest worker also benefits;
  in reality workers are imbalanced and the actual wall-time win is
  likely ≤1.2%

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — no prior Vm/instantiate-amortization hypothesis in the
ledger or soroban-env fail summaries

### Why It Failed

Even under the most optimistic assumption (single instantiation per worker
per contract per ledger), the recoverable wall time is ~1.4% of applyLedger
— below the 3% Medium floor required by `optimize-soroswap`. The
hypothesis is also blocked by `Vm`'s consumed-by-invocation lifetime: any
cache must invent a clone-or-reset primitive in vendored
`soroban-env-host` (a per-protocol-version submodule), which adds
correctness risk and protocol-compatibility surface for a sub-Medium
projected gain.

### Lesson Learned

For Soroban worker-time optimizations, always (1) normalize aggregate
Tracy time by `NUM_CLUSTERS`, (2) check whether the proposed cache target
sits in vendored `soroban-env-host` (cross-version compatibility raises
the bar), and (3) project both best-case savings and the residual
unavoidable work before drafting. Compiled-module caching is already
in tree; runtime-instance caching for Wasm engines is a fundamentally
different (and architecturally larger) change that cannot be justified
by sub-2% per-worker wins.
