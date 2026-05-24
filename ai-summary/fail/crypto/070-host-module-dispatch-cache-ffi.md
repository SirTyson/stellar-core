# H070: Cache resolved HostModule on C++ side to skip per-FFI `get_host_module_for_protocol` linear walk

**Date**: 2026-05-24
**Subsystem**: rust (bridge dispatch)
**Severity**: Low (below objective floor)
**Impact**: per-FFI fixed-cost dispatch overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For every `rust_bridge::invoke_host_function`, `compute_transaction_resource_fee`,
`compute_rent_fee`, and `contract_code_memory_size_for_rent` FFI crossing on the
apply path, the Rust side should dispatch to a protocol-specific
`HostModule` function-pointer table with constant-time overhead. Because the
`(config_max_protocol, ledger_protocol_version)` pair is fixed for the duration
of a ledger close, the resolved `&'static HostModule` pointer could be cached
once per ledger and reused for every subsequent FFI invocation, replacing the
linear walk + asserts in `get_host_module_for_protocol` with a single load.

## Mechanism

`src/rust/src/soroban_proto_all.rs:1198 get_host_module_for_protocol` is
called once at the top of every `invoke_host_function` (line 23), every
`compute_transaction_resource_fee` (line 69), every `compute_rent_fee`, etc.
It linearly walks `HOST_MODULES` (currently 6 entries: p21..p26), running an
`assert!` and two range comparisons per iteration. For soroswap, the apply
path performs ~2000 `invoke_host_function` calls per ledger × 65 ledgers
≈ 130K dispatch lookups, plus ~2000 `compute_transaction_resource_fee` calls
per ledger via `computePreApplySorobanResourceFee`
(`src/transactions/TransactionFrame.cpp:1936/2109/2174`). Caching the resolved
`HostModule` pointer in C++ (e.g., a `thread_local` keyed on protocol pair, or a
`rust_bridge::cache_host_module_for_ledger(...)` call at `closeLedger` entry)
would replace the linear walk with a single indirect call. The deviation is
that today, every FFI crossing pays the dispatch cost — the cache would
eliminate it.

## Trigger

Standard `apply-load --mode benchmark-model-tx --model soroswap` workload at
p26 reproduces the dispatch cost on every FFI invocation. Counting calls via
ftrace on `get_host_module_for_protocol` would show ~150K invocations per
65-ledger run.

## Target Code

- `src/rust/src/soroban_proto_all.rs:1198-1218` — `get_host_module_for_protocol`
  linear walk
- `src/rust/src/soroban_invoke.rs:23,69` — call sites at the top of each FFI
  entrypoint
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575` — main
  `invoke_host_function` call site
- `src/transactions/TransactionFrame.cpp:1192` — `compute_transaction_resource_fee`
  call site

## Evidence

- 6-entry linear scan with one `assert!` and two `u32` comparisons per
  iteration: roughly 10–30 ns per call in Rust release builds.
- Called once per `invoke_host_function` and once per fee FFI; aggregate count
  is in the high six figures across a soroswap run.
- The resolved pointer is genuinely invariant for the duration of a ledger
  (and in practice for the lifetime of the process: `config_max_protocol`
  cannot change at runtime, and `ledger_protocol_version` is stable within a
  ledger close).

## Anti-Evidence

- Meta-Pattern 8 (FFI bridge surface ~50 ms total across the soroswap trace):
  the entire bridge wrapper budget — including marshalling, cxx thunks,
  exception-translation prelude, and dispatch — is capped at ~50 ms aggregate.
  Dispatch is a strictly smaller subset of that, putting it well under 10 ms
  aggregate even before subtracting the part that cannot be removed (the
  indirect call to `hm.invoke_host_function` itself).
- Meta-Pattern 12 (parallel-worker normalization): the per-op FFI calls are
  inside `applySorobanStageClustersInParallel`, so aggregate Rust-side
  dispatch time must be divided by `NUM_CLUSTERS=8` to convert to wall-clock
  apply impact. A 10 ms aggregate becomes ~1.25 ms wall-clock per run,
  ~19 µs per ledger — three orders of magnitude below the 6.5 ms/ledger
  Medium floor.
- Branch prediction makes the linear walk effectively a single mispredicted
  branch per call (after warmup the walk always exits at the same iteration);
  modern CPUs absorb this to single-digit nanoseconds per call.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; distinct from H037
(`getCachedLedgerInfo` cost-params caching) and H038 (per-tx SorobanResources
pre-encode), which target marshalling of FFI input buffers rather than the
Rust-side protocol dispatch function.

### Why It Failed

Bounded structurally by Meta-Pattern 8 (FFI bridge surface ~50 ms aggregate)
and further by Meta-Pattern 12 (8× parallel-worker normalization). A
realistic upper bound on dispatch overhead is well under 10 ms aggregate;
after normalization, ~1.25 ms wall-clock per run, single-digit µs per ledger.
Three orders of magnitude below the 6.5 ms/ledger Medium floor and still well
below the 1% Low floor. The hypothesis is a clean cosmetic optimization but
cannot move the headline benchmark metric.

### Lesson Learned

Per-FFI fixed-cost optimizations inside the cxx bridge wrappers
(`get_host_module_for_protocol` dispatch, exception-translation prelude,
panic catch-unwind harness) are all bounded by Meta-Pattern 8's ~50 ms
aggregate ceiling. Combined with Meta-Pattern 12's 8× parallel-worker
normalization, no single sub-component of the bridge wrapper can reach Low
(let alone Medium) severity. Future bridge hypotheses must target work that
escapes both ceilings — typically by eliminating an entire FFI crossing
rather than shaving fixed overhead from each.
