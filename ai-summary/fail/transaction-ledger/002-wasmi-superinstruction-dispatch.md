# H002: Add deterministic wasmi superinstructions for hot soroswap bytecode

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / Soroban VM apply
**Severity**: High
**Impact**: Soroswap apply-time reduction by restructuring the dominant guest-Wasm interpreter phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap router and pair Wasm execution should produce identical stack, memory, trap, fuel, host-call, event, and ledger effects. The interpreter should not pay one large bytecode-dispatch step for every tiny straight-line operation when the translated wasmi bytecode contains deterministic adjacent instruction pairs or triples that can be fused safely.

Correct fusion must leave `ConsumeFuel`, branches, calls, host imports, memory/table growth, fallible traps, and observable call boundaries in the same relative order. Branch targets must not land inside a fused sequence.

## Mechanism

The pinned `soroban-wasmi` executor runs one internal `Instruction` at a time through `Executor::execute`. Prior quickening attempts failed when they targeted Stellar's `ModuleCache`, but the remaining opportunity is inside the wasmi translator/executor itself: add a small set of fused internal bytecode variants for measured hot straight-line sequences and execute each with one dispatch while performing the same primitive stack operations.

This is deterministic because fusion is a pure function of already-validated bytecode at translation time. It preserves metering if fusion never crosses `ConsumeFuel` and leaves fuel instructions in the stream; it preserves traps by excluding fallible instructions or any instruction whose trap timing can change. The improvement theory is that repeated soroswap guest execution spends enough time in the interpreter envelope that reducing instruction dispatch on the router/pair hot loops can move top-line apply time.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load trace from `ai-summary/CURRENT_STATE.md`, then add temporary deterministic counters in the pinned wasmi executor or translator to report the most frequently executed adjacent instruction pairs/triples under `Host::invoke_function`. Implement only the top measured fusions that do not include fuel, control-flow, calls/imports, memory growth, traps, or branch-target interiors, then compare three non-Tracy matrix runs against the current 270-276 ms soroswap median range.

## Target Code

- `src/rust/soroban/p26/Cargo.lock:1755-1762` — pins the `soroban-wasmi` dependency; a PoC must patch the pinned fork/revision, not add a local Stellar-side cache.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:478-480` — each apply-path host invocation reaches `Host::invoke_function` after bridge/storage setup.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — Soroban marshals arguments and enters wasmi through `Vm::invoke_function_raw`.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/engine/executor.rs:224-446` — `Executor::execute` dispatches one internal instruction at a time through the interpreter loop.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/engine/bytecode/mod.rs:37-145,207-360` — internal wasmi `Instruction` variants are the right level to add fused variants.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/engine/func_builder/inst_builder.rs:129-202` — translated instruction construction is the deterministic hook for pair/triple fusion after branch offsets are known.

## Evidence

The target VM envelope is inside the measured apply path. In the current soroswap Tracy trace, timestamp filtering to `applyLedger` windows shows `Host::invoke_function` totaling **9,824,196,894 ns** over 6,776 calls, `Vm::invoke_function_raw` totaling **12,842,366,133 ns** over 20,313 calls, and the generated wasmi/host `call` zone totaling **9,353,235,883 ns** over 40,605 calls. These events occur under `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply`.

The source has a structural interpreter-dispatch pattern: each guest instruction fetches an internal instruction, enters one match arm, performs a small primitive operation, and advances the instruction pointer. Soroswap repeatedly executes the same router/pair Wasm, so a small sequence histogram should identify whether a few deterministic pairs/triples cover enough guest instructions for a Medium-or-better win.

## Anti-Evidence

The cited VM zones are inclusive and include mandatory guest logic, host imports, argument conversion, fuel synchronization, and memory operations. A PoC must first isolate instruction-dispatch coverage with counters; otherwise this risks repeating prior over-attribution of broad VM zones. Fusion must be conservative: crossing fuel, branch, import, call, memory-growth, or trap boundaries can change consensus-visible behavior. Adding too many fused variants can also bloat bytecode/executor code and hurt instruction cache, so only top measured sequences should be attempted.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/001-wasmi-superinstruction-dispatch.md`
**Failed At**: reviewer

### Trace Summary

This hypothesis is substantially equivalent to the previously investigated `001-wasmi-superinstruction-dispatch` record: both propose deterministic fused internal wasmi bytecode variants for hot soroswap straight-line sequences, both target the same pinned `soroban-wasmi` translator/executor, and both require preserving fuel/control-flow/trap boundaries. I spot-checked the current path from `e2e_invoke::invoke_host_function` through `Host::invoke_function`, `Vm::invoke_function_raw`, and the pinned wasmi `Executor::execute` loop; the same one-instruction-at-a-time interpreter structure still exists. However, the prior investigation already proceeded through reviewer, PoC, and final review, and was rejected because all three authoritative non-Tracy soroswap runs regressed versus baseline.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/001-wasmi-superinstruction-dispatch.md:47-91` — prior reviewer accepted the same superinstruction mechanism as viable at Medium severity after tracing the exact host/VM/wasmi execution path.
- `ai-summary/fail/transaction-ledger/001-wasmi-superinstruction-dispatch.md:95-145` — prior PoC/final-review-needs-revision notes show the same fused local/arithmetic wasmi superinstruction implementation and reproducibility requirements.
- `ai-summary/fail/transaction-ledger/001-wasmi-superinstruction-dispatch.md:247-294` — final review rejected the implemented optimization because soroswap medians regressed from 272.249541 / 275.885919 / 270.551362 ms to 277.148919 / 280.837352 / 276.348005 ms.
- `src/rust/soroban/p26/Cargo.lock:1755-1762` — p26 still pins `soroban-wasmi` to `0.31.1-soroban.20.0.1` at the Stellar wasmi revision targeted by both hypotheses.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:478-480` — host invocation still reaches the `Host::invoke_function` Tracy span on the apply path.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` still marshals args and enters the metered wasmi function call.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:224-446` — the pinned executor still dispatches each internal `Instruction` through a large match loop, matching the duplicate hypothesis target.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/bytecode/mod.rs:37-145` — internal bytecode variants still include control-flow, fuel, and call boundaries that the duplicate superinstruction proposal would need to avoid.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/func_builder/inst_builder.rs:129-202` — instruction construction/finalization remains the deterministic hook identified in the prior investigation.

### Why It Failed

The exact optimization family has already been investigated and failed final review. The prior PoC implemented conservative first-word wasmi superinstructions for common infallible local/arithmetic pairs, but authoritative soroswap apply-load benchmarking showed a consistent 1.8-2.14% regression, so re-promoting the same hypothesis would duplicate a rejected investigation rather than advance the objective.

### Lesson Learned

The structural existence of interpreter dispatch overhead inside `closeLedger` is not sufficient for this objective. For wasmi superinstructions, the selected fused sequences must be proven by counters and then by repeated top-line apply-load runs; the prior concrete implementation showed that plausible local/arithmetic fusions can worsen real soroswap apply time, likely from added dispatch/code-size effects outweighing saved interpreter steps.
