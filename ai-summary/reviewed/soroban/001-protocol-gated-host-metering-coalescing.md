# H001: Protocol-gated Soroban host metering coalescing for object, XDR, and conversion hot paths

**Date**: 2026-05-02
**Subsystem**: soroban / soroban-env
**Severity**: High
**Impact**: Apply-time reduction in the Soroban host execution phase for soroswap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Under a new protocol gate, Soroban host execution should produce the same ledger entries, contract events, diagnostics, auth effects, and deterministic error ordering as the current p26 implementation, while charging a recalibrated but consensus-defined CPU/memory budget for host-internal object traversal, XDR serialization, and value conversion. Existing p26 ledgers should keep exact p26 per-operation metering; only the new protocol path should use coarser metering units that let the implementation remove repeated tiny `Budget::charge`, object-visit, and XDR-writer calls without pretending to preserve old p26 budget counters.

## Mechanism

Many prior hypotheses failed because they tried to remove physical work while preserving p26's exact per-call metering sequence. The current trace still shows the combined host-internal metering surface as a dominant apply descendant: `charge` at `soroban-env-host/src/budget/dimension.rs:176` has 1,747,927,342 ns self-time / 18,624,737 calls, `visit host object` at `host_object.rs:468` has 1,432,652,085 ns self-time / 3,491,848 calls, `call` dispatch at `vm/dispatch.rs:304` has 632,325,205 ns self-time / 30,534 calls, `ScVal to Val` has 293,123,796 ns self-time / 521,065 calls, and metered XDR read/write zones add another ~252 ms self-time. A protocol-gated cost-model change can deliberately replace millions of p26 micro-charges with calibrated bulk charges at stable boundaries such as VM dispatch, host value conversion, event externalization, and ledger-change serialization, unlocking implementation changes that were previously blocked by exact-budget compatibility.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) using the diagnostic trace from `ai-summary/CURRENT_STATE.md`. The trigger is ordinary successful swaps that repeatedly cross Wasm-host boundaries, call SAC transfers, traverse host object vectors/maps, and serialize return values/events/ledger changes during `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` currently records every fine-grained CPU and memory charge and therefore blocks physical coalescing in p26-compatible paths.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — CPU-dimension `charge` is one of the hottest apply-window self-time zones.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-490` — every object read charges `VisitObject` and performs per-handle validation/lookup.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — every VM host-function import returns fuel, charges dispatch, marshals values, augments errors, and refills fuel.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-470` — `ScVal`/`Val` conversions recursively visit objects and charge metered copies.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-82` — metered XDR writes/reads charge `ValSer`/`ValDeser` per writer/reader operation, preventing simple counted-writer shortcuts in p26.

## Evidence

The trace containment check against all 70 `applyLedger` windows shows these zones are not TX-set construction artifacts: `visit host object` has 3,478,780 contained events and 2,728,946,416 ns inclusive time inside `applyLedger`; `ScVal to Val`, `write xdr`, and `read xdr with budget` are each >99% inside `applyLedger`; and `applySorobanStageClustersInParallel` waits on the parallel workers for 3,467,944,842 ns. The broad worker aggregate must be normalized by the 8-cluster cap, but the combined host-internal metering/conversion surface is large enough that removing a meaningful fraction can plausibly clear the 3% Medium floor, and a protocol-level redesign of this surface qualifies as High because it restructures a dominant Soroban execution phase.

This is not a repeat of the isolated failed micro-optimizations. Those records show the important constraint: p26 exact metering makes single-slice changes either unsafe or below threshold. This hypothesis changes the premise by explicitly protocol-gating a new metering model, then co-designing the physical implementation to match the new model rather than replaying the old charge sequence.

## Anti-Evidence

This is a protocol-surface change, not a safe p26-only cleanup. It requires budget-model recalibration, observation fixture updates, compatibility tests for near-limit transactions, and careful proof that ledger effects and deterministic error ordering remain unchanged except for intentional new-protocol resource accounting. Prior attempts at `ValSer` batch charging and host-object visit batching regressed or were blocked when constrained to p26-equivalent metering; a viable PoC must show that the protocol gate removes that constraint and that the reduced physical work survives three non-Tracy apply-load runs.

---

## Review

**Verdict**: VIABLE
**Severity**: High
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — retained fail/success records contain adjacent p26-preserving metering failures, but not this protocol-gated coalescing redesign

### Trace Summary

The apply path reaches the cited code through parallel Soroban operation application: `InvokeHostFunctionOpFrame::doParallelApply` constructs a helper, calls the Rust bridge, builds a per-invocation `Budget` from ledger cost params, and runs `e2e_invoke::invoke_host_function`. Inside the host, `Host::invoke_function` converts host-function XDR into `Val`s, enters Wasm or SAC frames, and then every VM import dispatch returns fuel, charges `DispatchHostFunction`, translates relative/absolute object handles, calls the host function, translates the result, and refills fuel. The hot conversion, event externalization, ledger-change serialization, and object-table reads all funnel through fine-grained `Budget::charge` calls. Prior failures show those charges are protocol-visible in p26; the new and viable premise is to add a next-protocol metering model so physical work no longer has to preserve p26's exact micro-charge sequence.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584,985-1015,1359-1377` — parallel apply invokes the Rust host once per Soroban operation, then records storage changes, events, refundable resources, and the success preimage on the apply path.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_all.rs:1189-1215` — the bridge selects the host module by ledger protocol before invoking the versioned Soroban host.
- `src/rust/src/soroban_proto_any.rs:391-455` — each invocation constructs `Budget::try_from_configs` from the ledger's CPU/memory cost params and then calls the versioned `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-520` — host invocation decodes resources/footprint/auth/host-function XDR, constructs `Host`, runs `Host::invoke_function`, then externalizes result XDR, ledger changes, and events with metered serialization.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-785,1124-1194` — `InvokeContract` converts `ScVal` arguments to host `Val`s, enters a contract frame, invokes Wasm or SAC code, and converts the returned host `Val` back to `ScVal`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — every VM-to-host import performs fuel return, `DispatchHostFunction` charge, argument marshalling with object-handle translation, host call, error augmentation, result marshalling, and fuel refill.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,1261-1325` and `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — all public single and bulk charges update tracker state, charge CPU and memory dimensions, and check limits; the Tracy `charge` span is emitted for CPU-dimension charging.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-528` — each logical object visit creates the `visit host object` zone, charges `VisitObject`, validates handle flavor/bounds/type, and invokes the caller closure.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-270,407-443,463-620` — address, map, `Val`->`ScVal`, and `ScVal`->host-object conversions recurse through object visits and metered copies.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:20-24,40-52,56-82` — metered XDR write/read calls charge `ValSer`/`ValDeser`, including per-writer-call `ValSer` charging on writes.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:20-40,207-248` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-292,875-889` — event and ledger-change externalization traverse host objects and write XDR during successful host invocation finalization.
- `src/rust/soroban/p26/soroban-env-common/src/meta.rs:45-64`, `src/rust/soroban/p26/soroban-env-host/src/host.rs:555-587,1138-1172`, and `src/rust/soroban/p26/soroban-env-common/src/vmcaller_env.rs:178-188` — the host already carries ledger-protocol checks, and the `next` feature can raise the p26 crate's interface protocol to a new development protocol, making a protocol-gated implementation surface plausible.

### Findings

The inefficiency exists and is hot. The traced path executes per Soroban transaction in `closeLedger`, not during TX-set construction, and the target operations are called at high frequency: budget charge dispatch, object visits, VM import dispatch, `ScVal`/`Val` conversion, event externalization, ledger-change serialization, and metered XDR all occur inside successful soroswap invocation apply.

The important correctness distinction is that a p26-compatible optimization cannot skip these operations wholesale. `BudgetImpl::charge` updates public tracker fields, CPU/memory dimensions, and limit checks; `visit_obj_untyped` must reject relative/out-of-range/mistyped object handles; `metered_write_xdr` currently charges `ValSer` per writer call; and conversions/events rely on recursive object traversal for exact p26 metering. Retained failures already show that preserving these exact p26 micro-observations collapses several isolated optimizations below the objective threshold.

The protocol-gated version changes that premise in a way the codebase can support. The Rust bridge already dispatches by ledger protocol, the p26 host validates ledger protocol against its compiled interface version, and `next` builds can expose a new protocol number. Under that new protocol, a PoC can define new consensus cost accounting at coarser boundaries and remove the corresponding physical microcharge calls, while keeping existing p26 behavior untouched.

The projected impact is large enough for review-stage viability only if the PoC attacks multiple surfaces together. The rejected p26-preserving slices show that removing just a `RefCell` borrow, a zero-memory charge branch, or one XDR buffer is insufficient. A viable implementation needs to remove a meaningful fraction of the aggregate charge/object/conversion/XDR surface, not simply set cost params lower while still executing the same `Budget::charge` calls.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/budget.rs`, `src/rust/soroban/p26/soroban-env-host/src/host.rs`, `src/rust/soroban/p26/soroban-env-host/src/host_object.rs`, `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs`, `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs`, `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs`, `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs`, plus the protocol/network-cost-parameter plumbing needed to expose the new cost model.
- **Change description**: add a strictly next-protocol metering mode and keep the current p26 path bit-for-bit. In the new mode, move selected host-internal costs from per-leaf `Budget::charge` calls to calibrated bulk charges at stable boundaries such as VM import dispatch, `ScVal`/`Val` tree conversion, event externalization, and ledger-change/result XDR serialization. The PoC should physically skip or combine the corresponding microcharge calls; merely changing ledger cost params while still executing millions of charge calls will not prove the hypothesis.
- **Correctness check**: prove that ledger entries, emitted events, auth effects, diagnostics gating, and deterministic host errors remain unchanged for non-budget-limited successful transactions. For p26, existing budget/tracker observations must remain unchanged. For the new protocol, near-limit transactions may intentionally have different resource outcomes, but budget-exceeded failures must still be deterministic and must not leave partially applied storage/events beyond the existing rollback semantics.
- **Benchmark focus**: run three authoritative non-Tracy `scripts/run_apply_load_matrix.py` runs against the current `ai-summary/CURRENT_STATE.md` baseline. The required signal is reduced soroswap median apply time of at least 3% across repeated runs, with Tracy used only to confirm that `charge`, `visit host object`, `ScVal to Val`, `write xdr`, and `read xdr with budget` self-time fall in the optimized build.
