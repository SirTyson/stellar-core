# H001: Next-Protocol Budget Charge Accumulator for Linear Hot Costs

**Date**: 2026-05-03
**Subsystem**: soroban / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by coalescing high-frequency host budget charges in the Soroban worker path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For released p26 ledgers, every Soroban budget charge should remain exactly as it is today. For a next-protocol benchmark build, host-internal metering should still debit the same deterministic CPU/memory total for linear hot costs, and should still fail before any externally visible boundary if the remaining budget cannot cover the accumulated work. It should not pay the physical cost of a `BudgetImpl::charge` call, model lookup, tracker update, Tracy span, and limit check for every single `VisitObject`, map lookup, dispatch, shallow copy, or other tiny linear cost when those charges can be accumulated and flushed in deterministic chunks.

## Mechanism

`BudgetImpl::charge` (`src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284`) routes every cost through the generic tracker, CPU dimension, memory dimension, and limit-check path. The CPU dimension adds the hot `charge` Tracy span in `BudgetDimension::charge` (`src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188`), and many Soroban host call sites invoke it millions of times for small linear costs before doing actual work. The current diagnostic soroswap trace from `ai-summary/CURRENT_STATE.md` shows `charge` entirely inside `applyLedger`: **1,758,199,707 ns self-time across 20,300,668 calls**, plus adjacent metered-map and dispatch costs such as `map lookup indexed` at **543,656,426 ns**, `map lookup` at **345,449,339 ns**, and VM dispatch wrapper self-time at **922,554,179 ns**.

The proposed optimization is a protocol-gated accumulator in `BudgetImpl`: classify linear cost models at budget construction, keep per-cost pending `(iterations, input_sum)` counters for eligible hot costs, and flush either when a deterministic chunk threshold is reached or before any host/VM boundary where budget failure timing must be observed. This is broader than the accepted protocol-gated `VisitObject` / `ValSer` coalescing: it targets the remaining generic budget-charge machinery after that change, while preserving p26 exact metering and bounding next-protocol budget-exceeded behavior by prechecking/reserving chunks before side effects.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) with the diagnostic trace recorded in `ai-summary/CURRENT_STATE.md`. Successful swaps execute tens of millions of small host charges during `Host::invoke_function`, VM dispatch, host object conversion, storage-map lookups, SAC calls, and ledger-change extraction. A PoC should add narrow counters for accumulator flushes and compare the `charge`, `map lookup indexed`, and dispatch self-time before and after.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge`; add next-protocol pending counters and deterministic flush/precheck logic for eligible linear costs.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge`; currently contributes the hot CPU `charge` span on every micro-charge.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-240` — metered map `find`/`get` paths that repeatedly charge search/access costs during enforcing storage and footprint lookups.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` — generated dispatch wrappers that charge host-function dispatch and execute many small argument-conversion charges.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-490` — already partially optimized by protocol-gated `VisitObject` coalescing; useful as the precedent and as one flush-boundary caller family.

## Evidence

The current trace confirms this is in scope: all 20,300,668 `charge` events are contained within `applyLedger` windows, totaling 1.758 s of self-time before counting caller-side metered-map and dispatch work. The remaining `charge` zone is present after the accepted `protocol-gated-host-metering-coalescing` success removed the explicit `visit host object` span from the optimized diagnostic trace, so this is not a duplicate of that completed work. It is also not the rejected zero-memory fast path: that failure targeted only the uninstrumented memory-dimension slice for zero-memory costs, while this hypothesis targets the CPU-dimension micro-charge itself and a protocol-gated aggregate metering model.

The impact target is Medium because the full `charge` self-time alone is above the 3% wall-time threshold after NUM_CLUSTERS normalization in the 5.23 s `applyLedger` diagnostic window, and the caller families it enables (`map lookup indexed`, `map lookup`, dispatch wrappers, shallow-copy charges) add more removable physical overhead. A correct implementation does not need to remove semantic charges; it needs to make many small charges one physical accumulator update plus occasional deterministic flushes.

## Anti-Evidence

Budget failure timing is consensus-sensitive. A naive "flush at end of invocation" accumulator is not viable because it can allow a contract to execute side effects past the point where the old budget would have failed. The PoC must either reserve chunk budget before executing charged work or flush before every boundary where error timing is observable, and p26 must remain exact. If preserving failure timing forces very small chunks, the savings may fall back into Low severity.

The trace's `charge` span is Tracy-enabled diagnostic data, while the authoritative benchmark runs are non-Tracy. The PoC must therefore prove top-line non-Tracy apply-time improvement, not just a cleaner Tracy profile. It should also verify that tracker totals, fee/resource accounting, and debug budget reports are intentionally unchanged for p26 and explicitly protocol-defined for the next-protocol path.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — adjacent to `success/soroban/001-protocol-gated-host-metering-coalescing.md` and `fail/soroban/002-zero-memory-budget-charge-fast-path.md`, but not the same finding
**Failed At**: reviewer

### What's Wrong

The broad accumulator idea is plausible, but the specific `(iterations, input_sum)` mechanism is not correctness-preserving for the linear hot costs named in the hypothesis. `MeteredCostComponent::evaluate` rounds the scaled linear term on each evaluation (`lin_term * input * iterations`, then `unscale()`), so replacing many single charges with one pending input sum changes the charged CPU/memory total for variable-size `MemCpy`, `MemAlloc`, `ValSer`, and map/vector access costs unless the accumulator also tracks exact per-call charged amounts or scaled remainders. That violates the hypothesis's own requirement that next-protocol host-internal metering debit the same deterministic total for linear hot costs.

The flush-boundary story is also incomplete. `BudgetImpl::charge` currently updates tracker state, charges CPU, checks CPU limit, charges memory, and checks memory limit before the caller performs subsequent work. Deferring those checks requires explicit integration with host/VM fuel transfer (`Vm::metered_func_call`, generated dispatch wrappers, and `Budget::get_wasmi_fuel_remaining`), public budget observers (`get_cpu_insns_consumed`, `get_mem_bytes_consumed`, debug/display tracker output), shadow-mode accounting, and error-conversion call sites such as metered XDR writes. Without that full boundary map, a PoC can either over-issue VM fuel from unflushed pending CPU or change when `ExceededLimit` becomes observable.

The Medium projection is therefore not established. The recorded `charge` span is real apply-path diagnostic evidence, but clearing the optimize-soroswap floor would require removing most of the remaining generic charge machinery in authoritative non-Tracy runs. A corrected exact accumulator still has to perform a per-call borrow/fast-path dispatch and enough arithmetic to preserve per-call rounding or reservations, so the current write-up needs a narrower design and a stronger per-cost call-count/upper-bound model before promotion.

### Alternative Angle

Refine this into a protocol-gated "exact pending charge" design, not an `(iterations, input_sum)` design. For each eligible cost type, preclassify the CPU and memory models, maintain pending `iterations`, `input_sum` for reporting, and pending already-rounded `cpu_amount` / `mem_amount` or scaled residual state sufficient to reproduce the intended protocol totals exactly. Start with a very small eligible set: constant costs are simplest, while variable-input linear costs should only be included after proving their rounding semantics and budget-exceeded timing are intentionally preserved or intentionally redefined for the next protocol.

The refinement also needs an explicit mandatory-flush API and a list of all callers that must invoke it before exposing budget state or transferring fuel. If the design still projects Medium after counting only the work removed while retaining exact amount computation, it can be re-reviewed as a concrete protocol-gated accumulator rather than a generic budget-charge coalescer.

### Additional Code Paths

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` performs tracker updates, CPU charge/check, memory charge/check, and is the only safe place to centralize a pending-charge fast path.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` evaluates the cost model and emits the CPU-only `charge` Tracy span; this is the physical overhead the hypothesis wants to avoid.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — linear cost rounding happens during every model evaluation, so input-sum aggregation changes totals unless exact rounded amounts or residuals are tracked.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1301-1325` — `Budget::bulk_charge` already batches identical-cost operations, but its semantics are not a drop-in replacement for arbitrary variable-input single charges.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83,168-240` — metered map lookup/search uses `MemCpy` charges with input sizes derived from map entry counts and binary-search magnitude; these are representative variable-input charges.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:53-94` — shallow-copy and heap-allocation helpers generate many `MemCpy`/`MemAlloc` charges whose linear rounding semantics must be preserved if accumulated.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — generated VM-to-host wrappers return fuel, charge dispatch, call host functions, and refill VM fuel; pending CPU must be flushed before fuel is returned to wasmi.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345` — host-to-VM invocation charges `InvokeVmFunction`, transfers budget into wasmi fuel, performs the call, and returns fuel; this is another mandatory flush boundary.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-68` — metered XDR writes convert budget failures into IO errors, so delayed `ValSer` failures need special care if this path is included.
