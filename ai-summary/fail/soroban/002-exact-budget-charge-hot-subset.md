# H002: Exact next-protocol accumulator for measured hot Soroban budget charges

**Date**: 2026-05-05
**Subsystem**: soroban
**Severity**: Medium
**Impact**: apply-time reduction in Soroban host budget charging for soroswap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban apply must enforce deterministic CPU and memory budget limits, return the same aggregate `cpu_insns` and `mem_bytes` for successful invocations, preserve p26 metering exactly, and flush all pending accounting before any public budget observer, VM fuel transfer, shadow-mode transition, metered-XDR failure boundary, or host output construction. In a next-protocol-only metering mode, repeated charges for a measured whitelist of hot cost types should be accumulated as already-evaluated `(cpu_amount, mem_amount)` deltas, not as raw `(iterations, input)` values, so linear rounding and per-call cost-model semantics remain exact while reducing per-charge tracker/dimension update overhead.

## Mechanism

`Budget::charge` currently takes a `RefCell` mutable borrow, updates per-cost tracker fields, evaluates and updates the CPU dimension, checks the CPU limit, evaluates and updates the memory dimension, and checks the memory limit on every call. The current soroswap trace still has 20,300,668 `charge` spans after the accepted host-metering coalescing success removed `VisitObject` spans and coalesced `ValSer` writes. A refined accumulator would not defer arbitrary inputs or change rounding: it would immediately evaluate each whitelisted charge to concrete CPU/memory amounts, check `current_total + pending_total + amount` against the limits, append the exact deltas to per-cost pending totals, and flush them at mandatory observation/fuel/error boundaries. This targets the remaining physical overhead around a measured hot subset while avoiding the previously rejected raw-input accumulator semantics.

## Trigger

Run the current next-protocol soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). Successful swap execution repeatedly charges budget in VM dispatch, map/vector construction, storage access, SAC transfer, host-object conversion, and VM instantiation paths; these execute under `applySorobanStageClustersInParallel` worker threads during `closeLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` performs per-call tracker updates, CPU and memory dimension updates, and immediate limit checks.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` evaluates a cost model and mutates aggregate totals for every charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1391-1429` — public tracker/total/fuel observers that must flush pending exact deltas before returning values.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:291-295` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs:327-345` — VM/host fuel transfer boundaries where pending CPU totals must be visible before fuel is computed.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-82,109` — metered XDR boundaries that must preserve deterministic failure and budget-observation behavior.

## Evidence

The current accepted soroswap trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `applyLedger` has 71 windows totaling 5,230,315,999 ns. The residual budget hot path is still a major descendant:

| Zone | Apply-window self-time | Calls | Source |
|---|---:|---:|---|
| `charge` | 1,758,199,707 ns | 20,300,668 | `soroban-env-host/src/budget/dimension.rs:176` |
| `call` | 922,554,179 ns | 40,605 | `soroban-env-host/src/vm/dispatch.rs:304` |
| `map lookup` + `map lookup indexed` | 753,901,055 ns | 1,281,890 | `soroban-env-host/src/host/metered_map.rs:173,330` |
| `new map` | 331,023,872 ns | 170,072 | `soroban-env-host/src/host/metered_map.rs:148` |

Previous accumulator failures identified the correct blocker: aggregating raw inputs changes linear rounding and flush semantics. This hypothesis addresses that blocker by accumulating already-evaluated exact amounts and naming explicit flush boundaries. If a preliminary counter shows a hot whitelist accounting for at least roughly 70% of the 1.76 s residual `charge` CPU, then removing most per-call dimension mutation/check/tracker overhead for that subset can plausibly exceed the 3% Medium floor after cluster normalization.

## Anti-Evidence

This is not viable without direct measurement of cost-type distribution in the current post-coalescing baseline. The `charge` Tracy span is inside the CPU dimension and includes work that may still be required, and any deferred accounting must be flushed before fuel conversion or public budget reads. If the eligible whitelist is a small fraction of residual charges, or if exact pending-limit checks cost nearly as much as immediate updates, the improvement will fall into the already-rejected Low budget-micro-optimization family.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entries `001-exact-pending-budget-charge-accumulator.md` and `001-next-protocol-budget-charge-accumulator.md`
**Failed At**: reviewer

### Trace Summary

The hot path exists: Soroban transactions in the parallel apply phase enter Rust host execution through `InvokeHostFunctionOpFrame`, construct a `Budget`, and every host charge reaches `BudgetImpl::charge`. That charge path updates reporting fields, evaluates CPU and memory cost models, mutates aggregate dimensions, and checks limits; fuel transfer and bridge-output observers read those aggregate values after execution. The proposed "exact pending amount" accumulator is the same accumulator family already retained in the Soroban failure summary: the raw-input version failed on rounding/flush semantics, and the exact-pending version was already rejected without direct measurement proving the eligible subset can clear the 3% Medium threshold.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` launches one worker per cluster and waits on futures inside the measured apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-590` — C++ calls `rust_bridge::invoke_host_function` and records returned aggregate CPU/memory and VM-instantiation exclusion metrics.
- `src/rust/src/soroban_proto_any.rs:412-466` — Rust constructs `Budget`, invokes the protocol host, then reads `get_cpu_insns_consumed`, `get_mem_bytes_consumed`, `get_tracker(VmInstantiation).cpu`, and `get_time(VmInstantiation)`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,1323-1325` — `Budget::charge` takes the mutable `RefCell` borrow and `BudgetImpl::charge` performs per-call tracker updates, CPU and memory dimension charges, and immediate limit checks.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` evaluates the cost model, emits the CPU-dimension Tracy `charge` span, and mutates the dimension total.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1345-1365,1391-1429` — shadow-mode transitions and public tracker/total/fuel observers are mandatory flush boundaries for any pending accounting.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-39`, `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:291-295`, `src/rust/soroban/p26/soroban-env-host/src/vm.rs:327-345` — VM fuel refill/return computes fuel from host budget totals and charges spent fuel back to the host.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:20-23,56-82` — metered XDR converts budget failures into deterministic budget errors, so pending charges would need to be visible before error conversion.
- `ai-summary/fail/soroban/summary.md:58-60,113` — retained prior investigations already cover exact pending budget accumulation and the raw-input accumulator refinement path.

### Why It Failed

This is not novel. The retained Soroban failure summary already records an "Exact pending budget-charge accumulator" and states that accumulator hypotheses require direct measurement showing the eligible subset alone saves at least 3% after the accepted host-metering coalescing work. It also records the preceding next-protocol raw-input accumulator as `NEEDS_REFINEMENT`, with the requested refinement being exactly the approach proposed here: track already-rounded `cpu_amount`/`mem_amount` deltas and flush at fuel, observer, shadow-mode, and metered-XDR boundaries.

Even ignoring the duplicate, the current write-up does not supply the missing measurement. It projects from all residual `charge` events while acknowledging that the whitelisted subset may be too small and that exact pending-limit checks may cost nearly as much as immediate dimension updates. Under the optimize-soroswap objective, that is insufficient to promote a Medium hypothesis.

### Lesson Learned

For Soroban budget-charge accumulator ideas, the novelty bar is now the measured eligible cost-type distribution and a non-Tracy A/B signal that clears the 3% apply-time floor. Restating the exact-pending design without that measurement is a duplicate of the retained failure, not a new reviewable optimization.
