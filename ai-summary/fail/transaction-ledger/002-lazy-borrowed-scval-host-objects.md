# H002: Lazy borrowed ScVal host objects for immutable ledger and invocation values

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Soroban host value conversion
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding eager recursive `ScVal <-> Val` host-object materialization for immutable values in the apply path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When Soroban host execution reads immutable invocation arguments or immutable ledger values, it should preserve the same `Val` semantics, comparison ordering, budget accounting, storage-key validation, and final XDR output. On a next-protocol path, immutable `ScVal` trees should not have to be eagerly converted into owned `HostObject::Vec` / `HostObject::Map` trees and then recursively converted back to `ScVal` if the value is only inspected, compared, or passed through unchanged.

## Mechanism

`Host::to_host_val` recursively materializes object-valued `ScVal`s into host objects, and `Host::from_host_val` recursively externalizes host objects back to `ScVal`. Soroswap still performs hundreds of thousands of these conversions after the accepted typed-SAC-balance fast path because router/pair arguments, storage values, authorization arguments, and event values still cross the generic host-object boundary. A protocol-gated `HostObject::BorrowedScVal` / lazy-object representation for immutable inputs could hold an `Rc<ScVal>` plus a materialization state: comparison, hashing, storage-key conversion, and XDR write paths can operate directly on the borrowed tree, while mutation-oriented host functions materialize into the existing owned `HostVec` / `HostMap` only when required. This avoids repeated host-object allocation and recursive conversion while preserving deterministic ordering and exact logical values.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.
Every router/pair invocation enters `HostFunction::InvokeContract`, converts invoke args to host vals, reads contract storage through enforcing storage, and eventually serializes return values/events/ledger changes under `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-444` — `from_host_val`, `from_host_val_for_storage`, and `to_host_val` are the generic recursive conversion boundaries.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-540` — `from_host_obj` recursively visits `HostObject::Vec` / `HostObject::Map` and rebuilds `ScVal` output.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:22-39` and `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-457` — `HostObject` currently stores only owned object variants, and `add_host_object` pushes every materialized object into the host object table.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1129-1147` — top-level invoke-contract arguments are converted with `scvals_to_val_vec` before entering the call path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:498-580` — after execution, ledger changes and contract events are serialized from host/storage state back into XDR for C++ result processing.

## Evidence

- The current self-time CSV shows apply-descendant conversion/object zones that remain after accepted SAC-balance and storage-map optimizations: `ScVal to Val,soroban-env-host/src/host/conversion.rs:436` at **429,988,065 ns self-time** over **691,521** calls, `Val to ScVal,soroban-env-host/src/host/conversion.rs:411` at **245,978,039 ns self-time** over **446,612** calls, `add host object,soroban-env-host/src/host_object.rs:450` at **270,971,092 ns self-time** over **935,719** calls, and `Compare<HostObject>,soroban-env-host/src/host/comparison.rs:51` at **165,773,848 ns self-time** over **413,544** calls.
- Prior successes removed one typed SAC balance slice, but the source still contains the generic conversion boundary for non-SAC storage values, invoke arguments, auth arguments, router/pair maps/vectors, and events. This hypothesis targets the remaining generic immutable-value representation, not another SAC-only helper.
- The design is deterministic: borrowed `ScVal` values are immutable, already decoded under the transaction budget, and can use the same host comparison protocol; all nodes would lazily materialize the same value at the same API boundary when mutation or a host-object-specific operation requires it.

## Anti-Evidence

- `add host object` Tracy self-time includes profiler instrumentation and cannot be treated as pure production allocator cost. The PoC must use non-Tracy benchmark runs plus narrow counters for materializations avoided.
- Budget accounting is protocol-visible. If lazy borrowed values skip `ScVal->Val`, object-allocation, or `Val->ScVal` charges, the change must be protocol-gated and budget observations updated as an intentional lower-cost metering model.
- Object identity and handle semantics are subtle. Borrowed objects must not leak mutable aliases, must materialize before APIs that depend on host-object table handles or relative-object tables, and must preserve storage-key restrictions such as rejecting muxed-address keys in `from_host_val_for_storage`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related generic conversion, host-object traversal, and trusted-ledger decode ideas are recorded, but this exact borrowed-`ScVal` object representation was not previously investigated as a fail/success record
**Failed At**: reviewer

### Trace Summary

The close-ledger path reaches this code through `InvokeHostFunctionOpFrame::doParallelApply`, the C++/Rust invoke bridge, `e2e_invoke::invoke_host_function`, and `Host::invoke_function`. `HostFunction::InvokeContract` converts top-level XDR `ScVal` arguments to `Val`s with `scvals_to_val_vec`, storage reads convert ledger `ScVal` values back to host `Val`s in `get_contract_data`, storage writes and storage-key construction convert `Val`s back to `ScVal`s, and event/return externalization serializes host values back to XDR. The recursive conversion inefficiency exists, but the hypothesis sizes broad aggregate worker self-time and profiler-visible object-table spans rather than a Medium-sized critical-path slice that can actually be removed.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1358-1377` — parallel Soroban apply invokes the Rust host once per Soroban operation inside `closeLedger`.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:391-430` — the bridge constructs a fresh budget and dispatches to the p26 host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:487-580` — enforcing storage, auth, host function, source account, ledger info, and module cache are installed; after execution, the result, ledger changes, and events are externalized.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — `HostFunction::InvokeContract` converts invoke args with `scvals_to_val_vec` before calling the target contract.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:197-221,407-444,463-565` — vectors/maps are recursively converted through `to_host_val`, `from_host_val`, `from_host_obj`, `host_map_to_scmap`, and `scvals_to_val_vec`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2213-2341` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-563` — generic storage APIs reconstruct storage keys from `Val`, convert ledger `ScVal` values to host values on reads, and convert host values back to `ScVal` on writes.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-39` and `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — contract events are stored as host values and later externalized through `vecobject_to_scval_vec` and `from_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:22-39,446-457,460-535` — the object table stores concrete owned variants only; typed access goes through `HostObjectType::try_extract`, so a borrowed variant would either fail existing typed visits or require broad special cases/materialization paths.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — object comparison is recursive and must preserve `ScVal` ordering plus metered comparison costs.
- `ai-summary/CURRENT_STATE.md:71-84,115-124` and `ai-summary/fail/transaction-ledger/summary.md:71,100,121,131` — the current accepted baseline already protocol-gates host metering coalescing, and prior records require aggregate Soroban worker self-time to be divided by cluster parallelism before projecting top-line apply impact.

### Why It Failed

The proposed representation is directionally plausible but does not meet the optimize-soroswap Medium threshold. The cited conversion/comparison numbers are aggregate worker self-time from a parallel trace; after the required T=8 critical-path normalization, even treating the non-`add_host_object` conversion plus comparison categories as fully removable is below the 3% apply-time floor, and a correct implementation could not remove them fully. `add host object` is a Tracy span around object-table insertion and is not a direct measure of production allocator cost.

The current object model also makes the removable subset much smaller than the broad mechanism implies. Existing host APIs expect concrete `HostVec`, `HostMap`, `ScAddress`, byte/string/symbol, and numeric variants through `HostObjectType::try_extract`; a new borrowed variant would have to materialize on ordinary `vec_*`, `map_*`, address, auth, storage, event, and relative-object-table operations unless those APIs were broadly refactored to understand borrowed XDR trees. Storage-key conversion, event externalization, result serialization, comparison ordering, depth checks, muxed-address rejection, and protocol-visible budget charges must still happen or be explicitly protocol-gated, so the lazy object would mostly reshuffle required conversion/metering work rather than deleting a Medium-sized phase.

### Lesson Learned

Broad `ScVal to Val`, `Val to ScVal`, `Compare<HostObject>`, and `add host object` Tracy categories should not be promoted as a single removable optimization without isolating the exact immutable/pass-through subset and normalizing worker aggregate time by cluster count. For the current soroswap baseline, generic host-value representation changes need narrow counters proving a remaining >=3% top-line opportunity; otherwise they collapse to prior sub-threshold host-object traversal, trusted-ledger decode, event-representation, or SAC-helper micro-optimizations.
