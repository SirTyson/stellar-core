# H001: Protocol-gate actual-cost indexed enforcing-storage reads

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / Soroban host storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing compatibility-only budget work from indexed enforcing storage reads
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol Soroban invocations that use enforcing storage with the accepted storage side index, reading a known footprint key should validate the footprint, retrieve the storage slot by its deterministic indexed position, and charge a protocol-defined cost that matches the actual indexed access. It should not continue to charge and execute legacy binary-search metering solely to preserve p26 budget totals when the indexed path has already proven the position.

## Mechanism

The accepted indexed lookup path in `MeteredOrdMap::get_at_known_position` deliberately calls `charge_binsearch` and `charge_access(1)` even though it skips the binary search and jumps directly to `self.map.get(pos)`. Missing-key cases similarly call `charge_lookup` to reproduce the legacy failed-lookup budget profile. This compatibility charge is consensus-visible and must remain for p26, but under a new protocol version the host can define indexed enforcing-storage reads as an O(1) indexed operation, avoiding hundreds of thousands of budget charges and associated budget bookkeeping in the soroswap apply window without changing ledger effects or storage ordering.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) with the accepted trace `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Any router/pair invocation that repeatedly calls SAC and pair storage APIs triggers enforcing `Storage::try_get_full_helper`, which uses `enforce_storage_idx` and then `MeteredOrdMap::get_at_known_position`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-347` at accepted p26 commit `fa1226b3` — `try_get_full_helper` uses `enforce_storage_idx` and calls `get_at_known_position` for indexed storage-map reads.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:300-320` at accepted p26 commit `fa1226b3` — `enforce_access_indexed` handles footprint enforcement and calls `charge_lookup` for indexed missing-key compatibility.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-347` at accepted p26 commit `fa1226b3` — `get_at_known_position` and `charge_lookup` preserve the legacy binary-search budget profile despite already knowing the position.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-999` — `InvokeHostFunctionApplyHelper::doApply` invokes the Rust host after `addFootprint`, so the indexed reads are on the transaction apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ soroswap transactions execute through `doParallelApply`, making this worker-local work an `applyLedger` descendant.

## Evidence

- Tracy timestamp filtering against `applyLedger` windows confirms the target zones are inside the measured apply path. Across the seven long `applyLedger` windows in the current soroswap trace, `map lookup indexed` occurs **776,948** times and totals **542,751,364 ns** of worker time, or **77.536 ms aggregate per long window** before T=8 critical-path normalization.
- The same long windows show `storage get` at **640,695,560 ns**, `has_contract_data` at **482,296,884 ns**, and `get_contract_data` at **735,765,898 ns**. These are the host storage APIs that funnel into `try_get_full_helper` and amplify the indexed lookup charge.
- Source inspection shows the indexed path is already deterministic: `enforce_storage_idx` maps the same ledger-key set to stable positions, and `get_at_known_position` only reads `self.map.get(pos)`. The remaining binary-search charge is explicitly a compatibility shim, not required to find the value.
- This is not the previously accepted side-indexing hypothesis itself. That work removed comparisons and map searches while preserving legacy metering; this hypothesis targets the remaining protocol-gated metering and budget-bookkeeping cost that was intentionally left behind for p26 compatibility.

## Anti-Evidence

- Budget totals are protocol-visible. This must be gated behind a protocol version bump, with p26 continuing to call `charge_binsearch`/`charge_lookup` exactly as today.
- `map lookup indexed` is aggregate worker time. A reviewer should normalize by the active cluster count and isolate the budget-charge subset before expecting the full 77.5 ms aggregate per long window to become wall-clock savings.
- The existing host-metering coalescing already reduced some budget overhead. A PoC needs narrow counters for `get_at_known_position` charge time versus the direct `Vec::get` and `charge_access` portions to prove the remaining actual-cost delta clears the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/transaction-ledger` or `success/transaction-ledger`
**Failed At**: reviewer

### Trace Summary

The indexed enforcing-storage read path is real: C++ parallel Soroban apply calls the Rust host, `Storage::try_get_full_helper` enforces the footprint through `enforce_access_indexed`, and a successful indexed storage-map hit reaches `MeteredOrdMap::get_at_known_position`. That helper deliberately preserves p26 metering by charging `charge_binsearch` before the direct `Vec::get(pos)`, and then charges `charge_access(1)` for a found element. However, the safe "actual indexed access" change only clearly removes the binary-search-style charge; the one-entry access charge corresponds to the actual element read and is not merely a legacy search cost. The full `map lookup indexed` Tracy span is therefore an upper bound, not the removable production work, and after T=8 normalization it is too tight to support a Medium-severity claim once mandatory access work and diagnostic span overhead are excluded.

### Code Paths Examined

- `ai-summary/CURRENT_STATE.md:41-50` — the accepted baseline is three non-Tracy soroswap runs averaging 272.895607 ms, so the objective's 3% Medium floor is about 8.19 ms per ledger.
- `ai-summary/fail/transaction-ledger/summary.md:42` — the earlier storage-map side-index/lookup fast-path family was already measured around a Low-tier 2.17% improvement; this hypothesis targets only residual metering left after that class of lookup optimization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-999` — sequential Soroban apply invokes the Rust host after footprint loading and records storage changes afterward.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban transactions run through `doParallelApply`, so worker-local Rust host storage reads are descendants of `applyLedger`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:505-523` — each invocation builds enforcing `Storage` with the side-indexed storage map before constructing the host.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — enforcing storage constructs side indices for footprint and storage map positions; the key set is fixed for the lifetime of the enforcing storage.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:288-321` — `enforce_access_indexed` uses the footprint side index and charges `charge_lookup` on indexed misses to preserve legacy missing-key metering.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-353` — `try_get_full_helper` checks supported key type, enforces read access, then uses `enforce_storage_idx` and `get_at_known_position` for indexed hits.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-348` — `get_at_known_position` skips binary search but still charges `charge_binsearch` and `charge_access(1)`; only `charge_binsearch`/`charge_lookup` are unambiguously compatibility-only for an indexed read.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2234-2252` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:2254-2289` — `has_contract_data` and `get_contract_data` convert the storage key and call `Storage::{has,get}`, which funnel into the target read helper for persistent/temporary storage.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:3-14` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:191-202` — SAC balance reads amplify the read path because `try_get_contract_data` performs `has_contract_data` and then `get_contract_data` on found balances.

### Why It Failed

The inefficiency exists but does not meet the optimize-soroswap review threshold. The hypothesis's own trace gives `map lookup indexed` at 77.536 ms aggregate worker time per long apply window; normalized by T=8, the entire span is only about 9.69 ms, or 3.55% of the 272.896 ms accepted baseline. That is a hard upper bound: a correct actual-cost indexed read must still perform the `HashMap` side-index lookup outside this span, the direct `Vec::get(pos)`, result handling/cloning at the storage layer, and at least the one-entry access cost unless the protocol deliberately makes indexed element reads cheaper than their actual memory access. Removing only the clearly redundant `charge_binsearch`/`charge_lookup` leaves the projected top-line saving below the 8.19 ms Medium floor, while removing `charge_access(1)` is a broader metering-policy change not justified by the stated "skip binary-search compatibility" mechanism.

### Lesson Learned

For residual protocol-gated metering hypotheses, normalize the full Tracy zone by cluster parallelism first, then subtract work that remains mandatory under the proposed actual-cost model. A zone whose entire critical-path upper bound barely clears 3% should not advance unless the removable subcomponent has been isolated with narrow counters and still clears the objective's Medium floor.
