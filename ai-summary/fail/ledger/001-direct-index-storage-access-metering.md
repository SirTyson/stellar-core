# H001: Protocol-Gated Direct-Index Storage Access Metering

**Date**: 2026-05-25
**Subsystem**: ledger / soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing synthetic legacy budget work from hot enforcing-mode storage lookups
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Soroban transaction runs in enforcing mode with side indexes built by `Storage::with_enforcing_footprint_and_map`, footprint enforcement and storage lookup should use those indexes deterministically and charge only the protocol-defined cost for the work actually performed. For a next-protocol-gated optimization, the lookup should still reject out-of-footprint access, preserve read-only/read-write permissions, return the same ledger entry, and produce identical ledger state and metadata, but it should not pay binary-search-style budget charges when no binary search is executed.

## Mechanism

The current indexed fast path removes the comparison loop but intentionally keeps the legacy `charge_binsearch` budget profile in `MeteredOrdMap::get_at_known_position` and `charge_lookup`. `Storage::enforce_access_indexed` and `Storage::try_get_full_helper` therefore perform hash-index probes and direct vector access, but still issue synthetic binary-search charges on every hot `storage get`; in the current soroswap trace, this path is inside `applyLedger` and accounts for hundreds of thousands of calls. A protocol-gated cost-model split that adds an actually-direct lookup/charge path for indexed enforcing storage should reduce apply CPU while remaining deterministic because all nodes build the same indexes from the transaction footprint and storage map.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the current baseline. The trigger is any Soroban invocation with an enforcing footprint built by `invoke_host_function` where contract code repeatedly calls storage APIs for keys already present in `enforce_footprint_idx` and `enforce_storage_idx`; soroswap swaps hit this path through repeated pool and SAC storage reads/writes.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — builds deterministic side indexes for enforcing-mode footprint and storage maps.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:288-320` — enforces footprint access through `enforce_footprint_idx` but still calls `get_at_known_position` / `charge_lookup`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-352` — performs indexed storage `get` through `enforce_storage_idx` and then clones the result.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-457` and `600-628` — performs indexed storage replacement for writes and TTL extensions.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-348` — direct-position lookup still charges the legacy binary-search budget profile.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:350-381` — direct-position replacement skips comparisons but still pays legacy search/build validation costs.

## Evidence

The latest current-state soroswap Tracy trace is `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports `storage get` at `soroban-env-host/src/storage.rs:329` with 266,675,391 ns self over 357,046 calls, `map lookup indexed` at `soroban-env-host/src/host/metered_map.rs:330` with 532,467,330 ns self over 931,436 calls, and `charge` at `soroban-env-host/src/budget/dimension.rs:176` with 1,710,982,327 ns self over 21,078,947 calls. Unwrapped event intersection confirms these are apply-path events: `storage get` has 789,297,585 ns / 356,070 events inside `applyLedger`, and `map lookup indexed` has 681,483,367 ns / 929,010 events inside `applyLedger`.

The source comments explicitly say the indexed fast paths are preserving the legacy budget profile even though the index already proved the position. This leaves a measurable synthetic metering workload on the hottest soroswap storage path, making a protocol-gated actual-cost path plausibly large enough for Medium severity.

## Anti-Evidence

The current behavior deliberately preserves p26 budget equivalence, so an ungated change would alter resource accounting and fees. The viable version must be gated to a future protocol/cost-model switch, update only budget-derived expected numbers, and keep the fallback legacy path for recording-mode/test-constructed storage or mutated maps where index length no longer matches the map length.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — adjacent prior indexed-metering failures did not cover the current checkout after side-index and known-position helpers were added
**Failed At**: reviewer

### Trace Summary

The hot path is real: `InvokeHostFunctionOpFrame` calls the Rust bridge during apply, `e2e_invoke::invoke_host_function` builds enforcing `Storage` with footprint/storage side indexes, and contract storage APIs route through `Storage::prepare_read_only_access`, `enforce_access_indexed`, and `try_get_full_helper`. Those indexed paths use `HashMap<LedgerKey, usize>` plus direct vector access, but `MeteredOrdMap::get_at_known_position` and `charge_lookup` intentionally preserve the legacy binary-search budget profile. However, this work runs inside parallel Soroban worker execution, and the trace totals are aggregate worker CPU rather than serial apply-wall time; after normalizing by the configured 8 clusters and the current ~207.6 ms soroswap median baseline, the removable direct-index metering subset is below the objective's 3% Medium threshold.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ apply path invokes `rust_bridge::invoke_host_function` for Soroban host execution and records returned budget/resource metrics.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:391-452` — protocol-selected Rust bridge constructs the transaction budget, calls the p26 host module, and measures host invocation time.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-523` — p26 host invocation decodes resources/footprint/input entries, clones the initial storage map, builds enforcing `Storage`, and aligns positional metadata using `enforce_storage_idx`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:180-194` and `245-267` — enforcing storage now carries deterministic side indexes for footprint and storage-map positions.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:288-320` and `807-831` — read access enforcement uses `enforce_footprint_idx` when valid, but the hit and miss paths still call `get_at_known_position` / `charge_lookup` to preserve legacy budget accounting.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-352` — storage reads use `enforce_storage_idx` for direct-position lookup, then clone the `EntryWithLiveUntil`; the synthetic lookup charge is real, but the entry clone and surrounding storage semantics remain.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-457` and `600-628` — writes and TTL extensions use known-position replacement when possible; a direct-metering change would not eliminate the functional-map rebuild, deep-clone, scan charge, or canonical storage update.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83`, `168-194`, and `317-348` — normal `find` charges `charge_binsearch` before binary search, while `get_at_known_position` skips comparisons but deliberately keeps `charge_binsearch` and `charge_access(1)`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:238-287` and `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — each charge updates trackers, evaluates CPU and memory cost models, checks limits, and, in Tracy builds, emits the `charge` span; broad `charge` self-time cannot be attributed entirely to indexed storage.

### Why It Failed

The inefficiency exists, but the projected impact is below this objective's severity floor. The most specific measured target, `map lookup indexed`, is about 681 ms over ~929k in-apply events in the diagnostic run; spread over the benchmark's apply windows and normalized by 8-way parallel Soroban execution, even eliminating the indexed lookup's synthetic budget-charge work entirely is roughly low-single-millisecond or sub-millisecond wall time per ledger, well below 3% of the accepted ~207.6 ms soroswap median. The broader `charge` span is also not a safe Medium estimate because it includes all host budget charges and Tracy text/value emission, while a correct protocol-gated direct path would still need access metering, budget/resource-limit bookkeeping for other operations, storage entry clones, write-map rebuilds, TTL handling, and deterministic fallback behavior.

### Lesson Learned

Post-side-index storage metering is a real but narrow optimization target. For Soroban worker-thread hotspots, normalize aggregate trace time by configured cluster parallelism and isolate only the charges a correct protocol-gated direct path can remove; broad `charge` or `storage get` totals overstate the serial apply-time savings.
