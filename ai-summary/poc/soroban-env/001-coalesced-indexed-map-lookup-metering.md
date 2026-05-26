# H001: Coalesced Indexed Map Lookup Metering

**Date**: 2026-05-26
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated per-entry indexed lookup charge overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When enforcing-mode Soroban storage already has a side index proving the position of a `LedgerKey`, the host should read that known position deterministically without paying a tiny physical budget-charge path for every lookup. For the next-protocol apply-load configuration, the host should either preserve the intended aggregate metering with a deterministic bulk charge or intentionally use the next protocol's coalesced metering model, while keeping the same storage/footprint access decisions and ledger effects.

## Mechanism

`Storage::with_enforcing_footprint_and_map` builds side indices for footprint and storage maps, but `MeteredOrdMap::get_at_known_position` still executes `charge_binsearch` and per-access charge logic on every known-position hit. In the current soroswap trace, `map lookup indexed` at `soroban-env-host/src/host/metered_map.rs:330` has 478,055,076 ns self-time across 861,026 calls; unwrap containment shows 857,702 of those events inside `applyLedger`. A next-protocol-only fast path that bulk-charges deterministic indexed lookups at loop boundaries, then performs a bounds check and direct `Vec::get`, should remove a hot per-entry charge/update path without changing key ordering or observable ledger output.

## Trigger

Run the current next-protocol soroswap apply-load benchmark (`TX=2000,T=8`). Each invocation constructs enforcing storage side indices, then repeatedly hits `get_at_known_position` during contract storage reads/writes and during `get_ledger_changes` over every footprint entry.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-339` — known-position lookup still performs per-call `charge_binsearch` and access charging.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-344` — storage reads route side-index hits through `get_at_known_position`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:248-320` — ledger-change extraction performs known-position lookups for initial storage and footprint access type.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1383-1417` — existing `bulk_charge` and `coalesced_host_metering` machinery can host the protocol-gated aggregate charge.

## Evidence

The current diagnostic trace from `ai-summary/CURRENT_STATE.md` shows `applyLedger` as the measured envelope and `map lookup indexed` as a top Soroban self-time zone: 478.1 ms self-time, 861,026 calls, mean 555 ns. Unwrap containment confirms 857,702 events and 623,988,001 ns of event duration fall inside `applyLedger` windows. The source shows those indexed lookups no longer do binary-search comparisons, so the remaining hot work is dominated by budget charging and bookkeeping rather than necessary key search.

## Anti-Evidence

p26 exact metering makes charge-count changes protocol-visible, and prior failures show that removing or deferring `charge()` calls can change `BudgetExceeded` timing observed through `try_call`. This must therefore be next-protocol gated, should avoid released-p26 replay changes, and needs careful proof that any bulk charge is placed at deterministic points where budget-limit behavior is either preserved or intentionally redefined by the protocol transition.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The current p26 apply path builds enforcing-mode side indices in `invoke_host_function`, stores them on `Storage`, and then routes footprint checks, storage reads, and final ledger-change diff lookups through `get_at_known_position`. That helper no longer performs a binary search, but it still executes `charge_binsearch` and `charge_access(1)`, which each take the full `Budget::charge` path. Prior soroban-env success `002-specialize-storage-map-lookup-fast-path.md` is related but deliberately preserved explicit search/access charges, so this hypothesis targets a remaining physical metering overhead rather than a duplicate lookup-specialization finding.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-523` — host invocation decodes resources, builds `Footprint`/`StorageMap`, clones the initial map, constructs enforcing `Storage`, then sets ledger info, which enables next-protocol coalesced host metering.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — `with_enforcing_footprint_and_map` builds `LedgerKey -> position` indices for both footprint and storage maps; the key set is fixed in enforcing mode, so positions remain valid for lookup.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:288-347` — footprint enforcement and storage reads consult the side indices, then call `get_at_known_position` on hits; misses intentionally preserve the legacy lookup charge through `charge_lookup`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:248-320` — `get_ledger_changes` iterates the storage map and performs known-position lookups into the cloned initial map and footprint map for every entry when lengths match.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83,317-339` — the indexed lookup helper performs a direct `Vec::get`, but first charges a MemCpy binary-search model and then charges one-entry access on success.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:238-287,1383-1417` — every charge updates tracker fields, evaluates CPU/memory dimensions, and checks limits; existing `bulk_charge` and `coalesced_host_metering` are available for next-protocol batching or intentional coalescing.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:576-582` — `set_ledger_info` enables `coalesced_host_metering` only for ledger protocols greater than p26's minimum, providing the required released-protocol safety gate.

### Findings

The inefficiency exists. Once the side index has produced a verified position, `get_at_known_position` performs no key comparison or search, so the repeated `charge_binsearch`/`charge_access` calls are physical metering overhead around a bounds-checked vector access. This is hot in the objective scope: storage access happens during Soroban contract execution under `closeLedger`, and ledger-change extraction runs after successful invocation as part of apply-side host-function processing.

Existing optimizations do not remove this cost. The accepted storage lookup fast path specialized the search/comparison path while preserving explicit budget charges, and the existing protocol-gated host metering coalescing applies to `VisitObject`/`ValSer`, not indexed map lookups. The current baseline's trace projection is close to the Medium floor but credible: roughly 0.48-0.62s of indexed-lookup event time over the diagnostic soroswap apply run is approximately a 3-4% share of total apply time if most of the per-call metering path is removed.

Correctness hinges on the protocol gate. Released p26 must continue to use the current exact charge timing and totals. For next protocol, the PoC can either preserve aggregate MemCpy totals with deterministic bulk charges where counts and inputs are known, or explicitly define indexed side-index lookups as part of the next protocol's coalesced host metering model; in either case it must keep the direct lookup's bounds check and stale-index internal-error behavior.

### PoC Guidance

- **Target code**: `host/metered_map.rs::get_at_known_position`, `storage.rs::{enforce_access_indexed,try_get_full_helper,put_opt_helper,apply_ttl_extension}`, `e2e_invoke.rs::get_ledger_changes`, and `budget.rs` if an exact batched charge helper is needed.
- **Change description**: add a next-protocol-only indexed lookup path behind `Budget::coalesced_host_metering()`. For deterministic loops such as `get_ledger_changes`, precompute the number of indexed initial-map and footprint hits and replace repeated identical MemCpy lookup/access charges with `bulk_charge` or an exact per-leaf batched helper before doing unchecked-by-metering direct `Vec::get` calls. For per-operation storage reads, either use the same next-protocol coalesced model to skip indexed-lookup bookkeeping entirely, or add an explicit accumulator that flushes at deterministic frame/invocation boundaries without changing released p26 behavior.
- **Correctness check**: existing storage, map, protocol-gate, e2e invoke, and budget-metering tests should cover the core path; any budget-number updates must be limited to exact lower next-protocol metering expectations. Add focused tests that p26 leaves `get_at_known_position` charge totals unchanged and next protocol preserves storage/footprint decisions and ledger changes.
- **Benchmark focus**: run `scripts/run_apply_load_matrix.py` three times and compare soroswap median apply time against the current `CURRENT_STATE.md` baseline. The expected signal is a 3-4% median improvement if the trace projection holds; the diagnostic Tracy run should show the `map lookup indexed` zone disappear or shrink sharply and fewer per-lookup `Budget::charge` events.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-26
**PoC by**: claude-opus-4.7, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs`
  (`get_at_known_position`, lines ~317-348, and `charge_lookup`): gate the
  per-call `charge_binsearch` + `charge_access(1)` metering on
  `Budget::coalesced_host_metering()`. When the next-protocol coalesced
  metering flag is enabled (established by `Host::set_ledger_info` for
  ledger protocols above `MIN_LEDGER_PROTOCOL_VERSION`), both helpers
  skip charging and the tracy span is suppressed, mirroring the same
  pattern already used by `visit_obj_untyped` (host_object.rs) and
  the batched ValSer fast path (metered_xdr.rs). Released p26 keeps
  exact charge totals because the flag stays `false` at
  `MIN_LEDGER_PROTOCOL_VERSION`.

- `src/transactions/ParallelApplyUtils.cpp` (line ~803): restored a
  missing function header for
  `GlobalParallelApplyLedgerState::getSnapshotLedgerSeq()` that was
  pre-existing dirty worktree state and prevented compilation. Not part
  of the optimization; required only to build.

### Demonstration

The change removes per-call `Budget::charge` work (refcell borrow,
tracker update, dimension evaluation, limit check) from the hot
indexed-lookup path used by enforcing-storage reads, footprint access
checks, and `get_ledger_changes` post-execution diffing. Each
`get_at_known_position` call already performs zero key comparisons —
the side index has supplied a verified position — so the remaining
work was metering bookkeeping. With the coalesced-metering gate the
fast path is just a bounds-checked `Vec::get`, plus an internal-error
guard for stale indices. Released p26 behavior is unchanged because
the protocol gate flips on exactly when other already-shipped
coalesced charges flip on.

### Test Results

`env NUM_PARTITIONS=$(nproc) STELLAR_CORE_TEST_PARAMS='--ll fatal -r
simple --abort --disable-dots' make check` ran to completion. All
TESTS report `FAIL: 0` and `ERROR: 0` across the full C++ suite, the
Rust soroban-env-host workspace tests (including the
`protocol_gate::ledger_protocol_controls_coalesced_host_metering`
test that pins the next-protocol gating semantics this change rides
on), the fees, integration, option, and secp256r1 integration tests,
and the `selftest-nopg` / `check-nondet` top-level harnesses
(`All 2 tests passed`). No budget-number test edits were required.
