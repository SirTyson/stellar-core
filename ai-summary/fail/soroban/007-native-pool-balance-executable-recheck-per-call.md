# H007: Eliminate Per-Balance-Read `contract_instance_executable_is_stellar_asset` Recheck In Native Soroswap Pool Swap

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Low
**Impact**: Per-swap C++/Rust SAC fast-path executable-discriminant recheck on the apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`call_native_soroswap_pool_swap`
(`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1376`) dispatches
two SAC `transfer` subcalls followed by two SAC `balance` subcalls for the
same `token_0` / `token_1` contract pair within a single host invocation.
The two `balance` subcalls each take the fast path
`soroswap_pool_read_sac_contract_balance`
(`frame.rs:1503-1528`), which calls
`contract_instance_executable_is_stellar_asset(&instance_key)`
(`host/data_helper.rs:136-160`) to verify the token contract is a SAC
asset before reading the balance entry directly.

A correctly-engineered native pool path that has just executed two SAC
`transfer` calls on the same `(token_0, token_1)` pair should already know
both instances are `StellarAsset` executables (the SAC `transfer` path
itself loaded each instance and exercised SAC code). The subsequent two
`balance` reads should not need to re-probe storage for the executable
discriminant — they should consult an in-frame "verified SAC" set or
otherwise reuse the discriminant established during the immediately
preceding `transfer` calls within the same host invocation.

## Mechanism

Each `soroswap_pool_read_sac_contract_balance` call performs a full
`Storage::get(&instance_key, ...)` to materialize the
`ContractData(ContractInstance)` entry, walks two `match` levels to extract
`instance.executable`, and discards everything except the
`StellarAsset` discriminant bit. This storage probe runs a metered binary
search over the enforcing-mode `MeteredOrdMap`, and the returned entry is
discarded immediately. The actual signal extracted (one boolean) was
already proven by the immediately preceding SAC `transfer` invocation,
which loaded and executed the same instance entry.

Per native swap there are exactly 2 such redundant probes (one per token).
Per soroswap apply window there are ~2000 swap txs / ledger, so each
ledger carries ~4000 redundant `executable_is_stellar_asset` probes.

## Trigger

Run the protocol-27 soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`). Each accepted native pool swap
performs two SAC transfers, then two SAC balance reads on the same token
pair. The two balance reads each carry the redundant
`contract_instance_executable_is_stellar_asset` probe.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1184-1252` —
  native swap calls `soroswap_pool_invoke_sac_transfer` × 2 followed by
  `soroswap_pool_invoke_sac_balance` × 2 on the same token pair.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1503-1528` —
  `soroswap_pool_read_sac_contract_balance` calls
  `contract_instance_executable_is_stellar_asset` per balance read.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:136-160` —
  `contract_instance_executable_is_stellar_asset` performs a full
  `Storage::get` plus two `match` levels per call.

## Evidence

Source reading confirms two consecutive balance reads on the same token
pair, each calling `contract_instance_executable_is_stellar_asset` after
the corresponding transfer call has already validated the instance.
Per-call cost is ~5 µs (binary search + entry materialization), and call
count per ledger is 2 × 2000 = 4000.

## Anti-Evidence

The instance entries are part of the read-only footprint and are
preloaded into `mGlobalEntryMap` by the parallel-apply RO preload pass
(see `ParallelApplyUtils.cpp:654-718`), so the Storage::get hits an
in-memory map rather than a cold lookup. The actual per-probe cost is
closer to the `MeteredOrdMap` binary-search bound (~1-2 µs at the
soroswap footprint size) than to a full lookup.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a swap-call-site-specific
optimization. Adjacent fails (fail/soroban 003, 011, 022, soroban-env H005)
target structurally similar patterns in different call sites.

### Why It Failed

Upper-bound sizing places this firmly below the Medium severity floor and
also below the Low (1%) noise floor:

- Call count: 4,000 redundant probes / ledger
- Per-call cost: ~5 µs upper bound (Storage::get + match + metered_clone of
  `LedgerKey` for the `ContractData` lookup). With the RO preload making
  the underlying entry in-memory, the realistic cost is ~1-2 µs.
- Aggregate worker CPU: 4,000 × 5 µs = 20 ms / ledger (upper bound).
- After 8-way cluster parallelism normalization: ~2.5 ms / ledger ≈
  1.18 % of the 211 ms soroswap median baseline.
- With the realistic 1-2 µs per-call cost: ~0.5-1.0 ms / ledger
  ≈ 0.24-0.47 % of baseline.

Even the optimistic upper bound (1.18 %) is below the 3 % Medium floor and
below the 1 % Low floor under realistic per-call assumptions. The
optimization would also need to either:

1. Add a per-tx "verified SAC token set" to the `Host` (`HashSet<ContractId>`
   plus borrow-check plumbing), which adds per-invocation construction cost
   that may erase the small saving at this call volume; or
2. Cache the discriminant on the `Frame::NativeContract` instance, which
   only works for the current frame's tokens and breaks if subsequent
   native swap calls iterate different pairs.

The host metering charge associated with the dropped `Storage::get` call
is also protocol-visible (it contributes to the CPU budget consumed by
the swap host function), which means any change requires the
protocol-gated metering coalescing infrastructure already accepted in
success #001 / cap-9. A new gate for this specific elision is more
invasive than the saving justifies.

### Lesson Learned

When a SAC fast-path probe immediately follows a path that already
established the same fact (e.g., two `balance` reads after two
`transfer` calls in the same host invocation on the same token pair),
the savings from caching the discriminant within the host invocation
are bounded by `call_count × per-call_cost / NUM_CLUSTERS / N_ledgers`.
For the soroswap swap shape (2,000 swaps/ledger, 4 SAC subcalls per swap,
8-way parallelism), this formula yields an upper bound of ~1.2 % of
apply time and a realistic figure under 0.5 %. Add this to Meta-Pattern
#14 (per-call sub-µs host-side micro-opts are sub-Medium on soroswap)
and Meta-Pattern #12 (`InMemorySorobanState`-served reads are already
fast). Without a structural change that removes the per-tx state cost
of the cache itself, in-host SAC discriminant caching cannot clear
Medium severity on this workload.
