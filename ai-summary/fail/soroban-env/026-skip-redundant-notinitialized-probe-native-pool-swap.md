# H026: Skip Redundant NotInitialized Storage Probe in `call_native_soroswap_pool_swap`

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: <0.05% soroswap apply-time reduction; sub-Medium and rejected under objective threshold
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`call_native_soroswap_pool_swap` runs only after `try_call_native_soroswap_pool_swap` has already
verified, via `Self::soroswap_pool_scmap_has_address(storage, 0)`, that the pair instance contains
an `Address`-valued entry at key `0` (the `token_0` slot). The Wasm pair's `NotInitialized` check
maps to "has key `0` storing some non-default token address", which the pre-frame guard already
proved. The body therefore should not need to re-execute the same probe.

## Mechanism

The current code re-runs the NotInitialized check
(`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1096-1101`):

```rust
// NotInitialized check: pool wasm checks `has_token_0`.
if self
    .soroswap_pool_instance_storage_get(0)?
    .is_none()
{
    return Err(self.soroswap_pool_contract_err(SOROSWAP_ERR_NOT_INITIALIZED));
}
```

`soroswap_pool_instance_storage_get` (lines 969–972) calls `with_instance_storage`, builds a
`Val::from_u32(0)` key, and invokes `MeteredOrdMap::get` on the frame's `InstanceStorageMap`,
charging `charge_access`, a `find` binary-search (Compare<Val> + comparator), and key conversion.

But `try_call_native_soroswap_pool_swap` (lines 1056–1062) has already verified:

```rust
if !Self::soroswap_pool_scmap_has_address(storage, 0) || ... {
    return Ok(None);
}
```

This walks the upstream `ScMap` (untyped, pre-instance-storage-map) for an `Address` at key `0`,
which is exactly what the NotInitialized check is proving. The two probes are redundant on the
success path.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on the next-protocol soroswap
workload. Every accepted native pool swap re-runs the same key-`0` presence check at line
1096–1101.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1096-1101` — redundant
  `soroswap_pool_instance_storage_get(0).is_none()` NotInitialized check.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1056-1062` — upstream guard that already
  proved the key-`0` `Address` presence on the same instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-972` —
  `soroswap_pool_instance_storage_get` implementation showing the per-call charges.

## Evidence

The Tracy CSV from
`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`
shows `map lookup` and `map lookup indexed` aggregating 815 ms self-time across 1.33M lookups; the
per-lookup average is ~600 ns. The NotInitialized probe is one such lookup per native pool swap
(~7,000 swaps).

## Anti-Evidence

The removable physical work per swap is:
- One `Val::from_u32(0)` key build: ~10 ns.
- One `with_instance_storage` borrow: ~50 ns.
- One `MeteredOrdMap::get` on a 5-entry sorted Vec: `charge_access` (~50 ns) + binary-search
  `find` with ~3 comparator calls (~600 ns total) = ~650 ns.

Total removable per-swap: ~700 ns. With ~7,000 swaps per benchmark window, 8-way cluster
parallelism, and 70 ledgers, the aggregate wall-time saving is
`7,000 × 700 ns / 8 ≈ 0.6 ms` against a ~215 ms soroswap median apply window — **~0.0003%** of
apply time, **four orders of magnitude** below both the 1% noise floor and the 3% Medium floor.

Additionally, the metered `charge_access`/comparator charges are protocol-visible; even if the
physical lookup were skipped, those charges must be manually replayed to preserve
`cpu_insns`/`mem_bytes` (Meta-Pattern #2), leaving essentially zero removable physical work after
budget compatibility.

A correctness wrinkle further reduces viability: the upstream `has_address(0)` guard runs against
the *raw* `ScMap` from `instance.storage`, while the in-body check runs against the host
`InstanceStorageMap` which has been lazily decoded into `Val`s. If a future contract somehow
mutated instance storage during the brief window between frame push and NotInitialized check (it
cannot today, but the host explicitly does not assume immutability of instance storage), removing
the in-body probe would skip the freshly-required initialization check. The defensive in-body
probe is structurally sound.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Adjacent fail entries (e.g.
`fail/023-deduplicate-instance-lookup-in-extend-current-instance-and-code-ttl.md`,
`fail/004-static-wasm-hash-skip-instance-retrieve-in-pool-code-ttl-extend.md`) target redundant
*storage entry* lookups in TTL helpers; this hypothesis targets redundant *instance-storage map*
lookups within the native pool swap body itself, which is a distinct code path.

### Why It Failed

Projected impact is ~0.0003% apply-time reduction — four orders of magnitude below the objective's
3% Medium floor. Per-swap removable work is ~700 ns and the call count is ~7,000 events per
benchmark window. Even an aggressive "skip the probe entirely without budget replay" approach
would shift protocol-visible budget accounting (rejected per Meta-Pattern #2) while saving only
sub-millisecond wall time. The defensive in-body probe also guards against a hypothetical future
mutation of `InstanceStorageMap` between frame push and body entry, so removing it would slightly
narrow safety margins for a saving below benchmark noise.

### Lesson Learned

Within-`call_native_soroswap_pool_swap` redundant-probe elimination follows the
sub-Medium-aggregation pattern documented in `fail/004` and `fail/023`: individual µs-scale
removable operations on ~7,000-event call counts cannot clear Medium even before subtracting
mandatory replayed metering charges. Future native-pool-internal micro-optimization hypotheses
should aggregate removable per-swap physical work across **all** redundant probes/charges/clones
in the entire native pool path and pre-quantify total wall savings against the apply window before
promotion; piecewise µs savings on 7k call counts will not clear the objective threshold.
