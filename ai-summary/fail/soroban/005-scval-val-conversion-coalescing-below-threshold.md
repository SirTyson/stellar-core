# H005: Protocol-gated bulk ScVal/Val conversion coalescing for Soroban host objects

**Date**: 2026-05-03
**Subsystem**: soroban
**Severity**: Low
**Impact**: Reduce recursive host value conversion and map construction overhead in Soroban apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol 27+ execution, converting between XDR `ScVal` values and host `Val`/object representations should produce the same semantic values, ledger effects, contract events, and error behavior as the current implementation. Released p26 metering should remain unchanged, while any coalesced conversion accounting for a new protocol should still charge deterministic totals and preserve budget-exceeded behavior at defined boundaries.

## Mechanism

`Host::to_host_obj` recursively converts `ScVal::Vec` and `ScVal::Map` by allocating temporary vectors, calling `to_host_val` for every element, then constructing `HostVec`/`HostMap`; the reverse path `from_host_obj` recursively walks host objects and clones XDR values. The current trace still reports large aggregate self-time in `ScVal to Val`, `Val to ScVal`, `new map`, and `add host object` after the accepted typed SAC balance and host-metering coalescing work. A next-protocol bulk conversion mode could charge conversion work once per aggregate object and use specialized builders for trusted internal XDR values, avoiding per-leaf helper overhead while keeping p26 exact metering intact.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. The issue is triggered by normal successful Soroban host execution under `closeLedger`, especially contract argument/result conversion, authorization context construction, storage value conversion, and event construction paths that move nested maps/vectors between XDR and host-object representations.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-460` — top-level `from_host_val`, `from_host_val_for_storage`, `to_host_val`, and `to_valid_host_val` Tracy zones.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-620` — `from_host_obj` and `to_host_obj` recursively convert nested object values.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `MeteredOrdMap::from_exact_iter` / `new map` allocation and scan path used for converted maps.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:441-456` — `add_host_object` appends converted host objects to the object table.

## Evidence

The current diagnostic trace shows all of these conversion zones inside `applyLedger`: timestamp filtering found 691,521/691,521 `ScVal to Val` events, 494,127/494,127 `Val to ScVal` events, and 170,072/170,072 `new map` events inside apply windows. The self-time CSV reports `ScVal to Val` at 429,988,065 ns, `Val to ScVal` at 245,978,039 ns plus 13,194,113 ns for the storage-key variant, `new map` at 331,023,872 ns, and `add host object` at 270,971,092 ns. The code paths are generic and recursive, so a protocol-gated trusted-XDR bulk conversion mode could plausibly remove repeated helper overhead across many host surfaces.

## Anti-Evidence

The aggregate numbers are worker CPU, not direct wall-clock saving. Dividing the combined conversion/map/object self-time by the 8 configured soroswap clusters and 71 apply windows yields only a few milliseconds per ledger before subtracting mandatory semantic work, allocation that still remains, and any replacement accounting overhead. Prior accepted work already removed the highest-value typed SAC balance conversions and protocol-gated host-object/ValSer metering, so the remaining broad conversion total is too diffuse for a standalone Medium hypothesis.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — not a duplicate of the accepted typed SAC balance fast path or host-metering coalescing records

### Why It Failed

The source-level inefficiency is real, but the measured opportunity is below the optimize-soroswap threshold. The broad conversion-related self-time totals about 1.29 s of aggregate worker CPU across the full trace (`ScVal to Val`, both `Val to ScVal` zones, `new map`, and `add host object`). In the balanced 8-cluster soroswap workload this is roughly 160 ms of critical-lane CPU over 71 apply windows, or about 2.3 ms per ledger before accounting for unavoidable conversion semantics. That is under 1% of the current non-Tracy soroswap median and therefore below even Low-tier acceptance, much less the required Medium floor.

### Lesson Learned

After the accepted typed SAC balance and protocol-gated host-metering optimizations, broad host conversion zones are too diffuse to justify another generic coalescing hypothesis. Future conversion work needs a narrow call site with measured critical-path time above the Medium threshold, not a sum of many small recursive conversion surfaces.
