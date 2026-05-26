# H007: Fuse Shared `try_borrow_storage_mut` Across Instance+Code TTL Extension Pair

**Date**: 2026-05-26
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Apply-time reduction via removed duplicate RefCell borrow round-trips and an avoided `retrieve_contract_instance_from_storage` clone on the SAC code-TTL no-op path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Host::extend_current_contract_instance_and_code_ttl`
(`src/rust/soroban/p26/soroban-env-host/src/host.rs:2344-2359`) should perform
the minimum bookkeeping necessary to extend the current contract's instance
TTL and (for Wasm contracts) its code TTL: at most one
`try_borrow_storage_mut`, one footprint-enforced TTL update for the instance
key, and one TTL update for the code key only when the executable is Wasm.
For SAC frames the second update is a no-op and the helper should avoid
re-borrowing storage and re-retrieving the contract instance solely to
discover that the executable is `StellarAsset`.

## Mechanism

Today the helper invokes two sibling helpers — `extend_contract_instance_ttl_from_contract_id`
(`data_helper.rs:307`) and `extend_contract_code_ttl_from_contract_id`
(`data_helper.rs:287`). Each does its own `try_borrow_storage_mut()` and
its own metered storage operation. The code-side helper additionally calls
`retrieve_contract_instance_from_storage` purely to inspect the executable
discriminant — and for SAC frames the entire body falls through to
`StellarAsset => {}` after paying a `Storage::get` + `ScContractInstance::metered_clone`.
A fused helper holding one storage borrow, peeking the executable
discriminant via the existing `host/data_helper.rs` peek introduced in
`success/001-direct-sac-balance-for-native-pair.md`, and performing the
instance-TTL extension plus an optional code-TTL extension under the same
borrow would remove (a) one `RefCell` borrow round-trip and (b) one
`Storage::get` + `metered_clone` on the SAC path.

## Trigger

Every SAC frame in `applyLedger` invokes
`extend_current_contract_instance_and_code_ttl` once. Native SAC frames (the
dominant path in soroswap) walk the SAC branch where the code-TTL helper
performs a wasted `retrieve_contract_instance_from_storage` for the sole
purpose of discriminating `StellarAsset`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2344-2359` — `extend_current_contract_instance_and_code_ttl`
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-305` — `extend_contract_code_ttl_from_contract_id` (peek executable)
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:307-321` — `extend_contract_instance_ttl_from_contract_id`
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:extend_ttl` — TTL update API; would need a small variant accepting an external mutable borrow or two pre-computed (key, threshold, extend_to) tuples in one call

## Evidence

Tracy `extend_current_contract_instance_and_code_ttl` is 227 ms self-time at
`vmcaller_env.rs:270` plus 48 ms self at `dispatch.rs:304` across 16,098
calls. The helper is invoked from every contract frame, and the SAC subset
(no-op code-TTL branch) is the dominant fraction in soroswap (each SAC
transfer triggers one extension; ~14k SAC transfer events per benchmark
window). The peek-only executable-discriminant helper from
`success/001-direct-sac-balance-for-native-pair.md` already provides the
infrastructure to skip the full `retrieve_contract_instance_from_storage`
clone when only the executable kind is needed.

## Anti-Evidence

The mandatory protocol-visible work dominates this helper: one footprint
enforcement charge, one TTL-map lookup charge, one `Storage::extend_ttl`
update charge, and (for Wasm frames) one storage `get` + metered clone
charge for the code-TTL retrieve. The fused-borrow physical savings are
the `RefCell::try_borrow_mut` round-trip (low tens of ns) and, on the SAC
branch only, the unmetered fraction of the avoided `retrieve_contract_instance_from_storage`
clone. Per-call physical savings sum to roughly 3–5 µs (mostly from the
avoided SAC-path clone). With ~16,000 calls per benchmark window across 8
parallel workers and 71 ledgers, total wall-clock saving is
`5 µs × 16,000 / 8 / 71 ≈ 0.14 ms/ledger ≈ 0.07 %` of the 207 ms
soroswap baseline — well below the 1 % Low floor and three orders of
magnitude below the 3 % Medium floor this objective requires.

This investigation also overlaps directly with prior failures
`003.md` (memoize repeated SAC TTL extensions), `002-frame-instance-shortcut-extend-ttl.md`
(use frame instance to bypass retrieve), and
`023-deduplicate-instance-lookup-in-extend-current-instance-and-code-ttl.md`
(thread instance entry between the two passes). Those reached the same
sub-Medium ceiling for the same reason: protocol-visible metering forces
charge replay on every removed `Storage::get` / `MeteredClone`, and the
unmetered residual is small after parallelism normalization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — fused-borrow + peek-discriminant on the *same* extension call is novel relative to listed fail entries, but the projected impact is in the same sub-Low band that defeated those prior memoization/shortcut variants.

### Why It Failed

Aggregate `extend_current_contract_instance_and_code_ttl` self-time
(~275 ms across both wrapper layers) is already only 2.7 % of trace
self-time, and the *removable* fraction after protocol-visible metering
(one TTL-update charge, one optional retrieve charge, one optional
instance metered_clone) is at most a few µs per call. After 8-way
cluster parallelism and 71-ledger windowing this contributes < 0.1 %
of the soroswap apply baseline — below the objective's Medium floor by
two orders of magnitude and below the Low floor as well.

### Lesson Learned

For TTL-extension shortcut hypotheses in the current p26 metering
regime: the helper-body redesign saves only the unmetered `RefCell` and
clone residual; the rest is mandatory. Future TTL-extension Medium
hypotheses must redesign at a coarser granularity (e.g. transaction-wide
batched TTL settlement coordinated with the C++ apply path) and account
for the next-protocol metering changes such a redesign would require.
