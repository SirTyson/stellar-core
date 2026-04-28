# H002: Cache Decoded SAC Address Wrappers

**Date**: 2026-04-28
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding repeated host-object visits and metered clones for the same SAC address arguments
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC balance and transfer logic should continue to distinguish account addresses from contract addresses, enforce authorization, construct the same balance keys, emit the same events, and preserve the same externally visible host object handles for contract arguments. Once a SAC `Address` wrapper has been constructed from an `AddressObject`, repeated `to_sc_address()` calls on that wrapper or its clones should not repeatedly look up and clone the same `ScAddress` host object.

## Mechanism

`builtin_contracts::base_types::Address` stores only `{ host, object }`, and `Address::to_sc_address()` calls `Host::scaddress_from_address` every time. That helper enters the hot `visit host object` path and metered-clones the underlying `ScAddress`; SAC `transfer` then clones and reuses the same `from`/`to` addresses through `require_auth`, authorization checks, `spend_balance`, `receive_balance`, and event emission. In the current longest soroswap `applyLedger` interval, `visit host object` accounts for 1.074 s of aggregate overlap across 1.226M calls, while global self-time shows `visit host object` at 657.549 ms and `add host object` at 79.810 ms; caching the decoded `ScAddress` inside the SAC wrapper would remove repeated address-object visits from this dominant SAC path without changing parallel scheduling or ledger ordering.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap`, 4000 tx, 8 clusters) using the trace in `ai-summary/CURRENT_STATE.md`. The issue triggers when SAC `transfer` receives `Address` and `MuxedAddress` arguments, then repeatedly converts the same addresses to `ScAddress` while checking authorization, reading/writing balances, and building transfer events.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:305-385` — `Address` stores only an `AddressObject`; `to_sc_address` calls back into the host on every use.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256` — `scaddress_from_address` uses `visit_obj` and `metered_clone` for each address decode.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-224` — SAC `transfer` calls `from.require_auth`, clones `from` and `to`, and passes them through balance and event helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — `read_balance` converts the same wrapper with `to_sc_address`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` converts, clones, and reuses the same address while checking and writing contract balances.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-190` — `spend_balance_no_authorization_check` repeats the same address conversion and balance-key construction.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:232-254` — `is_authorized` converts contract addresses again to decide the authorization path.

## Evidence

The target is under `applyLedger`: the longest steady soroswap apply window contains 3,042 `SAC transfer` calls, 3,039 `SAC balance` calls, 1.112 s of `SAC transfer` aggregate overlap, and 1.074 s of `visit host object` overlap. The source shows that a contract-address transfer can call `to_sc_address()` for the same logical address in `is_authorized`, `spend_balance_no_authorization_check`, `receive_balance`, and event/key construction, and each call currently performs a host object lookup plus `ScAddress` clone. An eager or lazy `Address { host, object, sc_address }` representation, populated once when converting from `AddressObject`, should turn repeated conversions into cheap field reads while keeping the original object handle for `require_auth`, comparisons, and emitted arguments.

## Anti-Evidence

This overlaps the general `visit host object` hotspot, but it is not the previously failed host-object budget batching idea: it removes repeated visits for already-decoded SAC address wrappers rather than reordering or batching budget charges across arbitrary objects. The reviewer must quantify how much of `visit host object` comes specifically from SAC address conversion; if most visits come from maps, vectors, events, or VM boundary conversions, this may fall below the 3% Medium floor. Budget metering also needs an explicit decision: either preserve same-protocol resource accounting by charging equivalent clone/visit costs when returning the cached address, or gate the lower resource usage as an intentional protocol-versioned optimization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The p26 Soroban apply path builds a fresh host per invoke-host-function transaction, enters the built-in SAC frame for SAC calls, and passes SAC arguments as `Address` wrappers that currently hold only a host reference and an `AddressObject` handle. The claimed repeated `to_sc_address()` conversions are real in the SAC balance helpers: transfer can decode the same logical address once in `is_authorized` and again in `spend_balance_no_authorization_check` or `receive_balance`. However, the broader path cited by the hypothesis is mostly not removable by an `Address` wrapper cache: `require_auth`, event topics, issuer comparisons, authorization tracker matching, and `DataKey::Balance` conversion preserve/use object handles and compare through `obj_cmp`, not through `Address::to_sc_address()`. The remaining duplicate address decodes are only a few thousand visits out of the 1.226M `visit host object` calls in the cited trace.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-462` — each Soroban invoke constructs a fresh `Host`, decodes auth entries and host function data, and installs source/ledger/auth state before execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — SAC calls are dispatched through `Frame::StellarAssetContract` with a cloned `Vec<Val>` of original arguments; the built-in receives `Address` wrappers converted from those values.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:305-385` — `Address` contains only `host` and `object`; `to_sc_address()` delegates to `Host::scaddress_from_address`, while `require_auth()` and `as_object()` keep using the original object handle.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256` — every `scaddress_from_address` call performs `visit_obj` and a metered `ScAddress` clone.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-528` — `visit_obj` enters the `visit host object` Tracy zone, charges `VisitObject`, borrows the object table, validates the absolute handle, and then calls the typed closure.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` converts `to_mux` to an `Address`, requires auth for `from`, then calls `spend_balance`, `receive_balance`, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-229,233-254` — `read_balance`, `receive_balance`, `spend_balance_no_authorization_check`, and `is_authorized` are the actual repeated `to_sc_address()` users.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/storage_types.rs:31-35` and `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:195-203` — `DataKey::Balance(Address)` serializes through `Val::try_from_val(Address)`, which returns the address object handle rather than decoding `ScAddress`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-62,94-113` — transfer event selection compares/emits `Address` values through host value conversion and `Compare`, not by calling `to_sc_address()`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3605-3631` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:938-1004` — `require_auth` clones current frame args and matches authorization trackers by comparing address objects, so an `Address` wrapper-local decoded cache would not avoid these visits.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1223-1231` and `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145` — object comparisons route through `obj_cmp` and `visit_obj_untyped`; they do not consult SAC `Address` wrapper state.
- `ai-summary/CURRENT_STATE.md:21-28` — the current objective baseline uses a 596.381 ms soroswap median apply time, so the Medium floor is about an 18 ms wall-clock reduction.

### Why It Failed

The inefficiency exists, but the removable portion is far below the optimize-soroswap Medium threshold. In the cited window, `SAC transfer` fires about 3,042 times and `SAC balance` about 3,039 times. A standalone SAC balance performs only one `Address::to_sc_address()` conversion, so caching inside that wrapper has no duplicate decode to remove. A transfer can remove at most the second decode for `from` and the second decode for `to` across `is_authorized`, `spend_balance_no_authorization_check`, and `receive_balance`, plus a small muxed-address edge if the argument is actually muxed.

That is roughly 6k duplicate address-object visits in the main transfer path, not the 1.226M total `visit host object` calls attributed to the whole Soroban apply trace. Using the hypothesis's own global self-time, `visit host object` averages about 0.54 microseconds per call, so removing 6k visits recovers only around 3 ms of aggregate worker self-time before any normalization. With 8 configured clusters, that is well under 1 ms wall-clock equivalent against a 596 ms apply baseline; even very optimistic assumptions about metered `ScAddress` clone cost remain far below the 18 ms wall-clock improvement needed for Medium severity.

The correctness constraints further reduce the benefit. If the cache preserves same-protocol resource accounting by charging equivalent `VisitObject`/`MemCpy` costs on cached reads, most of the cited `visit_obj` budget-charge work remains. If it intentionally lowers budget usage, it becomes a protocol-visible metering change that needs protocol gating and still does not have enough isolated address-decode volume to meet the objective floor.

### Lesson Learned

`visit host object` is too broad to attribute wholesale to SAC address decoding. SAC address wrapper caching targets only explicit `Address::to_sc_address()` calls; auth matching, event construction, object comparison, muxed-address extraction, map/vector operations, and storage-key conversion use separate object-handle paths that a wrapper-local decoded `ScAddress` cache would not accelerate.
