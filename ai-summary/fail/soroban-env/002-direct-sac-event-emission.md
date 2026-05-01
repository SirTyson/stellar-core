# H002: Emit SAC events from typed ScVal data instead of round-tripping through host Vec/Val objects

**Date**: 2026-05-01
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing generic host-object construction and later `Val` -> `ScVal` externalization from hot Stellar Asset Contract transfer events
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Stellar Asset Contract transfer, mint, burn, approve, and admin events should produce the exact same `ContractEvent` XDR, in the same chronological order, with the same failed-call rollback behavior. Because SAC event helpers already have typed Rust values (`Address`, `i128`, metadata name, muxed id) before they build event topics/data, the host should not need to first allocate a host `VecObject`/`MapObject`/numeric `Val` representation and then convert those host objects back into `ScVal` during event externalization.

## Mechanism

`stellar_asset_contract/event.rs` builds every SAC event through `host_vec!`, `map_new`/`map_put` for muxed transfer data, and `e.contract_event(topics.into(), data.into())`. `contract_event` stores only `VecObject` topics plus a `Val` data field in `InternalContractEvent`, and `InternalContractEvent::to_xdr` later calls `vecobject_to_scval_vec` and `from_host_val` to reconstruct the XDR event. A typed SAC event path could construct `Vec<ScVal>` and `ScVal` data directly, store them in a new internal event variant or typed payload, and preserve event order/rollback while skipping host-object allocation, object visits, generic map/vector construction, and the second conversion pass.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). The soroswap path performs SAC transfers for token legs; the trace reports `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` with 329,402,855 ns self-time over 10,172 calls. Unwrap scope checking found 10,140 of 10,172 `SAC transfer` events inside `applyLedger`, totaling 2,245,135,102 ns of in-apply execution.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — transfer event path builds topics/data through host vectors/maps and generic contract-event API.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:116-167` — mint, clawback, set_authorized, set_admin, and burn event helpers use the same host-vector event construction pattern.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-198` — `read_name` decodes full SAC metadata for every event topic that includes the asset name.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1284-1291` — `contract_event` accepts only `VecObject` topics and `Val` data.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — `record_contract_event` stores the host-object based `InternalContractEvent`.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-39` — `InternalContractEvent::to_xdr` converts host topics/data back into XDR at externalization time.

## Evidence

- Tracy scope check: the target is under measured `applyLedger`, not TX-set construction. `SAC transfer` had 10,140 of 10,172 events inside `applyLedger`; `get_contract_data` had 101,564 of 101,916 events inside `applyLedger`, totaling 831,315,290 ns in unwrap execution.
- Related current self-time hot zones are consistent with the source mechanism: `contract_event` totals 43,435,866 ns in Wasm dispatch plus 23,593,300 ns in direct-env calls, `new vec` totals 47,199,275 ns, `add host object` totals 187,782,012 ns, `visit host object` totals 1,432,652,085 ns, and `Val to ScVal` totals 71,258,405 ns across its two reported locations.
- The round-trip is structural. SAC event helpers start with typed values, create host objects solely to call the generic event API, and the event buffer later externalizes those same values to `ContractEvent` XDR.
- Event rollback semantics are compatible with a typed internal payload: `InternalEventsBuffer` rolls back by marking events after a saved length as failed calls, independent of whether the event payload is stored as host objects or XDR values.
- This is distinct from the accepted typed SAC balance storage fast path, which optimized balance `DataKey`/`BalanceValue` storage reads/writes. This hypothesis targets event topics/data construction and externalization after balances are updated.

## Anti-Evidence

- Host object allocation can affect internal object-handle numbering. A direct event path must ensure no guest-visible handles or trace-observation expectations depend on the extra temporary event objects; otherwise it may need to preserve object allocation in observation/test modes.
- Budget accounting is protocol-visible. A PoC should either replay existing vector/map/conversion charges while removing physical host-object work, or deliberately update budget expectations only if the project accepts cheaper SAC event metering for this protocol branch.
- The cited object/conversion zones are broad upper bounds; they include non-event work from user Wasm, storage conversions, comparisons, and other host calls. Focused instrumentation is needed to isolate the SAC event subset.
- SAC metadata reads (`read_name`) still require correct invalidation during `init_asset` / `set_metadata` and must preserve missing-metadata errors. A direct event path can cache or carry the typed name, but only after proving initialized SAC metadata is immutable for normal transfer calls.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban-env` or `success/soroban-env`; cross-subsystem fail/success directories are absent
**Failed At**: reviewer

### Trace Summary

The claimed round-trip exists: SAC transfer-style helpers build event topics through `host_vec!`, optional muxed data through `map_new`/`map_put`, record only `VecObject` plus `Val`, and `Host::try_finish()` later externalizes those internal events into `ContractEvent` XDR. However, a correct direct-XDR event path still has to construct the final `Vec<ScVal>`/`ScVal` payload, clone address and name objects into XDR, encode contract events after `get_ledger_changes`, preserve rollback ordering, and either preserve or intentionally change protocol-visible budget charges. After subtracting that mandatory work, the safely removable subset is mostly intermediate `HostVec`/`HostMap`/contract-id object materialization and one generic conversion layer, which is not supported as a 3%+ soroswap apply-time improvement.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — hot SAC transfer path updates balances and then calls `event::transfer_maybe_with_issuer`; event emission is in apply but is only the tail of the transfer operation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:28-167` — approve/transfer/mint/clawback/set-authorized/set-admin/burn construct topics with `host_vec!`; normal non-muxed transfer data is only an `i128` `Val`, while muxed data uses a temporary host map.
- `src/rust/soroban/p26/soroban-env-host/src/macros.rs:63-69` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:1085-1092` — `host_vec!` routes to `vec_new_from_slice`, which allocates a `HostVec`, charges/copies `Val`s, checks object integrity, and adds the vector to the host object table.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1693-1706` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-224` — muxed event data creates immutable host maps through insert/rebuild logic; this path matters only when a muxed destination is present.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1284-1291` and `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — the generic `contract_event` API records `VecObject` topics and `Val` data and also creates a host `BytesObject` for the current contract id.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-39,173-248` — event rollback/status is payload-agnostic, but externalization converts stored `VecObject`/`Val` into XDR and then pushes a `HostEvent`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:197-205,254-273,407-419,463-539` — vector externalization still must visit address/string objects and clone them into `ScVal`; a typed event path moves this work earlier rather than eliminating it.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:485-508,875-889` — `try_finish()` externalizes events before ledger-change extraction and `encode_contract_events` still XDR-serializes every successful contract event for the C++ bridge.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-198` — `read_name` still performs an instance-storage metadata read/convert for every name-bearing event; direct event storage does not remove this unless a separate metadata-name cache/read specialization is added and validated.
- `ai-summary/fail/soroban-env/001-small-scval-val-conversion-fast-path.md:199-225` and `ai-summary/fail/soroban-env/002-specialize-val-key-metered-map-lookups.md:75-83` — related conversion/map optimizations show that broad Tracy zones overstate removable work and that source-level unmetered fast paths did not clear the objective threshold.

### Why It Failed

The source-level inefficiency is real, but the Medium-impact claim is not viable for this objective. Current event emission does allocate intermediate host objects, but the final observable event still requires XDR `ScVal` topics/data, address/name metered clones, event-buffer pushes, failed-call filtering, and `metered_write_xdr` bridge encoding. A budget-preserving implementation would still execute the relevant `MemAlloc`, `MemCpy`, `VisitObject`, `ValSer`, and object-clone charges; it would mainly avoid host object table pushes, temporary handles, and some wrapper/conversion scaffolding. A non-budget-preserving implementation would lower protocol-visible instruction/memory accounting for SAC events and would require an explicit cost-model decision rather than being a drop-in performance optimization.

The cited profile evidence is also too broad for the required 3% floor. `add host object`, `visit host object`, `new vec`, and `Val to ScVal` include storage conversion, guest Wasm objects, auth, ledger-change extraction, metadata reads, balance paths, and non-event object work. The parts specifically attributable to SAC event intermediates are a subset of those zones, and direct event emission cannot remove much of the subset because final XDR construction still needs equivalent address/string clones and vector allocation. The previous immediate `Val`/`ScVal` fast-path PoC, which covered event externalization plus many more conversion call sites, regressed the authoritative non-Tracy soroswap benchmark by 2.67%, reinforcing that the remaining event-only conversion layer is not a supported Medium optimization.

The metadata component is a separate hypothesis. `read_name` still decodes metadata before the event helper has a typed name to emit; direct `ScVal` event storage does not by itself cache the SAC name, avoid the instance-storage lookup, or prove metadata immutability/invalidation. Without that separate design and instrumentation, the reviewed mechanism is below the objective severity threshold.

### Lesson Learned

For SAC event optimizations, distinguish intermediate host-object round-tripping from final required event materialization. A viable future hypothesis should first isolate event-specific counts and time after subtracting mandatory budget charges, final `ContractEvent` XDR allocation/serialization, address/name cloning, and `read_name`; broad object/conversion Tracy zones are not enough to project a Medium apply-time reduction.
