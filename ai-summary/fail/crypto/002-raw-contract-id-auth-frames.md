# H002: Raw Contract-ID Auth Frames Avoid HostObject Address Churn

**Date**: 2026-05-22
**Subsystem**: crypto / Rust Soroban authorization
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing per-frame `ScAddress::Contract` host-object allocation and deep address comparison in source-account auth matching
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Authorization matching must still treat contract addresses exactly as canonical `ScAddress::Contract` values, match the same root and sub-invocation trees, and preserve the same direct-invoker authorization behavior. Any optimization must be a representation change only: observable auth entries, diagnostic errors, metering for protocol versions before the gated change, and final authorization results must remain unchanged.

## Mechanism

`AuthorizationManager::push_frame` converts every contract frame's raw contract id into a host object by calling `host.add_host_object(ScAddress::Contract(contract_id))`, then later compares `AddressObject` handles through `HostObject` comparison when `require_auth_enforcing` and invoker-contract checks match addresses. For source-account-heavy soroswap, these objects are mostly transient auth bookkeeping: the frame address is needed to identify the current contract in the auth stack, but it rarely needs to be stored as a `HostObject` until an actual `AuthorizedFunction` is materialized for comparison or diagnostics. A protocol-gated internal representation such as `AuthStackFrame::Contract { contract_id: Hash, function_name }`, plus direct `Hash` comparison for contract-vs-contract auth paths and lazy `AddressObject` materialization only when required, could remove hot host-object allocation and comparison work without changing canonical auth semantics.

## Trigger

Run the accepted soroswap Tracy case from `ai-summary/CURRENT_STATE.md`. Every contract frame in `applyLedger` enters `AuthorizationManager::push_frame`, builds a new `ScAddress::Contract` host object, and later `require_auth` paths compare contract and account addresses through the generic `HostObject` comparison machinery.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:AuthStackFrame/ContractInvocation:480-490` — auth stack stores `contract_address: AddressObject`, forcing host-object representation for every frame.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:AuthorizationManager::push_frame:1345-1361` — clones the frame contract id and immediately calls `host.add_host_object(ScAddress::Contract(contract_id))`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:AuthorizationManager::maybe_check_invoker_contract_auth:880-930` — compares current, invoker, and tracker addresses via generic host comparison.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:AuthStackFrame::to_authorized_function:572-591` — only materializes an `AuthorizedFunction` when `require_auth` actually needs the current frame.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:Compare<ContractFunction>:524-542` — compares contract address, function name, and args; the contract-address part could use raw ids before falling back to existing canonical comparisons.

## Evidence

The apply-contained soroswap trace reports `add host object` at **352.429 ms / 935,719 calls**, `Compare<HostObject>` at **224.865 ms / 413,544 calls**, `obj_cmp` at **313.497 ms / 393,355 calls** in the common VM caller path, and `push auth frame` at **402.098 ms / 54,270 calls**. Not all host-object allocation is auth-owned, but the source path shows one auth-owned `add_host_object(ScAddress::Contract(...))` per contract frame before the corresponding frame has proven it needs auth. This hypothesis targets a different mechanism from the failed auth-function-fingerprint record: instead of trying to accelerate full `AuthorizedFunction` comparisons after the host objects already exist, it prevents transient frame-address objects and many generic address comparisons from being created in the first place.

## Anti-Evidence

The headline `add host object` and `obj_cmp` zones are broad and include non-auth VM object traffic, so a PoC must isolate the auth-owned share before claiming Medium severity. Some address comparisons involve account addresses or custom-account paths and cannot use a raw contract-id shortcut. The representation must also be careful around direct invoker authorization and diagnostics, because those code paths may genuinely need an `AddressObject`; if most calls still materialize the object in `to_authorized_function`, the optimization collapses to a small allocation reshuffle below the severity threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

`Host::with_frame` pushes each contract/SAC frame through `push_context`, which eagerly calls `AuthorizationManager::push_frame`. `push_frame` does indeed clone the contract id and allocate one `ScAddress::Contract` host object into `ContractInvocation`, and later `require_auth` turns the current frame into an `AuthorizedFunction` whose contract address is compared through the generic `Val`/`Object`/`HostObject` comparison path. The local inefficiency is real, but the auth-owned allocation surface is a small slice of the broad `add host object` zone, and the relevant comparison surface is bounded by the already-reviewed source-account auth-tree shape. After normalizing worker-aggregate Tracy zones by the 8-way Soroban worker phase, the projected saving is below the objective's Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` calls `auth_manager.push_frame` before pushing every context and stores the rollback snapshot.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:480-490` — `AuthStackFrame::Contract` stores `ContractInvocation { contract_address: AddressObject, function_name }`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` — each contract/SAC frame clones the raw contract id and immediately calls `host.add_host_object(ScAddress::Contract(contract_id))`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-457` — `add_host_object` charges heap allocation and pushes a `HostObject` into the host object table.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` — `require_auth` reads the last auth stack frame and materializes an `AuthorizedFunction` for matching.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:524-542` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1681-1731` — function matching compares contract address, function name, and args when extending an invocation match.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145`, `src/rust/soroban/p26/soroban-env-host/src/host.rs:1223-1265`, and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — object comparisons route through `obj_cmp`, visit both host objects, and then compare `HostObject::Address` values.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:880-930` — direct-invoker and invoker-contract tracker checks compare frame/tracker addresses through generic host comparison.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:938-1004` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1803-1840` — source-account enforcing auth mostly compares the required source account address against account trackers, not the frame contract id.
- `ai-summary/fail/crypto/001-lazy-auth-frame-materialization.md:47-68` and `ai-summary/fail/crypto/summary.md:39-40` — prior auth investigations establish that the full eager auth-frame envelope normalizes to Low-tier impact and that soroswap auth trees have only one root plus one SAC-transfer child.

### Why It Failed

The proposed representation change cannot plausibly reach the optimize-soroswap Medium floor. The one-per-frame contract-address allocation is real, but it is only 54,270 calls out of the broad 935,719-call `add host object` zone and is included in the previously reviewed `push_context`/`push auth frame` auth envelope; even eliminating that entire envelope normalized by `T=8` was about Low-tier impact, and this change would remove only a subset. The comparison side is similarly over-attributed: source-account auth matching primarily compares account addresses, while the contract-frame address appears in direct-invoker checks and `AuthorizedFunction` matching; the prior auth-function review found the soroswap tree shape is one root plus one SAC-transfer child, so contract-address comparison shortcuts remove only a small fraction of the global `obj_cmp` / `Compare<HostObject>` totals. Under the objective-specific rules, a real but sub-3% optimization is NOT_VIABLE rather than accepted at lower severity.

### Lesson Learned

Auth-frame representation changes should be sized against auth-owned frame counts and parallel-worker-normalized auth zones, not against global host-object allocation/comparison totals. For soroswap source-account auth, contract-address churn exists but is structurally bounded by the same Low-tier auth-frame and one-child auth-tree ceilings already documented for nearby hypotheses.
