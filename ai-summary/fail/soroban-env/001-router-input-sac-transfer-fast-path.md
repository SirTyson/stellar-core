# H001: Exact Router-Input SAC Transfer Fast Path

**Date**: 2026-05-26
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing one generic SAC transfer frame from each exact router swap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the next-protocol Soroswap apply-load route, the router's input-token SAC
`transfer(source, pair, amount_in)` should produce the same source-account auth
match, SAC instance TTL extension, source balance debit, pair balance credit,
contract event under the token contract id, result value, and rollback behavior
as `StellarAssetContract::transfer`. Released p26 ledgers, non-router callers,
non-`transfer` symbols, non-source-account senders, non-pair recipients,
non-SAC tokens, malformed arguments, failed auth, missing/unauthorized balances,
and all non-exact route shapes should continue through the existing generic SAC
call path.

## Mechanism

The current path enters `Host::call_contract_fn`, retrieves and clones the SAC
instance, pushes a full `Frame::StellarAssetContract`, dispatches through
`StellarAssetContract.call`, and then runs the generic `transfer` helper even
when the caller is the vendored Soroswap router issuing the benchmark's fixed
source-account-to-pair input transfer. A next-protocol exact fast path in the
StellarAsset branch of `call_contract_fn` can recognize this call shape and run
a typed SAC transfer settlement helper that still pushes an auth-visible native
SAC frame but avoids the generic built-in dispatch, repeated address/object
conversion, and avoidable frame-local instance materialization. This differs
from the rejected generic SAC-transfer specialization: it is not a broad
account-to-pair/pair-to-account rewrite, but an exact router-input path keyed by
caller frame, token executable, source account, pair recipient, and the normal
auth invocation.

## Trigger

Run the current next-protocol soroswap apply-load benchmark
(`TX=2000,T=8`). Each successful router `swap_exact_tokens_for_tokens` calls the
input SAC token's `transfer` export before entering the already-native pair
`swap` path; matching invocations should take the typed input-transfer helper
instead of the generic `Frame::StellarAssetContract` path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-834` — `call_contract_fn` always materializes `args_vec`, retrieves the full instance, and dispatches all `ContractExecutable::StellarAsset` calls through the generic frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic `transfer` sequence for auth, TTL, balance debit/credit, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-428` — contract/account balance debit and credit helpers the typed settlement path must preserve.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — auth frame stack push/pop behavior that the native SAC frame must keep observable.

## Evidence

The current Tracy trace is apply-path contained for this cost: unwrap-mode
containment shows `SAC transfer` at
`soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212`
has 16,069 events and 2,644,782,958 ns inside `applyLedger` (99.8% of its
events), while generated VM host `call` at
`soroban-env-host/src/vm/dispatch.rs:304` has 24,174 events and
4,937,728,356 ns inside `applyLedger` (99.7%). The exact router input transfer
is a stable subset of these calls and remains on the measured closeLedger path;
it is not TX-set construction. Because accepted native pair-swap work already
specializes the downstream pair frame, removing the remaining generic SAC frame
for the input leg attacks a different hot boundary than the prior pool getter,
pair swap, direct balance read, and storage-map successes.

## Anti-Evidence

This only clears Medium if the helper removes more than thin dispatch
scaffolding. A correct path must preserve SAC auth-frame advancement, TTL
extension, balance storage semantics, event contract id/order, and rollback, so
one-probe storage shortcuts or wrapper-only changes will fall into the
previously rejected sub-Low SAC micro-optimization class. The implementation
must also be next-protocol gated because any intentional change in metering or
budget-exceeded transition point is protocol-visible.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The apply-load generator constructs an exact router `swap_exact_tokens_for_tokens` invocation and a source-account auth tree whose sub-invocation is `token_in.transfer(source, pair, amount_in)`. At runtime the router Wasm still calls the generic host `call`, which reaches `call_n_internal`, then `call_contract_fn`; for SAC contracts that path loads the full instance, copies the argument slice into a frame, pushes `Frame::StellarAssetContract`, and runs the generated `StellarAssetContract` dispatch before entering `transfer`. The proposed shortcut can remove some SAC dispatch/type-branch scaffolding, but it cannot remove the router VM host-call wrapper, the auth-visible frame, rollback point, source auth match, SAC TTL extension, trustline debit, contract-balance credit, or transfer event. The claimed Medium impact is therefore bounded by a small fraction of a subset of the SAC transfer cost.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3427-3496` — confirms the benchmark shape: one router invocation per swap, exact args, footprint entries for SAC instances and pair balances, and one source-account auth sub-invocation for `token_in.transfer(source, pair, 100)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-834` — `call_contract_fn` retrieves the contract instance, charges/copies `args` into `args_vec`, and routes all `ContractExecutable::StellarAsset` calls through `Frame::StellarAssetContract` plus `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-630` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — any auth-visible fast path still pays frame push/pop, rollback snapshot, auth stack push/pop, instance-storage persistence checks, and rollback behavior.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` must keep nonnegative amount validation, muxed-address handling, `from.require_auth()`, SAC instance TTL extension, balance debit/credit, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-428` — input transfer specifically takes the account/trustline spend branch and contract-balance receive branch; these storage reads/writes and authorization checks are the core state transition and are not removable.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-112` and `metadata.rs:192-198` — the transfer event still requires issuer classification/name metadata and final `contract_event` materialization under the SAC contract id unless a much broader event-specific redesign is attempted.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2344-2359` and `host/data_helper.rs:287-321` — SAC TTL extension currently performs a no-op code-TTL executable check, but the same SAC TTL shortcut class was already quantified as sub-Low in `fail/soroban-env/007-fuse-storage-borrow-across-instance-and-code-ttl.md`.

### Why It Failed

The optimization target is real but below this objective's Medium severity floor. The hypothesis's own Tracy upper bound for **all** SAC `transfer` bodies is 2.645 s across 16,069 events; the router input leg is only about half of those transfers. Even the impossible case of deleting the whole input-transfer body would be roughly `1.32 s / 8 workers / 71 ledgers ~= 2.3 ms/ledger`, about 1% of the ~207 ms soroswap baseline and below the 3% Medium threshold. A correct fast path would preserve most of that body, so the actual removable portion is much smaller.

The generated VM host `call` zone should not be counted as removable for this hypothesis: the router remains a Wasm frame and must still issue the host `call`; only a full native-router path can eliminate that wrapper. Related prior investigations also bound the likely residuals: SAC TTL no-op removal is sub-Low, address-object caching in SAC transfer/balance/event paths is sub-Medium, and direct SAC event emission was rejected as below Medium. This proposal combines the same small residual classes on only the input-transfer subset, so it cannot clear the objective threshold.

### Lesson Learned

For exact SAC-transfer shortcuts in the current soroswap baseline, first normalize the whole relevant Tracy zone by subset size, `NUM_CLUSTERS`, and ledger count. If deleting the entire subset is already below 3%, then preserving auth, storage, event, frame, and rollback semantics leaves only dispatch/conversion residue and should be rejected before PoC. A viable future SAC-transfer hypothesis would need to remove a coarser phase, such as as part of a confirmed full native-router redesign, not just specialize the SAC branch inside `call_contract_fn`.
