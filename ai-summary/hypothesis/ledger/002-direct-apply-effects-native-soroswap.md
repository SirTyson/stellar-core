# H002: Direct Apply-Effects Builder for Native Soroswap Swaps

**Date**: 2026-05-26
**Subsystem**: ledger / Soroban host apply bridge
**Severity**: High
**Impact**: dominant-phase redesign of recognized soroswap `InvokeHostFunction` apply by bypassing generic Host/VM/storage-map construction for one protocol-gated swap shape
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a recognized next-protocol official soroswap router swap transaction, the apply bridge should produce exactly the same public result, contract events, rent/TTL changes, modified ledger entries, budget/resource accounting, and error behavior as the current host execution path. If the transaction is not exactly the supported soroswap shape, the existing Rust `Host` execution should run unchanged.

The optimized path should execute the known router/pool/SAC swap semantics directly over the transaction's encoded footprint entries and return an `InvokeHostFunctionResult`-equivalent structure. It should not instantiate the router Wasm VM, construct a generic enforcing `StorageMap`, push generic contract frames, or extract ledger changes by diffing a full host storage map when all required ledger effects can be computed directly from the fixed ABI and typed ledger entries.

## Mechanism

The current p26 apply bridge has already accumulated several protocol-gated native soroswap optimizations, but they fire after the expensive generic host setup has occurred. `invoke_host_function` still decodes generic resources, builds a `StorageMap`, clones an initial snapshot, constructs a `Host`, decodes auth and host function XDR, invokes router Wasm, then finishes the host and diffs storage into `LedgerEntryChange`s.

A direct apply-effects builder would move recognition earlier, before `Host::with_storage_and_budget`. For the exact official router swap ABI and footprint, it would decode only the needed typed entries (router/pool instances, token instances, SAC balances, TTLs), enforce the same auth and layout predicates, compute the pool swap and SAC balance transitions with checked arithmetic, build the same event XDR and result XDR, and return only the ledger effects consumed by stellar-core apply. This avoids the broad `Host::invoke_function`/`Vm::invoke_function_raw`/`call`/storage-map path for the headline workload while keeping a conservative fallback for every unrecognized case.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with next-protocol enabled. The trigger is a successful official soroswap router swap `InvokeHostFunction` whose footprint contains the expected router/pool/SAC entries and whose contract code hashes/layouts match the accepted native soroswap path. Any mismatch must return `None` from the recognizer and execute the current generic host path.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — current C++ bridge call that always invokes the generic Rust host function for each Soroban operation.
- `src/rust/src/soroban_proto_any.rs:391-488` — protocol dispatch wrapper that could route next-protocol p26 apply calls to a specialized direct-effects helper before falling back.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — generic storage-map construction, initial snapshot clone, positional metadata, and host construction that the recognized direct path would skip.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:528-579` — generic auth/host-function decoding, `Host::invoke_function`, host finish, ledger-change diffing, and event encoding.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — generic contract dispatch that currently recognizes native pool calls only after router Wasm crosses `call`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1528` — existing native pool swap and direct SAC balance logic to reuse as the semantic reference for typed direct effects.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:356-428` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC debit/credit/auth/event behavior that the direct helper must preserve.

## Evidence

The latest baseline trace is `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release` shows that the generic host execution subtree remains the dominant in-apply cost: `Host::invoke_function` totals 8,262,600,385 ns, `Vm::invoke_function_raw` totals 7,250,910,294 ns, generated `call` totals 4,950,309,676 ns, `SAC transfer` totals 2,651,398,200 ns, `storage get` totals 720,764,042 ns, and `new map` totals 459,483,809 ns. Intersecting unwrapped events with `applyLedger` windows confirms these are not TX-set-construction artifacts: `call` has 24,078 in-window events totaling 4,937,728,356 ns, `SAC transfer` has 16,005 totaling 2,644,782,958 ns, `storage get` has 328,819 totaling 718,936,767 ns, and `new map` has 168,905 totaling 458,268,680 ns.

The source also shows a clean recognition boundary: `InvokeHostFunctionOpFrame` already passes the encoded host function, resources, auth, source account, ledger entries, TTL entries, rent config, and module cache to Rust in one place, and p26 already has protocol-gated native pool swap semantics in `host/frame.rs`. Moving a narrower recognizer before generic host construction targets the whole remaining Host/VM/storage-map envelope, not the sub-Medium leaf costs rejected in prior ledger failures.

## Anti-Evidence

This is effectively a specialized interpreter for one benchmark-critical contract path, so correctness risk is high. It must reproduce router-visible auth roots, event XDR, result hashing, budget/resource accounting, TTL extension, rent-size accounting, rollback/failure behavior, and every fallback case exactly or be protocol-gated with updated budget expectations. Prior native-router work failed at PoC complexity; this hypothesis is only viable if scoped to an apply-only direct-effects builder with exhaustive shape checks and conservative fallback, not if it attempts to skip semantics by assuming the benchmark always succeeds.
