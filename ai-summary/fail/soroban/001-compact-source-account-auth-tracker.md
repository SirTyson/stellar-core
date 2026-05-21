# H001: Compact Source-Account Auth Tracker for Soroswap Apply

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce apply-time host setup and auth matching for source-account-authorized soroswap swaps
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a source-account-authorized Soroswap swap, enforcing auth should verify that the actual call stack matches the submitted `SorobanAuthorizedInvocation` tree and should mark each matched node exhausted exactly once. The host should not need to eagerly convert every auth-tree `ScVal` argument into `Val`/host objects or allocate full generic `AccountAuthorizationTracker` state when the credential is `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` and authentication has already been established by transaction signature processing.

## Mechanism

`Host::build_auth_entries_from_xdr` decodes auth XDR, and `AuthorizationManager::new_enforcing` immediately converts every source-account auth tree into generic `AccountAuthorizationTracker` / `AuthorizedInvocation` objects. For the soroswap benchmark, `ApplyLoad::generateSoroswapSwaps` creates exactly one source-account auth entry per transaction: a router `swap_exact_tokens_for_tokens` root with one nested input-token SAC `transfer` invocation. A compact source-account tracker could store the submitted `SorobanAuthorizedInvocation` XDR plus a small exhausted-node bitset, then compare only the current call's contract/function/args against the corresponding XDR node at `require_auth`, avoiding eager `ScVal -> Val` conversion, host-object allocation, and generic tracker snapshot work for the common source-account path while preserving deterministic matching semantics.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the current soroswap scenario (`TX=2000, T=8`). Every generated swap has source-account credentials and the same two-node auth-tree shape, so successful SAC input transfers call `require_auth` against a generic tracker that was built from XDR at invocation start.

## Target Code

- `src/simulation/ApplyLoad.cpp:3477-3496` - constructs the soroswap source-account auth tree: root router swap plus nested input-token SAC transfer.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1055-1065` - eagerly decodes every auth entry before host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:772-790` - builds generic enforcing account trackers from decoded auth entries.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:594-654` - recursively converts XDR auth functions into host `AddressObject`, `Symbol`, and `Vec<Val>` state.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` - `require_auth` constructs the actual current `AuthorizedFunction` and matches it against tracker state.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` - snapshots the generic tracker tree at every frame push.

## Evidence

The current soroswap trace from `ai-summary/CURRENT_STATE.md` keeps the relevant zones inside `applyLedger`: `snapshot auth` is 176,060,644 ns self-time across 54,270 calls, `push auth frame` is 117,838,779 ns self-time across 54,270 calls, and `ScVal to Val` is 429,988,065 ns self-time across 691,521 conversions. Prior auth snapshot and conversion-coalescing hypotheses rejected narrow local cleanups after cluster normalization, but this candidate removes a broader source-account-only representation cost: eager auth-tree conversion plus generic mutable snapshot state for a credential class whose authentication is already handled outside the host.

The trigger shape is stable and synthetic: `ApplyLoad::generateSoroswapSwaps` always uses `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`, a two-address path, fixed amount/deadline, and one nested transfer authorization. A compact tracker can be protocol-gated and limited to source-account credentials, falling back to the existing generic tracker for address credentials, custom accounts, invoker-contract auth, recording mode, diagnostics, and any non-compact tree shape.

## Anti-Evidence

The previous `002-lazy-authorization-frame-snapshots.md` and `005-scval-val-conversion-coalescing-below-threshold.md` records show that isolated auth snapshots or conversion caching are below threshold after 8-way worker normalization. This hypothesis only clears Medium if the compact representation removes enough combined eager conversion, host-object allocation, auth snapshot, and matching overhead without adding expensive XDR comparisons at `require_auth`. It must preserve all auth-tree exhaustion, recoverable-error, diagnostic, and recording-mode behavior; otherwise it should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - exact compact source-account tracker was not previously investigated; it overlaps prior auth snapshot and ScVal/Val conversion bounds
**Failed At**: reviewer

### Trace Summary

The workload shape is real: `ApplyLoad::generateSoroswapSwaps` emits one `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` entry whose root is the router `swap_exact_tokens_for_tokens` invocation and whose only child is the input-token SAC `transfer`. C++ parallel apply serializes that auth entry into the Rust bridge, `e2e_invoke` decodes it, `Host::set_authorization_entries` builds a generic `AuthorizationManager`, and `AccountAuthorizationTracker::from_authorization_entry` converts the whole auth tree into `AuthorizedInvocation`/`Val` state before execution. During successful swaps both the router/root auth and nested SAC transfer auth are expected to execute, so a compact XDR representation cannot avoid matching the same two authorized nodes; it can only replace eager conversion/snapshot mechanics with lazy structural comparison and a smaller mutable state representation.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3496` - confirms fixed two-token soroswap transactions, root router call args, one nested SAC `transfer` authorization, and source-account credentials.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1378` - Soroban parallel apply serializes auth entries and passes them through `rust_bridge::invoke_host_function` inside `doParallelApply`.
- `src/rust/src/soroban_proto_any.rs:391-448` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:440-463,1055-1065` - Rust bridge builds the host, decodes auth entries with `metered_from_xdr`, decodes the host function and source account, then installs the authorization manager before invoking the host function.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:526-532` - `Host::set_authorization_entries` always constructs a generic enforcing `AuthorizationManager`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:594-654,772-790,1801-1840` - enforcing setup allocates `AccountAuthorizationTracker`s; source-account credentials skip nonce/signature payloads but still convert the root invocation and sub-invocations into host `AddressObject`, `Symbol`, and `Vec<Val>` state.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:216-221,435-555,579-628` - `scvals_to_val_vec` recursively converts auth-tree `ScVal` args; object-like I128, U64, Vec, and Address values allocate host objects.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:186-204,748-785,1124-1148` - every contract/SAC frame pushes auth state; top-level invoke converts router args to `Val`, and calls enter either Wasm contract frames or native SAC frames.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:823-850,937-1004,1167-1220,1306-1370,1663-1732,1782-1798,1891-1945,2076-2080` - `require_auth` builds the current `AuthorizedFunction`, scans account trackers, matches against the invocation tree, snapshots mutable exhaustion state at frame push, and source-account authentication is already a no-op.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - SAC `transfer` calls `from.require_auth()`, exercising the nested source-account auth node on the benchmark path.
- `ai-summary/fail/soroban/summary.md:84,87-88` - prior records bound lazy auth snapshots, auth prehashing, and broad ScVal/Val conversion cleanup below the objective threshold after parallelism normalization.

### Why It Failed

The optimization target exists, but the Medium impact claim does not survive the trace. Source-account auth already skips the expensive parts of account authentication: `authenticate` and nonce verification return immediately for `is_transaction_source_account`, so the remaining removable work is representation overhead. The cited `snapshot auth` total was already rejected as Low/sub-1% after dividing aggregate worker CPU by the 8 soroswap clusters, and `require auth`/auth-payload work is even smaller. The broad `ScVal to Val` total is not an auth-tree-only cost; top-level invoke argument conversion, storage reads, event/meta/value conversion, and other host paths also contribute. For the auth tree itself, successful soroswap consumes the root and nested transfer nodes, so a compact tracker still has to compare both nodes' contract IDs, function names, and arguments at `require_auth` time. Avoiding the initial host-object representation would either shift work into lazy XDR-vs-`Val` comparison or require new structural comparison machinery, while preserving metering and error behavior.

Even an optimistic "delete all auth snapshot plus all broad conversion cleanup" model is built from slices already recorded below the objective's 3% Medium floor. The actual source-account-specific removable subset is smaller than those broad slices, and the proposed compact tracker would add complexity around rollback snapshots, exhaustion semantics, active tracker matching, recoverable-error boundaries, and p26/next-protocol metering. This is therefore a real but below-threshold cleanup for the optimize-soroswap objective, not a viable Medium finding.

### Lesson Learned

For source-account auth ideas, separate generic auth/account-contract costs from source-account-only representation costs. Source-account credentials already bypass signature and nonce work; proposals must isolate measured auth-tree conversion/snapshot time for this exact credential class and show a post-parallelism >=3% apply-time win before promotion.
