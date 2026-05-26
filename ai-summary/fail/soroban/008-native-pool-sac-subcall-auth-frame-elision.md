# H008: Skip Authorization Frame Push for Native-Pool-Originated SAC Subcalls

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low
**Impact**: per-SAC-subcall reduction of authorization manager bookkeeping when
caller is a trusted native pool contract
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a Soroban contract invokes another contract via `call` or `try_call`, the
host pushes a new authorization frame onto `AuthorizationManager` to track
which authorizations apply to the child call (matching against the auth tree
provided in the transaction's `SorobanAuthorizationEntry` list). For native
pool contracts (registered in the `NativePool` registry, see successes
`native-pool-raw-instance-storage` and related), the contract code is
trusted host code, not user-supplied Wasm; the pool's calls into the SAC
(token contract) are deterministic from the input arguments and known to the
host implementation.

Expected behavior of a *well-shaped* native pool invocation: when a native
pool synchronously calls SAC `transfer` / `balance` / `mint`, the host should
recognize that the caller's authorization frame is a pass-through (the user
already authorized the pool's entry point, and the pool's internal SAC
subcalls are an implementation detail of the pool's promised semantics).
The push/pop of an auth frame, the matching against the auth tree, and the
snapshot of authorization state into the rollback stack are unnecessary for
this restricted caller class.

## Mechanism

Tracy soroswap trace shows per-cluster auth bookkeeping:
- `snapshot auth` 166 ms (also covered by fail `002-lazy-authorization-frame-snapshots`)
- `push auth frame` 105 ms
- `push context` 101 ms

For every SAC subcall originating from the native pool router contracts
(swap and add/remove liquidity paths), `AuthorizationManager::push_frame`
records a new `AuthStackFrame` and snapshots the per-account
`AccountAuthorizationTracker` state for rollback. The actual matching work
for these native-originated subcalls is wasted because (a) the SAC subcalls
are deterministic given the input, (b) the user's transaction-level auth
already covers the pool's entry point, and (c) the pool's `require_auth`
calls (when present) execute against the same tracker the parent has.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the soroswap scenario. Every
soroswap swap transaction's native pool router makes 2 SAC subcalls
(transfer in, transfer out). At ~250 txs/cluster × 2 SAC subcalls/tx ×
71 clusters in the bench window, that's ~35.5k auth frame pushes per
worker per trace.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:push_frame,pop_frame,snapshot_tracker_state`
  — push/pop/snapshot paths invoked on every contract-to-contract call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:push_frame,pop_frame`
  — calls into `AuthorizationManager::push_frame`.
- Native pool dispatch site in stellar-core's native pool registry where
  SAC subcalls are issued (see success `native-pool-raw-instance-storage`).

## Evidence

- Tracy aggregate self-times for the three auth-related zones above sum to
  ~372 ms.
- Native pool router is the *exclusive* caller of the SAC contracts in the
  soroswap benchmark (the user's tx invokes the router, which invokes the
  SAC). The pool is host-trusted code, so the same control-flow assertion
  the host makes for native pool storage reads (success
  `native-pool-raw-instance-storage`) extends to the auth domain.
- The `snapshot auth` zone is the largest of the three, suggesting that
  snapshotting trackers for rollback dominates the push/pop work itself.

## Anti-Evidence

- After 8-way cluster normalization and 71-ledger division:
  `372 ms / 8 / 71 = 0.655 ms/ledger = 0.32 %` of the 207 ms soroswap
  baseline. This is the *upper bound* assuming full elimination of all three
  zones for native-pool-originated subcalls (which themselves are only a
  fraction of total auth work). Below the 1% Low noise floor.
- Fail `002-lazy-authorization-frame-snapshots.md` already established that
  the broader `snapshot auth` path's aggregate post-normalization impact is
  <1%. This hypothesis targets a strict subset (native-pool-originated
  subcalls only) of the same code path, so the upper bound is strictly
  smaller.
- Protocol semantics constraint: the `SorobanAuthorizationEntry` tree
  recorded in the transaction has a specific shape that the host walks
  during each `push_frame` to confirm `require_auth(addr)` calls match the
  pre-declared invocation tree. Skipping the push for native-pool-originated
  SAC subcalls means either (a) the SAC's internal `require_auth` calls
  cannot find their tracker (correctness failure), or (b) the auth tree
  must be rewritten by the host to elide the SAC subcall node, which is a
  protocol-visible change requiring careful design (replay equivalence
  across nodes that don't apply the optimization).
- The SAC `transfer` host function does its own `require_auth(from)` call
  (see `SAC transfer` zone 691 ms which dominates auth-related savings). If
  we skip the frame push for the pool → SAC subcall, the SAC's internal
  `require_auth(from)` must still resolve against the *user's* auth entries
  upward in the stack, requiring stack-walking changes that may cost more
  than they save.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a native-pool-scoped
auth-frame elision. Distinct from fail `002-lazy-authorization-frame-snapshots.md`
(generic lazy snapshot covering all callers) and from success
`001-native-pool-raw-instance-storage.md` (storage-only native pool bypass).

### Why It Failed

Upper-bound saving of 0.32% is sub-Low even before subtracting the cost of
the auth-tree-rewrite or stack-walking logic required to keep
`require_auth(from)` resolving correctly for the SAC's internal auth check.
A correctness-preserving implementation would have to maintain a virtual
"pass-through" frame anyway so that nested `require_auth` calls find the
user's tracker; the saving collapses to the differential between a full
push/snapshot and a lightweight pass-through marker, which is well within
benchmark noise.

Additionally, the `SAC transfer` zone (691 ms self-time) — which is the
*real* target for native-pool SAC subcall optimization — has been
extensively addressed by the successes already in the stack, and the
*remaining* auth bookkeeping is what is left after those wins. The
authorization frame push is one of the smallest residual pieces.

### Lesson Learned

For trusted-caller optimizations targeting auxiliary host bookkeeping
(auth, context, events): once the *primary* user (e.g., SAC transfer) has
been optimized, the residual bookkeeping zones rarely individually clear
even the Low threshold. The auth manager's per-frame work is bounded
collectively by the `push_frame` + `snapshot` + `match` triple, and after
the SAC's own optimizations only the matching cost remains meaningful.
Native-pool-scoped variants of broader auth optimizations inherit the
parent variant's normalization ceiling and cannot exceed it.
