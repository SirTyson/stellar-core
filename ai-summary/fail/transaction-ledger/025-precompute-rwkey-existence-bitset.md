# H025: Precompute mRwKeyExisted Bitset Outside Per-Tx addReads Loop

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / parallel apply per-tx Soroban setup
**Severity**: Low
**Impact**: Per-tx existence-check work in `addReads` for read-write footprint keys
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionOpFrame::HostInvocationCtx::addReads` at
`src/transactions/InvokeHostFunctionOpFrame.cpp:386` iterates the
read-write footprint and, for each existing entry, sets a bit in
`mRwKeyExisted` (a `BitSet` keyed by footprint index). The bit is
consumed later by `recordStorageChanges` (line 718–719) to decide whether
a host-returned modified entry is a *new* creation or an *update* of a
pre-existing entry. The expected efficient behavior is that, since the
read-write footprint of every cluster transaction is statically known
ahead of parallel apply, the existence pattern over the cluster-shared
state is computed once during cluster setup
(`ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`)
and threaded into each tx's `HostInvocationCtx` as a precomputed
`BitSet`, so per-tx `addReads` does not pay the existence-check work
again.

## Mechanism

`addReads` performs a `getLedgerEntryOpt(lk)` per RW footprint key
(`InvokeHostFunctionOpFrame.cpp:476`); when the entry exists it sets
`mRwKeyExisted.set(i)`. For a cluster of N sequentially-applied
soroswap txs sharing the same shared-state shape (router, pair, SAC
contract instances, balance entries), the existence answer for stable
footprint keys is identical on the first invocation but evolves per-tx
as upstream txs in the same cluster create or delete entries. A naive
"compute once at cluster setup" cache would shortcut every
`getLedgerEntryOpt` call inside `addReads`, eliminating the corresponding
`ThreadParallelApplyLedgerState` map probes per-tx.

## Trigger

Run the soroswap apply-load benchmark. Each soroswap swap tx has ~3-4
RW footprint keys (pair contract instance/data, two balance entries,
the user trustline). The `addReads` zone is reported at 196,665,860 ns
self-time across the entire trace (1.91% of trace), so the within-apply
fraction is bounded.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386,476-498` —
  `addReads` per-tx loop, including `getLedgerEntryOpt`,
  `mRwKeyExisted.set(i)`, and the `toCxxBuf(*entryOpt)` encoding.
- `src/transactions/ParallelApplyUtils.cpp:925-986` —
  `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`,
  which already walks every cluster footprint key and could side-record
  existence per (tx, footprint-index).

## Evidence

- `addReads` self-time is 196.7 ms aggregate across the trace; within-apply
  share is a fraction of that. After T=8 cluster division, the per-cluster
  critical-path budget for `addReads` is ~25 ms / 70 ledgers ≈ 0.36 ms/ledger.
- `mRwKeyExisted.set(i)` itself is sub-microsecond, so the optimization
  target is the *upstream* `getLedgerEntryOpt(lk)` call whose result
  decides existence. That call is also the call that produces the
  `entryOpt` used to build the `leBuf` `CxxBuf` passed to the host.

## Anti-Evidence

- The existence answer changes within a cluster: tx N may have created an
  entry that tx N+1 reads as existing, or tx N may have erased an entry
  the cluster's setup phase saw as existing. A static cluster-setup
  precomputation is therefore semantically wrong unless it is invalidated
  on every upstream commit, which is exactly the same per-tx work as
  the existing `getLedgerEntryOpt` call.
- The `getLedgerEntryOpt` call also produces the entry bytes (`leBuf`)
  that must be marshalled to the host. Caching only the existence bit
  does not eliminate the load itself; eliminating the load entirely
  requires the broader pre-encode pre-load design that has already been
  rejected at hypothesis or final-review (fail/ledger/010-cache-encoded-bytes-on-globalparapply-entry.md,
  fail/transaction-ledger/001-cache-serialized-soroban-entries-in-memory-state.md).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — `mRwKeyExisted` precomputation has not been
proposed in any prior fail/hypothesis/reviewed/poc record.

### Why It Failed

The proposal conflates two distinct quantities. The first is the
*existence-bit* set into `mRwKeyExisted`, which is a function only of
"does the cluster-thread state currently hold a non-deleted value at
this key when this tx is about to apply?". That answer mutates within
a cluster as upstream txs write or delete the same RW key, so it cannot
be precomputed at cluster setup without rebuilding it per-tx — at which
point the precomputation is identical to the per-tx work being removed.

The second quantity is the *entry bytes* (`leBuf`). Eliminating the
per-tx `getLedgerEntryOpt(lk)` call requires both that the existence
question be cached *and* that the encoded payload be available at
cluster setup with a zero-copy bridge to the host. The encoded-payload
pre-load pattern has been investigated and rejected from multiple angles
(`fail/ledger/010-cache-encoded-bytes-on-globalparapply-entry.md`,
`fail/transaction-ledger/001-cache-serialized-soroban-entries-in-memory-state.md`,
`fail/transactions/006-preserialize-inmem-soroban-entries-for-addreads.md`)
because the bridge `CxxBuf` copy preserves heap allocation cost, and the
in-memory cache pressure can offset the C++ savings.

After T=8 cluster normalization, the entire `addReads` critical-path
budget for soroswap is well below 1 ms/ledger, putting any
existence-bit-only optimization deep below the 3% Medium floor and even
below the 1% Low noise floor. Per the objective, Low is not accepted at
the hypothesis stage.

### Lesson Learned

`mRwKeyExisted` is set as a *side effect* of the per-tx
`getLedgerEntryOpt` call that also produces the entry bytes for the
host bridge. The bit alone is too cheap to hoist, and removing the
underlying load requires a zero-copy encoded-bytes pipeline that has
been independently rejected. Future RW-footprint optimizations must
target the encoded-bytes pipeline directly, with a zero-copy bridge
design, rather than the cheap existence-bit accounting that rides on
top of it.
