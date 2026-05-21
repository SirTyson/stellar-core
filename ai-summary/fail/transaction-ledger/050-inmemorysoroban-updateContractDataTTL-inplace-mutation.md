# H050: Replace erase-then-reinsert in InMemorySorobanState::updateContractDataTTL with in-place mutation via mutable hash-key wrapper

**Date**: 2026-05-21
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: post-apply async hot-archive / in-memory-state update phase
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Updating a `ContractData` entry's TTL should mutate the
`TTLData` field in place (or via a const-cast to the stored
`ContractDataMapEntryT`) without rehashing or erase/reinsert into
`mContractDataEntries`. The unordered_set's hash key is the TTL key hash
(precomputed and stable across TTL updates), so a TTL-only mutation cannot
change the entry's hash or equality-key and therefore should not perturb the
table.

## Mechanism

`InMemorySorobanState::updateContractDataTTL`
(`src/ledger/InMemorySorobanState.cpp:54-65`) finds the entry by TTL key
hash, then erases and re-inserts a copy with the new `TTLData`. Because the
unordered_set stores `InternalContractDataMapEntry` by value (with a
`unique_ptr<AbstractEntry>` indirection), every TTL bump pays an unnecessary
node-link unlink/relink plus a control-block-bearing
`make_unique<ValueEntry>` allocation. Since the hash key is invariant under
TTL change, an in-place update would skip the entire table mutation.

## Trigger

Any Soroban-heavy workload where TTL bumps fire on previously known
`ContractData` entries — soroswap commits a TTL bump on each token-balance
read and on each instance access. The path runs inside the
`updateInMemorySorobanState` future scheduled from
`LedgerManagerImpl::finalizeLedgerTxnChanges`.

## Target Code

- `src/ledger/InMemorySorobanState.cpp:54-65` — `updateContractDataTTL`
- `src/ledger/InMemorySorobanState.h:107-280` — `InternalContractDataMapEntry` (would need a TTL-only mutator)
- `src/ledger/LedgerManagerImpl.cpp:3340-3360` — `updateInMemorySorobanState` async-future invocation site

## Evidence

- Code inspection confirms erase + emplace pattern on a `std::unordered_set`
  whose hash function depends only on the TTL key hash (a SHA-256 of the
  CONTRACT_DATA key), which is invariant under TTL update.
- Each soroswap tx typically bumps several persistent `ContractData` TTLs
  (token balances, contract instance), so the call rate per ledger is
  thousands.

## Anti-Evidence

- Tracy: the entire `updateInMemorySorobanState` async future takes
  ~36 µs/ledger total (well under 1 ms even when aggregated across the
  full trace). This work is dominated by the *async* phase scheduled off
  the apply thread, not the synchronous critical path.
- The future is joined inside `finalizeLedgerTxnChanges` but completes long
  before the join; in practice it does not block apply.
- Out-of-scope guard from the objective context: "**Bucket merge work that
  runs lazily on background threads.** ... Only *blocking* bucket work
  counts." The same principle applies to other post-apply async work —
  speeding it up does not shorten the apply critical path unless apply
  actually blocks on it.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Distinct from fail/035
(updateContractDataTTL TTL-key-hash cache) and fail/005 (TTL-key memoization
for shared RO entries); both of those target the *lookup*-side SHA cost,
while this targets the table-mutation side.

### Why It Failed

Below objective severity floor. The total wall-clock cost of
`updateInMemorySorobanState` is ~36 µs per ledger (Tracy measurement on the
current accepted trace), and it runs as a `std::async` future scheduled in
parallel with `addLiveBatch` and `addHotArchiveBatch`. Even a 100%
elimination of the erase/reinsert cost cannot move soroswap apply time —
the savings (~tens of µs per ledger, hidden behind the async future) are
three orders of magnitude below the 8.2 ms/ledger Medium threshold.

### Lesson Learned

When triaging an algorithmic inefficiency in an apply-adjacent code path,
verify whether the path runs on the synchronous apply thread or behind a
`std::async` future joined later. Inefficiencies on async sub-millisecond
futures do not move the apply critical path even when the underlying code
pattern is genuinely suboptimal; the OUT_OF_SCOPE "bucket-merge background
work" rule generalizes to any async/joined-later work whose wall-clock cost
fits inside the parallel slack window.
