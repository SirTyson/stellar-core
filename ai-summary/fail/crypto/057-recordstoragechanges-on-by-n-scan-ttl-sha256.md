# H057: O(M*N) recordStorageChanges Scan with Inline getTTLKey SHA256

**Date**: 2026-05-21
**Subsystem**: crypto / SHA256 / transactions apply
**Severity**: Low
**Impact**: recordStorageChanges per-op rwKey scan and inline TTL SHA256 (sub-Medium)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each modified ledger entry returned by the Soroban host,
`recordStorageChanges` should locate the corresponding RW footprint slot
(for "created vs upsert" classification and footprint coverage tracking) in
roughly amortized O(1) time, hashing each RW footprint key's TTL form at
most once per op. The classification result must be byte-for-byte identical
to the current implementation.

## Mechanism

`InvokeHostFunctionOpFrame::recordStorageChanges`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:640-741`) iterates
`out.modified_ledger_entries` and for **each** output entry runs a nested
linear scan over `rwKeys` looking for either a direct `rwKeys[j] == lk`
match or, when `lk.type() == TTL`, a TTL-derived match
`getTTLKey(rwKeys[j]) == lk`. `getTTLKey` (see `src/transactions/
TransactionUtils.cpp`) builds a `LedgerKey::Ttl` whose `keyHash` is a
SHA256 of the XDR-serialized rwKey. This means the inner loop calls
`getTTLKey(rwKeys[j])` repeatedly across output entries — once per TTL
output entry per rwKey scanned — and the direct equality test
`rwKeys[j] == lk` walks the full XDR structure on each comparison
(non-trivial for CONTRACT_DATA keys whose `key` field is an `ScVal` map or
vector). Replacing the loop with a precomputed `(ledgerKeyHash → rwKey
index, ttlKeyHash → rwKey index)` map built once per op would make
classification amortized O(M+N) and hash each rwKey TTL form at most once.

## Trigger

Run the current soroswap apply-load case (`soroswap, TX=2000, T=8`) from
`ai-summary/CURRENT_STATE.md`. Each successful swap invocation produces M
output entries against an N-entry RW footprint, triggering the nested scan
and inline TTL SHA256 work.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:recordStorageChanges:654-695` — nested rwKey scan with inline `getTTLKey` and XDR equality.
- `src/transactions/TransactionUtils.cpp:getTTLKey` — SHA256 of XDR-serialized LedgerKey to build `LedgerKey::Ttl`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:addReads:386-510` — populates `mResources.footprint.readWrite`; could opportunistically cache `getTTLKey(rwKeys[j])` for each Soroban rwKey at addReads time.

## Evidence

The inner loop has worst-case O(M*N) behavior per op, with both a SHA256
call (`getTTLKey`) and an XDR walk (`==`) inside the comparison body. For
soroswap-like workloads with M ≈ N ≈ 4–8 RW entries per op and 6,776 ops
across the trace, the inner-loop body executes on the order of 100K–500K
times. Each `getTTLKey` SHA256 hashes ~50–150 bytes of XDR-serialized
LedgerKey.

## Anti-Evidence

`recordStorageChanges` totals 98.487 ms across the entire soroswap trace
(6,776 calls, ~14.5µs/call). The total apply-contained recordStorageChanges
time is therefore bounded at ~98 ms ⇒ ~0.55% of the cumulative trace apply
budget across all ledgers. Even eliminating the entire rwKey scan
(impossible — some classification work is required) would not reach the
1% Low floor, let alone the 3% Medium floor. Furthermore Meta-Pattern 1
caps the entire in-apply SHA256 budget at ~0.67% (~4 ms/ledger), so the
inline `getTTLKey` SHA256 share of this loop is a small fraction of an
already-sub-Low ceiling. Meta-Pattern 6 also warns that XDR-equality /
hash-map redesigns produce only fractional wins when the underlying total
is small.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — prior H004 (`precompute-footprint-ttl-keys`) targeted cross-phase `getTTLKey` deduplication, not the specific O(M*N) inner-loop pattern inside `recordStorageChanges`; prior H019 (`getfullhash-apply-share`) targeted a different SHA256 callsite. The specific `recordStorageChanges` inner-loop interaction was not individually scoped.

### Why It Failed

The entire `recordStorageChanges` zone is ~98 ms across the whole soroswap
trace (~0.55% of cumulative apply budget when normalized). Removing the
entire inner-loop scan and inline TTL SHA256 would save a small fraction
of that already-sub-Low total. The SHA256 share is independently bounded
by Meta-Pattern 1 (~0.67% global in-apply ceiling). No realistic
restructuring of this loop can reach the 1% Low floor for this objective.

### Lesson Learned

`recordStorageChanges` is a small fixed-cost apply phase whose total budget
is below the Low floor. Future hypotheses targeting this function — whether
the rwKey scan, the inline TTL SHA256, the XDR-equality, or the upsert
loop — must cite an apply-contained measurement exceeding ~25 ms /
ledger before being viable, which would require the whole-trace zone
total to grow several-fold from its current ~98 ms baseline.
