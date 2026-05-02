# H020: Replace per-ledger `xdrSha256(LedgerHeader)` with incremental hashing

**Date**: 2026-05-02
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time SHA256 reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Computing the hash of the previous and final `LedgerHeader` once per
`applyLedger` invocation should be a near-constant cost — the struct is small
(<200 bytes serialized) and SHA256 throughput is hundreds of MB/s. The
aggregate per-ledger header hashing share of apply time should be sub-µs.

## Mechanism

`LedgerManagerImpl::applyLedger` calls `xdrSha256(prevHeader)` once near the
start (line 1506) and `xdrSha256(header)` once near the end (line 2208) when
constructing the `CompleteConstLedgerState`. Each invocation pays the
`XDRSHA256` setup, archives the header through `xdr::archive`, finalises the
SHA256 state, and tears down the streaming buffer. A hypothesis would propose
either (a) computing both hashes off the apply critical path or (b) replacing
the streaming archive with a one-shot serialise-then-`crypto_hash_sha256` over
a small stack buffer.

## Trigger

Run the soroswap apply-load benchmark with Tracy and aggregate the
`xdrSha256`/`SHA256::add`/`SHA256::finish` self-time attributable to the two
LedgerHeader hashing call sites.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:1506` — `auto prevHash = xdrSha256(prevHeader);`
- `src/ledger/LedgerManagerImpl.cpp:2208` — `lcl.hash = xdrSha256(header);`
- `src/ledger/LedgerHeaderUtils.cpp:148` — `auto ledgerHash = xdrSha256(lh);`
  (storeInDatabase; outside hot apply but called per ledger)
- `src/crypto/SHA.h:39-65` — `XDRSHA256` and `xdrSha256` template helpers.
- `src/crypto/XDRHasher.h` — buffered streaming archive used by `xdrSha256`.

## Evidence

Two unconditional SHA256-of-LedgerHeader calls live inside `applyLedger` at
lines 1506 and 2208. Each pays streaming-archive overhead documented in
H018 (XDRHasher buffered archive) and H012 (SHA256 streaming class) as
having Tracy-inflated per-call self-times.

## Anti-Evidence

`LedgerHeader` XDR encodes to roughly 150-200 bytes for soroswap, so each
`xdrSha256` call hashes a single SHA256 block (one `crypto_hash_sha256_update`
call after the streaming archive flushes its 256 B buffer). With two such
calls per `applyLedger` and 65 ledgers per soroswap run, the absolute cost
is bounded by:

- 130 SHA256 finalisations × ~1 µs each ≈ 130 µs total wall time.
- That is ~0.0007 % of the 18 s soroswap run and ~0.001 % of the 5.09 s
  `applyLedger` envelope.

Even if XDRHasher streaming overhead doubles this estimate (Meta-Pattern 7
documents ZoneScoped inflation of crypto-primitive zones), the upper bound
remains under 1 ms across the entire run — three orders of magnitude below
the 1 % Low floor and four orders of magnitude below the 3 % Medium minimum
this objective requires.

The same call site pattern is captured by Meta-Pattern 1 ("SHA256 budget
ceiling ~0.67 % per soroswap apply") and Meta-Pattern 7 ("Tracy ZoneScoped
overhead inflates crypto primitive costs"). H015 already established that
per-ledger bulk-XDR SHA256 work (`txResultSet`) is ~1 ms / ledger and below
the 1 % Low floor; the LedgerHeader hashes are an even smaller subset of
the same budget.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H012 (SHA256 streaming class for
`getTTLKey`/`subSha256`), H015 (`txResultSet` bulk hash), and H018
(`XDRHasher` short-object redesign); this entry targets the two
`xdrSha256(LedgerHeader)` call sites at the boundaries of `applyLedger`.

### Why It Failed

The two header-hash calls per `applyLedger` are paid on a ~200-byte struct
and total at most a few hundred microseconds across the entire 65-ledger
soroswap run. Even fully eliminating both calls (which is impossible —
`previousLedgerHash` and `lcl.hash` are required for ledger continuity)
would be undetectable below benchmark noise. The objective explicitly
rejects sub-1 % findings.

### Lesson Learned

`LedgerHeader` hashing is structurally bounded by O(constant per ledger)
calls on a fixed-size payload. Per Meta-Pattern 1 the entire in-apply
SHA256 budget is already capped near 0.67 % of soroswap apply, and any
fixed-cost-per-ledger SHA256 work — header hashes, `txSetResultHash`,
contract-id `xdrSha256(preimage)` — falls inside that ceiling at amounts
measured in single-digit milliseconds for the whole run. Future
SHA256-primitive hypotheses on the apply path should be sized against the
non-Tracy 0.67 % ceiling and rejected up-front unless they target a
per-tx or per-entry call site that compounds large numbers of bytes.
