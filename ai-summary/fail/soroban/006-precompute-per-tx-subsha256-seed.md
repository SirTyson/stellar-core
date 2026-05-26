# H006: Precompute Per-Tx `txSubSeed = subSha256(sorobanBasePrngSeed, txNum)` Once on Apply Thread

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low
**Impact**: Apply-time reduction via amortized SHA256 derivation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each Soroban transaction's per-tx PRNG seed is derived as
`txSubSeed = subSha256(sorobanBasePrngSeed, txBundle.getTxNum())` inside
the cluster worker loop (`LedgerManagerImpl::applyThread` line 2500). The
correct optimization, if viable, would be to compute every
`(txNum, txSubSeed)` pair once on the apply thread (or once per cluster
during cluster construction) and attach the precomputed seed to the
`TxBundle`. Worker threads would then read the cached seed rather than
recomputing the SHA256 each iteration. This preserves determinism —
`subSha256` is a pure function of its two arguments — and moves a small
amount of CPU work from the parallel-critical-path workers into the
serial setup phase (or eliminates it entirely if precomputed in parallel
during cluster build).

## Mechanism

`applyThread` is invoked once per (stage, cluster) pair and iterates
over its assigned `TxBundle`s. For each bundle it computes
`subSha256(sorobanBasePrngSeed, txBundle.getTxNum())`, a SHA256 hash of
the 32-byte base seed concatenated with an 8-byte big-endian txNum.
With SHA256-NI on the bench host this is well under 1 µs per call. The
soroswap trace shows 8 039 `parallelApply` calls (one per Soroban tx)
across 71 ledgers, so the aggregate cost is roughly
8 039 × 1 µs ≈ 8 ms of *worker-thread CPU* across the trace.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark and
inspect Tracy zones inside `applyThread` for any zone matching
`subSha256` or its callees (`SHA256::add` / `SHA256::finish`).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:applyThread:2500` — per-tx
  `subSha256` call inside the cluster worker loop
- `src/crypto/SHA.cpp:subSha256` — definition
- `src/ledger/TxBundle.h` — candidate carrier for precomputed seed

## Evidence

The `subSha256` call sits inside the per-tx worker loop where
self-time would naturally show up under `parallelApply` on the cluster
worker. The structural observation (worker-side derivation of a pure
function of static inputs) matches the "redundant work in hot per-entry
path" pattern from the objective skill.

## Anti-Evidence

The per-call cost of SHA256 on a 40-byte input is ~0.5–1 µs on modern
x86 with SHA-NI. Across 8 039 worker invocations divided over 8 cluster
workers, the per-worker wall-clock cost is ~1 ms total over 71 ledgers
= ~14 µs/ledger ≈ 0.007 % of the 207 ms baseline. Even full elimination
is three orders of magnitude below the Medium threshold (3 %). The
zone does not appear in `/tmp/soroswap_self.csv` self-time top entries,
confirming it is below the Tracy zone-emission noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis
stage). The per-tx `subSha256` derivation costs ~1 µs on SHA-NI
hardware; across 8 039 Soroban txs in the trace this aggregates to
~8 ms of worker-thread CPU, or ~1 ms wall-clock per worker over the
whole trace — well below 0.01 % of apply time per ledger. Eliminating
it entirely would not register against benchmark noise.

### Lesson Learned

Cryptographic-hash micro-optimizations on the soroban parallel-apply
worker path are bounded by Meta-Pattern #5 (SHA256/TTL key budget) and
its corollary: any per-tx pure-function recomputation whose inputs
are fixed at cluster-build time has at most a few microseconds of
saving per call, which only becomes meaningful at >100 k call volume
per ledger. The soroswap workload at ~28 Soroban txs/ledger cannot
reach that scale.
