# H029: Skip Per-Event XDR Decode in collectEvents for Disabled-Meta Soroswap

**Date**: 2026-05-24
**Subsystem**: transactions (parallel worker contract-event materialization)
**Severity**: Low
**Impact**: soroswap worker-path ContractEvent decode elimination
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionOpFrame::collectEvents` iterates the host's
`out.contract_events`, decodes every `CxxBuf` into a `ContractEvent` via
`xdr_from_opaque`, and pushes it into `success.events`. The
`finalizeSuccess` path already uses a streaming SHA256 over the raw
`buf.data` slices for the consensus-visible result-hash (introduced to
"avoid round-trip serialization"), so the decoded `ContractEvent` objects
are only needed for the user-facing meta path (via `setEvents` →
`OpEventManager::setEvents`).

When meta is enabled in production, the decoded events are required to
materialize the `LedgerCloseMeta` event vector. When meta is effectively
disabled or only the event preimage is consumed (e.g., `dontUseMeta` /
`!mEnabled` cases), the decode is dead work: the streaming SHA already
covers consensus, and downstream consumers can be fed the raw XDR bytes.

Expected: in disabled-meta configurations the worker should skip the
per-event `xdr_from_opaque` decode and the `success.events.emplace_back`
deep copy entirely, leaving only the budget/size accounting that
`collectEvents` already performs.

## Mechanism

`src/transactions/InvokeHostFunctionOpFrame.cpp:769-816` decodes every
contract event with `xdr_from_opaque(buf.data, evt)` and copies the
decoded `ContractEvent` into `success.events`. For soroswap each tx
emits 2–3 events (router transfer + SAC transfer effects + fee event),
each with sub-1KB encoded XDR. The decoded `ContractEvent` carries nested
`SCVal` topics/data that re-allocate heap memory per event.

The same `buf.data` slices are already fed into the streaming SHA256 in
`finalizeSuccess` (lines 902-920), so the consensus-visible hash does not
require the decoded form. When `mOpMeta`'s event manager is in a
disabled state (`!mEnabled`), the decoded events are immediately
dropped. A protocol-gated fast path could check `mOpMeta.getEventManager()`
emission-needed status up-front and skip the decode entirely, retaining
only the per-buf size accounting in the `for` loop.

## Trigger

Run the soroswap apply-load benchmark (protocol 27, TX=2000, T=8) with the
default benchmark configuration (`DISABLE_SOROBAN_METRICS_FOR_TESTING=true`
and minimal meta consumers). Every successful Soroban tx enters
`collectEvents` and decodes 2–3 events whose decoded form has no live
consumer beyond the worker.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-816` — `collectEvents`
  per-event `xdr_from_opaque` + `emplace_back` + the inline size/budget
  accounting that must remain.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:879-928` —
  `finalizeSuccess`: streaming SHA over raw event bytes (consensus path)
  and `setEvents(success)` consumer of the decoded events.
- `src/transactions/EventManager.cpp` / `.h` — `OpEventManager::setEvents`
  and the `mEnabled` gating that ultimately determines whether decoded
  events are stored or discarded.

## Evidence

Soroswap per-tx event count is small (≈ 3). Per worker the aggregate
decode load is bounded by ~2000 txs × 70 ledgers × 3 events / 8 workers
≈ 52,500 event decodes per worker. Each decode + nested `SCVal`
heap-allocation is dominated by 200–500 bytes of XDR parsing plus 2–3
small allocations, totaling ~1–2 µs each in similar microbenches.
Streaming SHA already avoids the parallel decode in the consensus path,
proving the bytes are sufficient for downstream protocol needs.

## Anti-Evidence

Total aggregate worker decode cost: 52,500 × 1.5 µs ≈ 79 ms per worker,
mostly overlapping across 8 workers. Critical-path bound: ~79 ms / 8 ≈
**9.9 ms ≈ 0.17 % of `applyLedger`** (~5,774 ms) — below the 1 % noise
floor and far below the 3 % Medium threshold.

Additionally:
1. The benchmark's `OpEventManager` is **not** disabled — the soroswap
   benchmark still populates per-op event vectors so result-hashing and
   any meta gathering remain consistent. The skip-decode fast path would
   trigger only in a non-default mode that is outside the
   `run_apply_load_matrix.py` benchmark configuration.
2. Even in disabled-meta builds, downstream consumers still require event
   counts and sizes for diagnostic budget enforcement, so the loop body
   cannot be fully elided.

This combination — small event count per tx, T=8 division, and benchmark
configuration that still requires decoded events — makes the optimization
both quantitatively below threshold and practically inapplicable to the
measured workload.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — closest prior record (`001-disabled-meta-event-materialization.md`)
targeted the disabled-meta event encoding path inside the host result
handling. This hypothesis instead targets the C++ side per-event
`xdr_from_opaque` decode in `collectEvents`. Different code site but
substantively the same conclusion.

### Why It Failed

Below objective severity threshold and inapplicable to the measured
benchmark configuration. Quantitatively the critical-path bound is
≈ 0.17 % of `applyLedger` (below 1 % noise floor). Configurationally the
soroswap benchmark does not disable the event manager so the proposed
skip path never triggers.

### Lesson Learned

The C++-side `xdr_from_opaque` decode in `collectEvents` is structurally
redundant with the streaming SHA256 path for consensus, but the savings
do not survive T=8 division and the soroswap benchmark configuration
keeps the event consumer enabled. Confirms Meta-Pattern 15: per-tx
worker micro-optimizations in the Soroban output-processing path are
exhausted; future event-path candidates need either a larger event
volume (much higher event count per tx) or a structural redesign that
removes the decoded `ContractEvent` consumer entirely.
