# H005: Per-Subframe `RollbackPoint` Storage Map Clone In `push_context`

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Low
**Impact**: Per-subframe rollback snapshot overhead inside soroban host invocation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the soroban host pushes a new sub-call frame (router → pair → SAC token
contract) it needs to be able to roll back the per-host `Storage::map` if the
sub-call fails. The map keys/values are `Rc<LedgerKey>` /
`Option<(Rc<LedgerEntry>, Option<u32>)>` so a "snapshot" should be functionally
a cheap structural sharing operation (Rc bumps + Vec clone), with negligible
critical-path cost for the dominant non-failing path used by the steady-state
soroswap workload.

## Mechanism

`Host::push_context` (`frame.rs:223`) calls
`self.try_borrow_storage()?.map.metered_clone(self)?` on every sub-frame push,
including frames that never roll back. For soroswap, the steady-state
measurement window pushes ~6 frames per tx (router invocation + native
pair calls + SAC sub-calls), allocating a fresh `Vec<(Rc<LedgerKey>,
Option<(Rc<LedgerEntry>, Option<u32>)>)>` of storage-map length each time
plus charging per-entry budget for the clone. The actual rollback payload
is only consumed on sub-call failure, which is rare in the benchmark.

The expected behavior — a cheap structural snapshot — is mostly already what
happens (the inner Rcs are bumped, not deep-copied), but a fresh `Vec`
allocation and per-entry budget charge still occur on every push. The
deviation is the unconditional Vec/charge work; the question is whether
its cumulative size clears the objective severity floor.

## Trigger

Run the protocol-27 soroswap apply-load benchmark. Every successful
soroswap router invocation pushes ~6 sub-frames; each push records a
`RollbackPoint::storage` snapshot via `metered_clone`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:223-238` —
  `Host::push_context` calls `self.try_borrow_storage()?.map.metered_clone(self)?`
  unconditionally on every sub-frame push.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs` and
  `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs` —
  per-entry budget-charge clone path.

## Evidence

The diagnostic Tracy trace
(`8dd3f525748f-20260524-114704-02-soroswap-tx-2000-t-8.tracy`) shows
`push context` self-time of 97.94 ms across 50,389 calls (0.95% of trace
self-time, mean 1.94 µs/push, std 9.04 µs). Source reading confirms the
`RollbackPoint::storage` clone path is unconditional on push, and that
both the parent `Host::with_frame` and the sub-frame setup paths run
inside `applyLedger`.

## Anti-Evidence

After normalizing by the configured `NUM_CLUSTERS=8` parallel workers and
the 5 soroswap measurement ledgers (the remaining 67 of 72 closeLedger
events are setup ledgers, per CURRENT_STATE), the projected critical-path
saving is well below the 3% Medium floor:

- Raw self-time 97.94 ms ÷ 8 workers ÷ 5 measurement ledgers ≈ 2.45 ms/ledger
  ≈ **1.16% of the 211 ms soroswap median**.

This is below the Medium (≥3%) bar required by this objective, and is
in the same regime as the previously-rejected
`002-cow-invoke-storage-snapshot.md` (top-level `init_storage_map` clone)
and meta-pattern 6 (async-with-immediate-join is neutral on critical path).
Removing the clone entirely is also not free: the structural snapshot is
required for the rare sub-call rollback path; replacing it with a true
COW design (e.g., `im::Vector`) would not preserve the deterministic
metered-clone budget charges and would change protocol-visible metering
(meta-pattern 11). A safer "skip clone on infallible frames" optimization
requires marking each sub-call site as infallible at the Wasm boundary,
which is not statically determinable for the soroswap router → pair → SAC
chain.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — the per-subframe `push_context` storage-map snapshot
is a distinct call site from the previously-investigated top-level
`init_storage_map` clone (`002-cow-invoke-storage-snapshot.md`), and the
zone `push context` (frame.rs:223) does not appear in any prior fail
record.

### Why It Failed

Even fully eliminating the per-subframe storage-map clone saves only
~1.16% of the 211 ms soroswap median after parallel-worker normalization,
below the 3% Medium severity floor required by this objective. The clone
also cannot be elided without either (a) breaking the deterministic
metered-clone budget charges that are protocol-visible (meta-pattern 11),
or (b) introducing a true persistent/COW container that changes the
internal storage-map representation and re-opens the metering equivalence
question.

### Lesson Learned

Per-subframe rollback-snapshot zones in the soroban host (push_context,
push auth frame, snapshot auth) are individually sub-Medium after
`NUM_CLUSTERS=8` and 5-measurement-ledger normalization, even when their
raw Tracy self-time is ~1%. The aggregate of these three zones
(push context 0.95% + push auth frame 0.98% + snapshot auth 1.55%
≈ 3.48% raw → ~0.43% critical-path) is also sub-Medium, so combined
"frame setup elimination" hypotheses also fail the severity floor unless
they include a structural change (e.g., compile-time frame elimination
via native contracts), which is gated by meta-pattern 15.
