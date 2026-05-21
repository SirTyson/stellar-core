# H047: Stream `metered_hash_xdr` Directly Into SHA256

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`Host::metered_hash_xdr` should hash an XDR value while it is being serialized,
without first materializing the entire XDR byte stream in a temporary `Vec<u8>`.
For apply-path callers such as contract-id hashing and Soroban auth payload
hashing, the expected efficient shape is a writer that charges `ValSer` per
chunk and feeds the same bytes into a streaming SHA256 state.

## Mechanism

The actual implementation in `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs`
allocates `let mut buf = vec![]`, calls `metered_write_xdr` to serialize into
that vector, and then calls `sha256_hash_from_bytes_raw(&buf, self)`. This
performs a materialization pass plus a second read pass over the serialized
bytes. A streaming writer could preserve metering and deterministic byte order
while avoiding the temporary buffer and one memory pass, but the measured zone is
too small to matter for this objective.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` and
filter `hash xdr`:

```sh
./lib/tracy/csvexport/build/unix/csvexport-release -e -f 'hash xdr' \
  /mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy
```

The trace reports `hash xdr,soroban-env-host/src/host/metered_xdr.rs,45` at
11,649,601 ns self-time across 20,341 calls. Unwrap-mode containment confirms
all 20,341 events are inside `applyLedger`, with 38,403,650 ns total event time.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:33-38` —
  `Host::metered_hash_xdr` serializes into a temporary vector and hashes it.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` —
  `metered_write_xdr` is the charging writer that a streaming hash writer would
  need to preserve.
- `src/rust/soroban/p26/soroban-env-host/src/crypto/mod.rs:410-419` —
  `sha256_hash_from_bytes_raw` performs the final SHA256 over the materialized
  bytes.
- `src/rust/soroban/p26/soroban-env-host/src/host/lifecycle.rs:199-231` and
  `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2056-2073` — representative
  production callers.

## Evidence

The source has a clear avoidable allocation and byte-buffer materialization in a
zone that is confirmed to execute within the `applyLedger` window. A streaming
writer would be deterministic because it would consume the exact same `WriteXdr`
serialization order and would only change the sink from `Vec<u8>` to SHA256
state plus the existing budget charging.

## Anti-Evidence

The complete `hash xdr` total event time is only 38.4 ms over a 5.230 s traced
`applyLedger` envelope, or about 0.73% if eliminated entirely. Its self-time is
only 11.65 ms. The objective accepts only Medium-or-better hypotheses at this
stage, and Medium requires at least a 3% reduction (~157 ms on this trace).
Realistic savings are a fraction of the total zone because serialization,
metering, and SHA256 compression still remain.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — prior crypto failures covered C++ `XDRHasher`, tx-result
hashing, host SHA256 syscall dispatch, and bridge XDR serialization, but not
the Rust host `metered_hash_xdr` temporary-buffer shape.

### Why It Failed

Even a perfect streaming implementation cannot reach the objective's Medium
severity floor. The entire apply-contained `hash xdr` zone is below 1% of traced
apply time, and the removable allocation/memory-pass portion is smaller than
the zone total.

### Lesson Learned

Rust host XDR-hash materialization is a real local inefficiency, but it should
be rejected for optimize-soroswap unless a future workload makes `hash xdr`
orders of magnitude larger. Size streaming-hash cleanups against the whole
apply-contained zone, not against nearby broader `write xdr` totals.
