# H035: Relocate InvokeHostFunctionSuccessPreImage SHA256 to Rust Host

**Date**: 2026-05-20
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`finalizeSuccess` in `InvokeHostFunctionOpFrame::doApply()` is called once per
InvokeHostFunctionOp during ledger apply, i.e. ~2000 times per soroswap
ledger. The expected behavior is that the hash that lands in
`mOpFrame.innerResult(mRes).success()` (the operation result code's success
preimage hash) is produced with the minimum number of FFI buffer hand-offs
and the minimum amount of C++-side streaming work, since the Rust host has
already serialized both the result value and each `ContractEvent` to XDR
bytes that exist as `Vec<u8>` inside `InvokeHostFunctionOutput` before the
C++ side ever sees them.

## Mechanism

In the current implementation
(`src/transactions/InvokeHostFunctionOpFrame.cpp:879-921`) the C++ side
constructs a fresh `SHA256` hasher per op, then calls
`hasher.add(out.result_value.data)`, `hasher.add(<htonl events length>)`,
`hasher.add(buf.data)` for each event, and finally `hasher.finish()`. The
Rust host already owns all the input byte ranges in contiguous `Vec<u8>`
form. Pushing the hash computation across the FFI — i.e., adding a
`success_preimage_hash: [u8; 32]` field to `InvokeHostFunctionOutput`
computed Rust-side from the same buffers — would eliminate the per-op C++
`SHA256` init/update/final cost (one libsodium init, N+2 libsodium update
calls, one finalize) and the associated Tracy zone overhead, replacing it
with a 32-byte memcpy out of `RustBuf`.

## Trigger

Run any soroswap workload (~2000 InvokeHostFunctionOp per ledger). On every
op, the `finalizeSuccess` SHA256 streaming runs on the apply critical path.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:879-921` — the
  `finalizeSuccess` function with its multi-add streaming SHA256
- `src/rust/src/bridge.rs` — `InvokeHostFunctionOutput` struct (would gain a
  `success_preimage_hash: [u8; 32]` field)
- `src/rust/src/soroban_proto_any.rs` — Rust-side host invocation that
  populates `InvokeHostFunctionOutput`; would compute the SHA256 from the
  already-serialized `result_value` and `contract_events` bytes
- `src/crypto/SHA.cpp` — `SHA256` class (cost source on C++ side)

## Evidence

- `finalizeSuccess` runs unconditionally per InvokeHostFunctionOp on the
  apply path; soroswap exercises this ~2000 times per ledger.
- The Rust host already produces `result_value: RustBuf` and
  `contract_events: Vec<RustBuf>` via metered XDR encoding before returning
  to C++, so the input bytes for the hash exist on the Rust side first.
- Streaming SHA256 init+update+finalize each carry libsodium dispatch and
  Tracy zone overhead; a Rust-side computation could fold the work into the
  same metered serialization pass.

## Anti-Evidence / Why It Failed

- **Meta-Pattern 1 (SHA256 budget ceiling)**: total in-apply SHA256 work
  for soroswap is ~4 ms per ledger (~0.67% of apply). The
  `finalizeSuccess` callsite is one component of that ceiling. Even
  removing 100% of the C++-side streaming overhead at this site recovers a
  fraction of 0.67%, which is below the 1% Low floor and far below the 3%
  Medium floor required by this objective.
- The hash *computation itself* is required by protocol — it's the
  operation result code's success preimage hash and must be produced
  somewhere. Relocation only removes init/update/final dispatch overhead
  (libsodium + Tracy), not the actual SHA256 compression rounds.
- Adding a fixed-size hash field to `InvokeHostFunctionOutput` introduces
  a new Rust↔C++ ABI commitment for marginal savings, and the Rust-side
  computation would also incur its own metering / `crypto_hash_sha256`
  dispatch work.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail/hypothesis/reviewed/poc record targets
the `finalizeSuccess` callsite specifically, though H012/H023/H026 cover
related SHA256 class-form / pool / lazy-init redesigns and Meta-Pattern 1
imposes the same ceiling.

### Why It Failed

The SHA256 work at `finalizeSuccess` is one component of the ~0.67% of
apply time soroswap spends on SHA256 (Meta-Pattern 1). Eliminating
*dispatch* overhead at this site (relocating the hash to Rust) recovers a
fraction of that already-sub-1% budget, and the underlying compression
work is required by protocol and merely relocated, not removed. The
projected impact is below the 1% Low floor — well below the 3% Medium
threshold required by the objective.

### Lesson Learned

For per-op apply-path SHA256 sites (e.g., `finalizeSuccess`), do not size
savings against the streaming-class dispatch overhead alone — the entire
apply-path SHA256 budget is already capped at ~0.67% (Meta-Pattern 1).
Relocation across the FFI does not remove the protocol-required hash
work, only its dispatch site. Future SuccessPreImage hash hypotheses must
identify a removable *protocol-level* redundancy (e.g., a parallel
duplicate hash path), not a relocation.
