# H016: Replace `vec![0u8; n]` Linear-Memory Backing in soroban-wasmi With mmap-Anonymous Pages

**Date**: 2026-04-29
**Subsystem**: soroban-env / vm
**Severity**: Medium
**Impact**: Apply-time reduction in `Vm::instantiate_wasmi` (per host invocation)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each `wasmi::Linker::instantiate` call allocates a fresh
`MemoryEntity` for the contract's linear memory. The backing storage
should use a strategy that defers physical-page commit until first
access — `mmap(MAP_ANONYMOUS|MAP_PRIVATE)` on Linux — so that the
*allocation* cost of an N-page initial memory is roughly constant
regardless of N (the kernel only zeros pages on first read). For
soroswap, with ~146 VM instantiations per ledger, this would keep
per-instantiation allocation cost in the microsecond range and the
zero-fill cost would scale only with the bytes the contract actually
touches.

## Mechanism

`soroban-wasmi-0.31.1-soroban.20.0.1/src/memory/buffer.rs:21-26`
defines `ByteBuffer::new(initial_len)` as `Self { bytes: vec![0u8;
initial_len] }` — i.e. a heap allocation of `initial_len` bytes plus a
synchronous `memset(0)` over the whole region. `MemoryEntity::new`
(`memory/mod.rs:130-164`) calls this with the contract's declared
initial-pages count × 64 KiB. For a Rust-compiled Soroban contract
with even a modest memory section (1–17 pages), every host invocation
pays a 64 KiB–1 MiB malloc+memset on the apply path. With ~146
instantiations per ledger and Soroswap-router-sized contracts likely
using multiple pages, the cumulative cost could plausibly land in the
Medium tier (3–10% of the 313 ms median apply window).

The Tracy zone `Vm::instantiate_wasmi - instantiate` shows 676 ms
self-time over 10,061 calls (≈ 9.8 ms/ledger ≈ 3.13% of median apply
time). Replacing the Vec-based backing with mmap-anonymous pages would
turn the bulk of that allocation-and-zero work into deferred kernel
faults that only happen for pages the contract actually touches.

## Trigger

Run the soroswap apply-load benchmark and observe `Vm::instantiate_wasmi
- instantiate` self-time. Patch `soroban-wasmi`'s `ByteBuffer` to use
`mmap(MAP_ANONYMOUS)` for buffers ≥ one page, falling back to `Vec` on
non-Unix targets. Re-run the benchmark.

## Target Code

- `soroban-wasmi-0.31.1-soroban.20.0.1/src/memory/buffer.rs:1-55` —
  `ByteBuffer::new` and `ByteBuffer::grow`.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/memory/mod.rs:130-164` —
  `MemoryEntity::new` call site.
- `Cargo.lock:1836-1838` — `soroban-wasmi` is a stellar-owned fork
  (`git+https://github.com/stellar/wasmi?rev=0ed3f3d…`), so a patch is
  in principle landable.

## Evidence

1. `csvexport-release` on the soroswap trace gives the
   `Vm::instantiate_wasmi - instantiate` zone 676 ms total self-time
   across 10,061 calls — ≈ 67 µs per call, dominated by allocation in
   the Vec-backed path.
2. wasmi's documentation comment on `ByteBuffer` itself says: "*This
   is less efficient than the byte buffer implementation that is based
   on actual OS provided virtual memory but it is a safe fallback
   solution fitting any platform*" — confirming the upstream design
   acknowledges the trade-off.
3. The crate is a stellar-owned fork, so we can land a patch without
   coordinating with upstream; we already maintain Soroban-specific
   tweaks on this branch.

## Anti-Evidence

- Without the actual Soroswap router contract's `(memory …)` section in
  hand, I cannot bound the per-instantiation page count. If
  contracts only request 1 page (64 KiB), the per-call cost is
  ~10–20 µs and the per-ledger savings would be sub-1%, dropping
  below the noise floor.
- mmap-anonymous on Linux still costs a syscall per allocation
  (~2–5 µs). For 1-page memories the wins are marginal.
- Replacing the backing buffer touches wasmi internals across many
  paths (grow, slicing, pointer aliasing inside the interpreter); risk
  of subtle bugs is high.
- Determinism: as long as the contract observes the same zeroed-memory
  semantics, mmap vs Vec is invisible. But any deviation in page-fault
  behavior under failure injection (e.g., overcommit) could change
  observed errors across nodes — needs careful testing.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (no fail entries
mention `ByteBuffer`, `mmap`, or wasmi linear-memory backing).

### Why It Failed

The optimization sits inside `soroban-wasmi`, a forked-but-pinned crate
where any Wasm-execution-touching change carries large protocol-risk
surface area (subtle page-fault / overcommit divergence across nodes;
interpreter pointer aliasing assumptions). More importantly, the
projected impact cannot be confidently bounded without measuring the
actual `(memory …)` section of the Soroswap router/LP contracts —
which can range from 1 page (64 KiB, ~0.4% per-ledger savings, well
below the Medium threshold) to 17+ pages (~2–3% savings, still
borderline-Medium at best). The Tracy `Vm::instantiate_wasmi -
instantiate` zone is 9.8 ms/ledger total, but only a fraction of that
is the linear-memory `vec![0u8; n]` — the rest is data-segment copy,
table init, and wasmi-internal validation that an mmap change does
not touch. Any optimistic share-of-zone estimate puts the projected
win at or under the Low/Medium boundary, on the wrong side of the
"sub-1% noise floor" rule for a change with a high-blast-radius
implementation site.

### Lesson Learned

For wasmi-internal optimizations targeted at `Vm::instantiate_wasmi`:
do not propose them without a per-zone breakdown that isolates the
sub-cost being attacked (e.g., a Tracy zone wrapped specifically
around `MemoryEntity::new` vs. data-segment copy vs. linker
import-resolution). The aggregate `instantiate` zone is too coarse to
ground a Medium-tier projection. Future investigators should add
finer-grained Tracy zones inside the patched wasmi fork *first*, then
generate hypotheses based on the disaggregated data. Also, any
wasmi-internal change should be evaluated against the
"determinism-across-nodes" bar with extra care because the apply-path
risk is multiplied by every contract instantiation network-wide.
